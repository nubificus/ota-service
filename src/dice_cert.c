#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_event.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "dice/dice.h"
#include "dice/ops.h"

#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/esp_debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"

#include "esp_crt_bundle.h"
#include "esp_flash.h"
#include "esp_partition.h"
#include "esp_mac.h"

#include "dice_cert.h"

#define BOOTLOADER_HASH_OFFSET 0x1000
#define BOOTLOADER_HASH_SIZE 64

#define BOOTLOADER_LEN 128

static const char *TAG = "dice-cert-gen";

int gen_dice_cert(void *buf, size_t max_len) {
	uint8_t final_seal_cdi_buffer[DICE_CDI_SIZE] = {0};
	uint8_t final_cdi_buffer[DICE_CDI_SIZE] = {0};
	uint8_t cdi_buffer[DICE_CDI_SIZE] = {0};
	uint8_t seal_cdi_buffer[DICE_CDI_SIZE] = {0};
	DiceInputValues input_values = {0};
	uint8_t cert_buffer[2048];
	DiceResult dice_ret;
	int ret, i;
	size_t cert_size;
	const uint8_t uds_buffer[] = {
		0xDA, 0xDD, 0xAE, 0xBC, 0x80, 0x20, 0xDA, 0x9F, 0xF0, 0xDD, 0x5A,
		0x24, 0xC8, 0x3A, 0xA5, 0xA5, 0x42, 0x86, 0xDF, 0xC2, 0x63, 0x03,
		0x1E, 0x32, 0x9B, 0x4D, 0xA1, 0x48, 0x43, 0x06, 0x59, 0xFE, 0x62,
		0xCD, 0xB5, 0xB7, 0xE1, 0xE0, 0x0F, 0xC6, 0x80, 0x30, 0x67, 0x11,
		0xEB, 0x44, 0x4A, 0xF7, 0x72, 0x09, 0x35, 0x94, 0x96, 0xFC, 0xFF,
		0x1D, 0xB9, 0x52, 0x0B, 0xA5, 0x1C, 0x7B, 0x29, 0xEA};

	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;

	mbedtls_ctr_drbg_init(&ctr_drbg);
	ESP_LOGI(TAG, "Seeding the random number generator");

	mbedtls_entropy_init(&entropy);
	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
					&entropy, NULL, 0)) != 0) {
		ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed returned %d", ret);
		abort();
	}
	ESP_LOGI(TAG, "Minimum free heap size: %" PRIu32 " bytes",
			esp_get_minimum_free_heap_size());

	ESP_LOGI(TAG, "Stack bytes available: '%d'",
			uxTaskGetStackHighWaterMark(NULL));
	for (i = 0; i >= 0; i--) {
		ESP_LOGI(TAG, "%d...", i);
		vTaskDelay(1000 / portTICK_PERIOD_MS);
	}
	esp_flash_read(NULL, input_values.code_hash, BOOTLOADER_HASH_OFFSET, BOOTLOADER_HASH_SIZE);
	ESP_LOGI(TAG, "Using bootloader hash");

	#if DEBUG
	for (i = 0; i < 64; i++) {
		printf("%02x:", input_values.code_hash[i]);
	}
	printf("\n");
	#endif

	uint8_t bytes[BOOTLOADER_LEN] = {0};
	esp_flash_read(NULL, bytes, BOOTLOADER_HASH_OFFSET, BOOTLOADER_LEN);

	#if DEBUG
	ESP_LOGI(TAG, "Using bootloader hash");
	for (i = 0; i < BOOTLOADER_LEN; i++) {
		printf("%02x:", bytes[i]);
	}
	printf("\n");
	#endif

	if (esp_efuse_mac_get_default(input_values.config_value)) {
		ESP_LOGE(TAG, "Failed to read MAC addr");
		goto fail;
	}

	#if DEBUG
	printf("Using MAC: ");
	for (i = 0; i < 6; i++)
		printf("%02x:", input_values.config_value[i]);
	printf("\n");
	#endif

	input_values.mode = kDiceModeNormal;
	input_values.config_type = kDiceConfigTypeInline;
	dice_ret = DiceMainFlow(NULL, uds_buffer, uds_buffer,
				&input_values, 0, NULL, NULL,
				cdi_buffer, seal_cdi_buffer);
	if (dice_ret != kDiceResultOk) {
		ESP_LOGE(TAG, "DICE first CDI failed!");
		goto fail;
	}
	ESP_LOGI(TAG, "First CDI buffer created");

	#if DEBUG
	for (i = 0; i < DICE_CDI_SIZE; i++)
		printf("%x:", cdi_buffer[i]);
	printf("\n");
	#endif

	memset(input_values.code_hash, 0, sizeof(input_values.code_hash));
	esp_flash_read(NULL, input_values.code_hash, 0x20000, 16);
	ESP_LOGI(TAG, "Using application hash");

	#if DEBUG
	for (i = 0; i < 64; i++)
		printf("%02x:", input_values.code_hash[i]);
	printf("\n");
	#endif

	input_values.mode = kDiceModeNormal;
	input_values.config_type = kDiceConfigTypeInline;
	dice_ret = DiceMainFlow(NULL, cdi_buffer, cdi_buffer, &input_values,
				sizeof(cert_buffer), cert_buffer,&cert_size,
				final_cdi_buffer, final_seal_cdi_buffer);
	if (dice_ret != kDiceResultOk) {
		ESP_LOGE(TAG, "DICE final CDI failed!");
		goto fail;
	}
	ESP_LOGI(TAG, "Final cdi buffer created");
	
	if (cert_size + 1 > max_len) {
		ESP_LOGE(TAG, "Buffer length not enough to hold the certificate");
		goto fail;
	}

	memset(buf, 0, max_len);
	memcpy(buf, cert_buffer, cert_size);

	DiceClearMemory(NULL, sizeof(final_cdi_buffer), final_cdi_buffer);
	DiceClearMemory(NULL, sizeof(final_seal_cdi_buffer), final_seal_cdi_buffer);

	return cert_size;

fail:
	DiceClearMemory(NULL, sizeof(final_cdi_buffer), final_cdi_buffer);
	DiceClearMemory(NULL, sizeof(final_seal_cdi_buffer), final_seal_cdi_buffer);
	return -1;
}
