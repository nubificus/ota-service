#ifdef OTA_SECURE

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

#include "esp_efuse.h"
#include "esp_efuse_table.h"
#include "soc/efuse_reg.h"

#include "esp_ota_ops.h"
#include "esp_image_format.h"
#include "esp_crc.h"
#include "spi_flash_mmap.h"

#define DEBUG 1

#define MAGIC 0xe7
#define V2 0x02
#define JUMP CONFIG_MMU_PAGE_SIZE
#define HASH_OFF 4
#define HASH_SIZE 32
#define CSR_OFF 1196
#define PAD_OFF 1200
#define PAD_LEN 16
#define PAD "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"

#define BOOTLOADER_HASH_SIZE 64
#define APP_HASH_SIZE   16

static const char *TAG = "dice-cert-gen";

static int dice_config_v2(DiceInputValues *input_values) {
	uint32_t flash_size;
	esp_err_t err = esp_flash_get_size(NULL, &flash_size);

	if (err == ESP_OK) {
		ESP_LOGI(TAG, "Flash size: %d bytes (%.2f MB)",
			(int) flash_size, (float) flash_size / (1024.0 * 1024.0));
	} else {
		ESP_LOGE(TAG, "Failed to get flash size: %s", esp_err_to_name(err));
		return -1;
	}

	bool boot_hash_written = false;
	const uint32_t jump = JUMP;
	for (uint32_t offset = 0x0; offset < flash_size; offset += jump) {
		const void *mm = NULL;
		const size_t size = 4096;
		spi_flash_mmap_handle_t mm_handle = 0;

		esp_err_t err = spi_flash_mmap(offset, CONFIG_MMU_PAGE_SIZE, SPI_FLASH_MMAP_DATA,
					       &mm, &mm_handle);
		if (err != ESP_OK) {
			printf("Failed to map flash region: %d\n", err);
			return -1;
		}

		for (unsigned int suboff = 0x0; suboff < CONFIG_MMU_PAGE_SIZE; suboff += size) {
			/*
			printf("Offset checked: 0x%x\n", (unsigned int)(offset + suboff));
			*/

			const uint8_t *bytes = (const uint8_t *) (mm + suboff);

			/* First condition */
			if (bytes[0] != MAGIC && bytes[1] != V2 && bytes[2] && bytes[3])
				continue;

			/* Second condition */
			if (*((uint32_t *)(bytes + CSR_OFF)) != esp_crc32_le(0, bytes, CSR_OFF))
				continue;

			/* Third condition */
			if (memcmp(bytes + PAD_OFF, PAD, PAD_LEN))
				continue;

			printf("Found signature block at offset: 0x%x -- Address: 0x%x\n", (unsigned int)(offset + suboff), (unsigned int)bytes);

			if (!boot_hash_written) {
				printf("Writing boot hash..\n");
				memcpy(input_values->code_hash, &bytes[HASH_OFF], HASH_SIZE);
				memcpy(input_values->code_hash + HASH_SIZE, &bytes[HASH_OFF],
				       HASH_SIZE);
				boot_hash_written = true;
			} else {
				printf("Writing application hash..\n");
				memset(input_values->config_value, 0, sizeof(input_values->config_value));
				memcpy(input_values->config_value, &bytes[HASH_OFF], APP_HASH_SIZE);
				spi_flash_munmap(mm_handle);
				return 0;
			}

		}
		spi_flash_munmap(mm_handle);
	}
	return -1;
}

typedef enum {
	SECURE_BOOT_NONE = 0,
	SECURE_BOOT_V1,
	SECURE_BOOT_V2
} secure_boot_version_t;

#define BOOTLOADER_HASH_OFFSET 0x80
#define APP_HASH_OFFSET 0x200b0

secure_boot_version_t secure_boot_version() {
#ifdef CONFIG_IDF_TARGET_ESP32
	if (esp_efuse_read_field_bit(ESP_EFUSE_ABS_DONE_0))
		return SECURE_BOOT_V1;
#elif defined(CONFIG_IDF_TARGET_ESP32S2) || \
	defined(CONFIG_IDF_TARGET_ESP32S3) || \
	defined(CONFIG_IDF_TARGET_ESP32C6)

	if (esp_efuse_read_field_bit(ESP_EFUSE_SECURE_BOOT_EN))
		return SECURE_BOOT_V2;
#endif
	return SECURE_BOOT_NONE;
}

static void dice_config_none(DiceInputValues *input_values) {
	memset(input_values->code_hash, 0, sizeof(input_values->code_hash));
	memset(input_values->config_value, 0, sizeof(input_values->config_value));
}

static void dice_config_v1(DiceInputValues *input_values) {
	esp_flash_read(NULL, input_values->code_hash, BOOTLOADER_HASH_OFFSET,
		       BOOTLOADER_HASH_SIZE);
	memset(input_values->config_value, 0, sizeof(input_values->config_value));
	esp_flash_read(NULL, input_values->config_value, APP_HASH_OFFSET,
		       APP_HASH_SIZE);
}

static void dice_config(DiceInputValues *input_values) {
	secure_boot_version_t version = secure_boot_version();
	switch (version) {
	case SECURE_BOOT_V1:
		printf("Secure Boot: V1\n");
		dice_config_v1(input_values);
		break;
	case SECURE_BOOT_V2:
		printf("Secure Boot: V2\n");
		if (dice_config_v2(input_values) == 0)
			break;
		printf("Secure Boot V2 DICE Configuarion failed..\n");
	case SECURE_BOOT_NONE:
		printf("Configuring DICE configuration without hashes\n");
		dice_config_none(input_values);
		break;
	}

	input_values->mode = kDiceModeNormal;
	input_values->config_type = kDiceConfigTypeInline;
}

static const uint8_t asym_salt[] = {
    0x63, 0xB6, 0xA0, 0x4D, 0x2C, 0x07, 0x7F, 0xC1, 0x0F, 0x63, 0x9F,
    0x21, 0xDA, 0x79, 0x38, 0x44, 0x35, 0x6C, 0xC2, 0xB0, 0xB4, 0x41,
    0xB3, 0xA7, 0x71, 0x24, 0x03, 0x5C, 0x03, 0xF8, 0xE1, 0xBE, 0x60,
    0x35, 0xD3, 0x1F, 0x28, 0x28, 0x21, 0xA7, 0x45, 0x0A, 0x02, 0x22,
    0x2A, 0xB1, 0xB3, 0xCF, 0xF1, 0x67, 0x9B, 0x05, 0xAB, 0x1C, 0xA5,
    0xD1, 0xAF, 0xFB, 0x78, 0x9C, 0xCD, 0x2B, 0x0B, 0x3B};

int gen_dice_cert(void *buf, size_t max_len) {
	uint8_t final_seal_cdi_buffer[DICE_CDI_SIZE] = { 0 };
	uint8_t final_cdi_buffer[DICE_CDI_SIZE] = { 0 };
	DiceInputValues input_values = { 0 };
	uint8_t cert_buffer[2048] = { 0 };
	DiceResult dice_ret;
	int ret, i;
	size_t cert_size;
	uint8_t uds_buffer[DICE_PRIVATE_KEY_SEED_SIZE];
	uint8_t mac_addr[6];

	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;

#ifdef CONFIG_MBEDTLS_SSL_PROTO_TLS1_3
	psa_status_t status = psa_crypto_init();
	if (status != PSA_SUCCESS) {
		ESP_LOGE(TAG, "Failed to initialize PSA crypto, returned %d",
			 (int) status);
		return;
	}
#endif

	mbedtls_ctr_drbg_init(&ctr_drbg);
	ESP_LOGI(TAG, "Seeding the random number generator");

	mbedtls_entropy_init(&entropy);
	if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
					&entropy, NULL, 0)) != 0) {
		ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed returned %d", ret);
		abort();
	}

	if(esp_efuse_mac_get_default(mac_addr)) {
		ESP_LOGE(TAG, "Failed to read MAC addr");
		goto fail;
	}

	/* the asym_salt must match the one we use on the certificate generator */
	ret = DiceKdf(NULL, DICE_PRIVATE_KEY_SEED_SIZE, mac_addr,
		      sizeof(mac_addr), asym_salt, sizeof(asym_salt),
		      (const uint8_t*)"UDS hkdf", 8, uds_buffer);
	if (ret != kDiceResultOk) {
		printf("DICE HKDF failed!");
		goto fail;
	}

	dice_config(&input_values);

	dice_ret = DiceMainFlow(NULL, uds_buffer, uds_buffer, &input_values,
				sizeof(cert_buffer), cert_buffer,
				&cert_size, final_cdi_buffer,
				final_seal_cdi_buffer);
	if (dice_ret != kDiceResultOk) {
		ESP_LOGE(TAG, "DICE CDI failed!");
		goto fail;
	}

#if DEBUG
	ESP_LOGI(TAG, "Using MAC ");
	for (i = 0; i < 6; i++)
		printf("%02x:", mac_addr[i]);
	printf("\n");
	ESP_LOGI(TAG, "UDS ");
	for (i = 0; i < sizeof(uds_buffer); i++)
		printf("%02x:", uds_buffer[i]);
	printf("\n");
	ESP_LOGI(TAG, "Bootloader hash");
	for (i = 0; i < 64; i++) {
		printf("%02x:", input_values.code_hash[i]);
	}
	printf("\n");
	ESP_LOGI(TAG, "Application hash");
	for (i = 0; i < 64; i++)
		printf("%02x:", input_values.config_value[i]);
	printf("\n");
#endif

	ESP_LOGI(TAG, "CDI buffer created");
	for (i = 0; i < DICE_CDI_SIZE; i++)
		printf("%x:", final_cdi_buffer[i]);
	printf("\n");

	if (cert_size + 1 > max_len) {
		ESP_LOGE(TAG, "Buffer length not enough to hold the certificate");
		goto fail;
	}

	memset(buf, 0, max_len);
	memcpy(buf, cert_buffer, cert_size);
	return cert_size;
fail:
	/* Clear memory once the CDIs are consumed */
	//TODO Clean all uds_buffer etc
	DiceClearMemory(NULL, sizeof(final_cdi_buffer), final_cdi_buffer);
	DiceClearMemory(NULL, sizeof(final_seal_cdi_buffer), final_seal_cdi_buffer);
	return -1;
}

#endif
