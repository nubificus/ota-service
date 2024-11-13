#include "ota-service.h"
#include "tls.h"

#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_log.h"

#include <mbedtls/ssl.h>
#include "mbedtls/base64.h"
#include "dice_cert.h"

#include "esp_ota_ops.h"
#include "esp_http_server.h"

#define KB 1024
#define STACK_SIZE (32 * KB)

#define DICE_MAX_CERTIFICATE_SIZE 2048
#define DICE_MAX_EXTENSION_SIZE 2048
#define DICE_MAX_KEY_ID_SIZE 40

#define MAX_ATTEMPTS 20

static void print_base64_encoded(uint8_t *data, size_t len) {
    size_t output_len;
    size_t encoded_len = 4 * ((len + 2) / 3);

    char *encoded = (char *)malloc(encoded_len + 1);
    if (encoded == NULL) {
        printf("Memory allocation failed\n");
        return;
    }

    if (mbedtls_base64_encode((unsigned char *) encoded,
			      encoded_len + 1, &output_len,
			      data, len) != 0) {
        printf("Base64 encoding failed\n");
        free(encoded);
        return;
    }

    encoded[output_len] = '\0';
    printf("%s\n\n", encoded);
    free(encoded);
}

static const char *TAG = "ota";

static esp_partition_t* update_partition = NULL;
static esp_ota_handle_t update_handle = 0;
static size_t partition_data_written  = 0;

static void ota_process_begin() {
	update_partition = esp_ota_get_next_update_partition(NULL);
	assert(update_partition != NULL);

	esp_err_t err = esp_ota_begin(update_partition, OTA_WITH_SEQUENTIAL_WRITES, &update_handle);

	if (err != ESP_OK) {
		ESP_LOGE(TAG, "esp_ota_begin() failed (%s)", esp_err_to_name(err));
		esp_ota_abort(update_handle);

		while(1) vTaskDelay(1000);
	}

	ESP_LOGI(TAG, "esp_ota_begin succeeded");
}

static int ota_append_data_to_partition(unsigned char* data, size_t len) {
	if (esp_ota_write(update_handle, (const void*) data, len) != ESP_OK) {
		esp_ota_abort(update_handle);
		ESP_LOGE(TAG, "esp_ota_write() failed");

		return -1;
	}
	partition_data_written += len;
	return 0;
}

static int ota_setup_partition_and_reboot() {
	ESP_LOGI(TAG, "Total bytes read: %d", partition_data_written);

	esp_err_t err = esp_ota_end(update_handle);

	if (err != ESP_OK) {
		if (err == ESP_ERR_OTA_VALIDATE_FAILED) 
			ESP_LOGE(TAG, "Image validation failed, image is corrupted/not-signed");
		else 
			ESP_LOGE(TAG, "esp_ota_end failed (%s)!", esp_err_to_name(err));
        
		return -1;
	}

	err = esp_ota_set_boot_partition(update_partition);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "esp_ota_set_boot_partition failed (%s)!", esp_err_to_name(err));
		return -1;
	}
	ESP_LOGI(TAG, "Prepare to restart system!");
	vTaskDelay(4000 / portTICK_PERIOD_MS);
	esp_restart();

	/* Probably unreachable */
	return -1; 
}

static int ota_write_partition_from_tls_stream(mbedtls_ssl_context *ssl) {
	ESP_LOGI(TAG, "Waiting for update..");
	const int chunk = 64; 
	unsigned char rx_buffer[chunk];
	int len;

	partition_data_written  = 0;
	while (1) {
		memset(rx_buffer, 0, sizeof(rx_buffer));

		len = tls_next_chunk(ssl, rx_buffer);
		if (len == 0)
			break;	
		else if (len > 0)
			ota_append_data_to_partition(rx_buffer, len);
		else
			return -1;
	}

	tls_kill_connection(ssl);
	ESP_LOGI(TAG, "Now all the data has been received");
	return 0;
}

void ota_service_task(void *pvParameters);

/*
 * The body in the receiving POST
 * request will have the following
 * form: `ip: X.X.X.X`
 * Therefore we extract the ip string
 * from the body to give it as an
 * argument to the ota-service task
 */

#define IP_LEN 16 + 1
#define POST_BODY_LEN (IP_LEN + 4)
esp_err_t ota_request_handler(httpd_req_t *req)
{
	char body[POST_BODY_LEN] = { 0 };
	size_t msg_len = req->content_len;
	size_t buf_len = POST_BODY_LEN;
	size_t recv_size = (msg_len < buf_len) ? msg_len : buf_len;

	int ret = httpd_req_recv(req, body, recv_size);
	if (ret <= 0) {
		if (ret == HTTPD_SOCK_ERR_TIMEOUT)
			httpd_resp_send_408(req);
		return ESP_FAIL;
	}

	char* ip = calloc(IP_LEN, 1);
	sscanf(body, "ip: %s", ip);
	ESP_LOGI(TAG, "OTA Agent IP: %s", ip);
	const char resp[] = "Received update request: About to update\n";
	httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
	xTaskCreate(ota_service_task,
		    "OTA Service Task",
		    STACK_SIZE,
		    (void *) ip,
		    1, NULL);
	return ESP_OK;
}

void ota_service_begin(char *ip) {
	xTaskCreate(ota_service_task,
		    "OTA Service Task",
		    STACK_SIZE,
		    (void *) ip,
		    1, NULL);
}

void ota_service_task(void *pvParameters) {
restart:
	;
	char *server_ip = (char *) pvParameters;
	mbedtls_ssl_context ssl;
	uint8_t reconnect = 0;
	uint8_t attempts = 0;

	char cert_buf[1000] = {0};
	int len = gen_dice_cert(cert_buf, sizeof(cert_buf));
	if (len <= 0) {
		ESP_LOGE(TAG, "Could not generate the certificate");
		abort();
	}
	#if DEBUG
	print_base64_encoded((uint8_t*) cert_buf, len);
	#endif

reconnect:
	if (attempts++ >= MAX_ATTEMPTS) {
		ESP_LOGE(TAG, "Reached max number of attempts to connect - aborting");
		while(1) vTaskDelay(1000 / portTICK_PERIOD_MS);
	}
	if (reconnect) {
		ESP_LOGI(TAG, "Waiting 4 seconds before trying again...");
		vTaskDelay(4000 / portTICK_PERIOD_MS);
	}
	reconnect = 1;

	if (tls_establish(&ssl, server_ip) < 0)
		goto reconnect;

	free(server_ip);
	printf("Established connection with server\n");

	if (tls_send_dice_cert(&ssl, (void *) cert_buf, len) < 0) {
		ESP_LOGE(TAG, "Could not send the certificate in the host");
		goto reconnect;	
	}

	if (cert_ok(&ssl)) {
		ESP_LOGI(TAG, "Cert OK");
	} else {
		ESP_LOGE(TAG, "Could not verify.. Closing the connection");
		tls_kill_connection(&ssl);
		goto out;
	}

	vTaskDelay(1000 / portTICK_PERIOD_MS);
	ota_process_begin();	

	if (ota_write_partition_from_tls_stream(&ssl) < 0) {
		ESP_LOGE(TAG, "Failed to update");
		goto restart;
	}

	if (ota_setup_partition_and_reboot()) {
		ESP_LOGE(TAG, "Failed to setup partition and reboot");
		goto restart;
	}
out:
	while (1) vTaskDelay(1000 / portTICK_PERIOD_MS);
}
