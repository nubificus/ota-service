#include "ota-service.h"

#ifdef OTA_SECURE

#include "tls.h"
#include "dice_cert.h"
#include <mbedtls/ssl.h>

#else

#define PORT 3333

#endif

#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_log.h"

#include "mbedtls/base64.h"

#include "esp_ota_ops.h"
#include "esp_http_server.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"


#define KB 1024
#define STACK_SIZE (64 * KB)

#define DICE_MAX_CERTIFICATE_SIZE 2048
#define DICE_MAX_EXTENSION_SIZE 2048
#define DICE_MAX_KEY_ID_SIZE 40

#define MAX_ATTEMPTS 20

static void
__attribute__ ((unused))
print_base64_encoded(uint8_t *data, size_t len) {
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

static const esp_partition_t* update_partition = NULL;
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

#ifdef OTA_SECURE

#define RETRY_DELAY_MS 500
#define MAX_RETRY_TIME_MS 3000

static int ota_write_partition_from_tls_stream(mbedtls_ssl_context *ssl) {
	vTaskDelay(pdMS_TO_TICKS(1500));
	ESP_LOGI(TAG, "Waiting for update..");
	const int chunk = 64;
	unsigned char rx_buffer[chunk];
	int ret;
	int total_sleep_time = 0;
	bool verified = false;
	bool ota_began = false;

	partition_data_written = 0;
	while (1) {
		memset(rx_buffer, 0, sizeof(rx_buffer));

		ret = tls_next_chunk(ssl, rx_buffer);
		if (!ret || ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
			if (!verified)
				ret = -1;
			else
				ret = 0;

			break;
		} else if (ret > 0) {
			verified = true;
			if (!ota_began) {
				ota_process_begin();
				ota_began = true;
			}
			total_sleep_time = 0;
			ota_append_data_to_partition(rx_buffer, ret);
			continue;
		}

		/* Wait for an amount of time before retrying */
		if (total_sleep_time < MAX_RETRY_TIME_MS) {
			vTaskDelay(pdMS_TO_TICKS(RETRY_DELAY_MS));
			total_sleep_time += RETRY_DELAY_MS;
		} else {
			ESP_LOGE(TAG, "Max retry time exceeded, aborting.");
			ret = -1;
			break;
		}
	}
	tls_kill_connection(ssl);
	if (ret > 0)
		ESP_LOGI(TAG, "Now all the data has been received");
	return ret;
}

#else

int ota_write_partition_from_tcp_stream()
{
	unsigned char rx_buffer[1024];
	char addr_str[128];
	int addr_family;
	int ip_protocol;

	struct sockaddr_in destAddr;
	destAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	destAddr.sin_family = AF_INET;
	destAddr.sin_port = htons(PORT);
	addr_family = AF_INET;
	ip_protocol = IPPROTO_IP;
	inet_ntoa_r(destAddr.sin_addr, addr_str, sizeof(addr_str) - 1);

	int listen_sock = socket(addr_family, SOCK_STREAM, ip_protocol);
	if (listen_sock < 0)
	{
		ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
		vTaskDelete(NULL);
		return -1;
	}
	ESP_LOGI(TAG, "Socket created");

	int err = bind(listen_sock, (struct sockaddr *)&destAddr, sizeof(destAddr));
	if (err != 0)
	{
		ESP_LOGE(TAG, "Socket unable to bind: errno %d", errno);
		ESP_LOGE(TAG, "IPPROTO: %d", ip_protocol);
		close(listen_sock);
		vTaskDelete(NULL);
		return -1;
	}
	ESP_LOGI(TAG, "Socket bound, port %d", PORT);

	err = listen(listen_sock, 1);
	if (err != 0)
	{
		ESP_LOGE(TAG, "Error occurred during listen: errno %d", errno);
		close(listen_sock);
		vTaskDelete(NULL);
		return -1;
	}

	ESP_LOGI(TAG, "Socket listening");
	struct sockaddr_in sourceAddr;
	uint addrLen = sizeof(sourceAddr);
	int sock = accept(listen_sock, (struct sockaddr *)&sourceAddr, (long unsigned int *)&addrLen);
	if (sock < 0)
	{
		ESP_LOGE(TAG, "Unable to accept connection: errno %d", errno);
		return -1;
	}

	ESP_LOGI(TAG, "Socket accepted");

	while (1)
	{
		int len = recv(sock, rx_buffer, sizeof(rx_buffer), 0);
		if (len < 0)
		{
			ESP_LOGE(TAG, "recv failed: errno %d", errno);
			return -1;
		}
		else if (len == 0)
		{
			ESP_LOGI(TAG, "Connection closed");
			break;
		}
		else
			ota_append_data_to_partition(rx_buffer, len);
	}

	ESP_LOGI(TAG, "Closing the socket...");
	shutdown(sock, 0);
	close(sock);

	ESP_LOGI(TAG, "Now all the data has been received");

	return 0;
}
#endif

#ifdef OTA_SECURE

esp_err_t ota_request_handler_secure(httpd_req_t *req);
void ota_service_task_secure (void *pvParameters);

#else

esp_err_t ota_request_handler_insecure(httpd_req_t *req);
void ota_service_task_insecure (void *pvParameters);

#endif


esp_err_t ota_request_handler(httpd_req_t *req) {
#ifdef OTA_SECURE
	return ota_request_handler_secure(req);
#else
	return ota_request_handler_insecure(req);
#endif
}

/*
 * The body in the receiving POST
 * request will have the following
 * form: `ip: X.X.X.X`
 * Therefore we extract the ip string
 * from the body to give it as an
 * argument to the ota-service task
 */

#ifdef OTA_SECURE

#define IP_LEN 16 + 1
#define POST_BODY_LEN (IP_LEN + 4)
esp_err_t ota_request_handler_secure(httpd_req_t *req)
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
	const char resp[] = "Received update request: About to update (Secure)\n";
	httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
	xTaskCreate(ota_service_task_secure,
		    "OTA Service Task",
		    STACK_SIZE,
		    (void *) ip,
		    1, NULL);
	return ESP_OK;
}
#endif

#ifdef OTA_SECURE
void ota_service_begin(char *ip) {
	xTaskCreate(ota_service_task_secure,
		    "OTA Service Task",
		    STACK_SIZE,
		    (void *) ip,
		    1, NULL);
}
#endif

#ifdef OTA_SECURE
void ota_service_task_secure(void *pvParameters) {
	char *server_ip = (char *) pvParameters;
	mbedtls_ssl_context ssl;
	uint8_t reconnect = 0;
	uint8_t attempts = 0;

	char cert_buf[1024] = {0};
	int len = gen_dice_cert(cert_buf, sizeof(cert_buf));
	if (len <= 0) {
		ESP_LOGE(TAG, "Could not generate the certificate");
		vTaskDelete(NULL);
	}
	#if DEBUG
	print_base64_encoded((uint8_t*) cert_buf, len);
	#endif

reconnect:
	if (attempts++ >= MAX_ATTEMPTS) {
		ESP_LOGE(TAG, "Reached max number of attempts to connect - aborting");
		vTaskDelete(NULL);
	}
	if (reconnect) {
		ESP_LOGI(TAG, "Waiting 4 seconds before trying again...");
		vTaskDelay(4000 / portTICK_PERIOD_MS);
	}
	reconnect = 1;

	if (tls_establish(&ssl, server_ip) < 0)
		goto reconnect;

	printf("Established connection with server\n");

	vTaskDelay(500 / portTICK_PERIOD_MS);

	if (tls_send_dice_cert(&ssl, (void *) cert_buf, len) < 0) {
		ESP_LOGE(TAG, "Could not send the certificate in the host");
		vTaskDelete(NULL);
	}

	if (ota_write_partition_from_tls_stream(&ssl) < 0) {
		ESP_LOGE(TAG, "Failed to update");
		vTaskDelete(NULL);
	}

	if (ota_setup_partition_and_reboot()) {
		ESP_LOGE(TAG, "Failed to setup partition and reboot");
		vTaskDelete(NULL);
	}
	while (1) vTaskDelay(1000 / portTICK_PERIOD_MS);
}
#endif

#ifndef OTA_SECURE
void ota_service_task_insecure(void *pvParameters) {
	ota_process_begin();	

	if (ota_write_partition_from_tcp_stream() < 0) {
		ESP_LOGE(TAG, "Failed to update");
		while (1) vTaskDelay(1000);
	}

	if (ota_setup_partition_and_reboot()) {
		ESP_LOGE(TAG, "Failed to setup partition and reboot");
		while (1) vTaskDelay(1000);
	}
	
	vTaskDelete(NULL);
}
#endif

#ifndef OTA_SECURE
esp_err_t ota_request_handler_insecure(httpd_req_t *req)
{
	const char resp[] = "Received update request: About to update (Insecure)\n";
	httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
	xTaskCreate(ota_service_task_insecure,
		    "OTA Service Task",
		    STACK_SIZE, NULL,
		    1, NULL);
	return ESP_OK;
}
#endif
