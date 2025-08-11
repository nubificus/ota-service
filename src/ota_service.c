#ifdef OTA_SECURE

#include "tls.h"
#include "dice_cert.h"
#include "esp_ota_ops.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "esp_log.h"

#include <stdbool.h>
#include "esp_err.h"
#include "esp_http_server.h"

#define STACK_SIZE 16 * 1024

// Add this global static variable if not declared:
static size_t partition_data_written = 0;
static const esp_partition_t* update_partition = NULL;
static esp_ota_handle_t update_handle = 0;
static int ota_process_begin();

static const char *TAG = "ota";

#define MAX_ATTEMPTS 20

static volatile bool ota_in_progress = false;

void set_ota_in_progress(bool v) { ota_in_progress = v; }
bool is_ota_in_progress(void) { return ota_in_progress; }


static int ota_setup_partition_and_reboot();
static int ota_append_data_to_partition(unsigned char* data, size_t len);

#if 0
static int ota_write_partition_from_tls_stream(tls_session_t *session) {
    const int chunk = 1024;
    unsigned char buf[chunk];
    bool ota_started = false;

    partition_data_written = 0;
    while (1) {
        int ret = tls_safe_read(session, buf, sizeof(buf));
        if (ret <= 0) break;
        if (!ota_started) {
            ota_process_begin();
            ota_started = true;
        }
        ret = ota_append_data_to_partition(buf, ret);
	if (ret) {
		ESP_LOGE(TAG, "OTA append failed, %d", ret);
    	}
        vTaskDelay(pdMS_TO_TICKS(20));
    }
    return ota_started ? 0 : -1;
}
#endif
static int ota_write_partition_from_tls_stream(tls_session_t *session) {
    const int chunk = 1024;
    unsigned char buf[chunk];
    bool ota_started = false;
    partition_data_written = 0;

    while (1) {
        int ret = tls_safe_read(session, buf, sizeof(buf));
	//ESP_LOGI(TAG, "read: %d", ret);

	if (ret == 0) {
		ESP_LOGI(TAG, "Done!");
		break; //Done!
	}
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            // No data available now, yield and retry later
	    ESP_LOGI(TAG, "retry: %d", ret);
            vTaskDelay(pdMS_TO_TICKS(10));
            continue;
        }
        if (ret < 0) {
            ESP_LOGE(TAG, "TLS read error or connection closed");
            break;
        }

	if (!ota_started) {
            esp_err_t err = ota_process_begin();
            if (err != ESP_OK) {
                ESP_LOGE(TAG, "OTA begin failed: %d", err);
                return -1;
            }
            ota_started = true;
        }

	esp_err_t write_ret = ota_append_data_to_partition(buf, ret);
        if (write_ret != ESP_OK) {
            ESP_LOGE(TAG, "OTA append failed: %d", write_ret);
            break;
        }

        // Small yield to allow other tasks CPU access
        vTaskDelay(pdMS_TO_TICKS(5));
    }

    return ota_started ? 0 : -1;
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
                   10, NULL);
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

static int ota_process_begin() {
       update_partition = esp_ota_get_next_update_partition(NULL);
       assert(update_partition != NULL);

       set_ota_in_progress(true);
       vTaskDelay(pdMS_TO_TICKS(2000));

       esp_err_t err = esp_ota_begin(update_partition, OTA_WITH_SEQUENTIAL_WRITES, &update_handle);

       if (err != ESP_OK) {
               ESP_LOGE(TAG, "esp_ota_begin() failed (%s)", esp_err_to_name(err));
               esp_ota_abort(update_handle);
	       set_ota_in_progress(false);

               return err;
       }

       ESP_LOGI(TAG, "esp_ota_begin succeeded");
       return ESP_OK;
}

#ifdef OTA_SECURE
void ota_service_task_secure(void *pvParameters) {
    char *server_ip = (char *) pvParameters;
    tls_session_t session;
    uint8_t attempts = 0;

    char cert_buf[1024];
    int len = gen_dice_cert(cert_buf, sizeof(cert_buf));
    if (len <= 0) {
        ESP_LOGE(TAG, "Failed to generate DICE certificate");
        vTaskDelete(NULL);
    }

    while (attempts++ < MAX_ATTEMPTS) {
        ESP_LOGI(TAG, "TLS connection start");
        if (tls_establish(&session, server_ip) < 0) {
            ESP_LOGW(TAG, "TLS connection failed, retrying...");
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }

        ESP_LOGI(TAG, "DICE Cert send");
        if (tls_send_dice_cert(&session, cert_buf, len) < 0) {
            ESP_LOGE(TAG, "Failed to send certificate to server");
            tls_cleanup(&session);
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }

        ESP_LOGI(TAG, "OTA Write partition");
        if (ota_write_partition_from_tls_stream(&session) < 0) {
            ESP_LOGE(TAG, "OTA partition write failed");
            tls_cleanup(&session);
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }

        ESP_LOGI(TAG, "TLS cleanup start");
        tls_cleanup(&session);

        ESP_LOGI(TAG, "Setup partition and reboot");
        if (ota_setup_partition_and_reboot() == 0) {
            // Successfully updated and rebooting, delete task.
            vTaskDelete(NULL);
        } else {
            ESP_LOGE(TAG, "OTA partition setup failed");
            vTaskDelete(NULL);
        }
    }
    set_ota_in_progress(false);

    ESP_LOGE(TAG, "Max retry attempts reached, aborting OTA");
    vTaskDelete(NULL);
}
#endif

static int ota_append_data_to_partition(unsigned char* data, size_t len) {
	int ret = 0;
	ret = esp_ota_write(update_handle, (const void*) data, len);
	if (ret != ESP_OK) {
               ESP_LOGE(TAG, "esp_ota_write() failed, ret: %d", ret);
               esp_ota_abort(update_handle);

               return ret;
       }
       partition_data_written += len;
       //ESP_LOGI(TAG, "data written: %d, chunk: %d, ret: %d", partition_data_written, len, ret);
       return ret;
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

       ESP_LOGI(TAG, "Setup partition");
       err = esp_ota_set_boot_partition(update_partition);
       if (err != ESP_OK) {
               ESP_LOGE(TAG, "esp_ota_set_boot_partition failed (%s)!", esp_err_to_name(err));
               return -1;
       }
       ESP_LOGI(TAG, "Prepare to restart system!");
       vTaskDelay(pdMS_TO_TICKS(1000));
       esp_restart();

       /* Probably unreachable */
       return -1;
}
