#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "ota-service.h"
#include "esp_log.h"
#include "esp_http_server.h"

#ifdef OTA_SECURE

#include "dice_cert.h"

#define STACK (16 * 1024)
#define DESC "Dice attestation certificate"
#define FAIL_MSG "Could not generate the certificate"

static char cert_buf[1024] = { 0 };
static int len = 0;

#ifdef OTA_SECURE
void gen_dice_cert_task(void *pvParameters) {
#ifdef OTA_SECURE
	len = gen_dice_cert(cert_buf, sizeof(cert_buf));
	if (len <= 0) {
		printf("Could not generate the certificate");
		len = -1;
	}
#else
	len = -1;
#endif
	vTaskDelete(NULL);
}
#endif

esp_err_t onboard_request_handler(httpd_req_t *req) {
#ifdef OTA_SECURE
	if (len == 0) { /* if the certificate has not been generated */
		BaseType_t result = xTaskCreate(gen_dice_cert_task, DESC, STACK,
						NULL, 5, NULL);
		if (result != pdPASS) {
			printf("Could not create dice cert task.\n");
			httpd_resp_set_status(req, "500 Internal Server Error");
			httpd_resp_send(req, FAIL_MSG, strlen(FAIL_MSG));
			return ESP_OK;
		}
		while (len == 0)
			vTaskDelay(100);
	}
	if (len == -1) { /* if certificate could not been generated */
		printf("Failed to create the attestation certificate.\n");
		httpd_resp_set_status(req, "500 Internal Server Error");
		httpd_resp_send(req, FAIL_MSG, strlen(FAIL_MSG));
		return ESP_OK;
	}

	httpd_resp_send(req, cert_buf, len);
	return ESP_OK;
#else
	httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OTA_SECURE not enabled");
	return ESP_FAIL;
#endif
}

#else

esp_err_t onboard_request_handler(httpd_req_t *req) {
	httpd_resp_set_status(req, "501 Not Implemented");
	httpd_resp_send(req, "Onboarding not available (OTA_SECURE not enabled)", 49);
	return ESP_OK;
}

#endif
