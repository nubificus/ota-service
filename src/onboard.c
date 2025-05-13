#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "ota-service.h"
#include "dice_cert.h"
#include "esp_log.h"
#include "esp_http_server.h"

#define STACK (16 * 1024)
#define DESC "Dice attestation certificate"
#define FAIL_MSG "Could not generate the certificate"

static unsigned char *cert = NULL;
static int len = 0;

void get_dice_cert_task(void *pvParameters) {
	len = get_dice_cert_ptr(&cert);
	if (len <= 0) {
		printf("Could not generate the certificate");
		len = -1;
	}
	vTaskDelete(NULL);
}

esp_err_t onboard_request_handler(httpd_req_t *req) {
	if (len == 0) { /* if the certificate has not been generated */
		BaseType_t result = xTaskCreate(get_dice_cert_task, DESC, STACK,
						NULL, 1, NULL);
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

	httpd_resp_send(req, (void*)cert, len);
	return ESP_OK;
}
