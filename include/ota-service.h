#ifndef __INCLUDE_OTA_SERVICE_H__
#define __INCLUDE_OTA_SERVICE_H__

#include "esp_http_server.h"

/* 
 * this function can be passed as an
 * argument in `akri_set_update_handler()`
 * so that it only runs when we receive a
 * POST request at `/update` endpoint.
 * */
esp_err_t ota_request_handler(httpd_req_t *req);

/*
 * On the other hand, this is a
 * direct trigger to the OTA update
 * process. Pass the IP address of
 * the OTA Agent as an argument.
 * */
#ifdef OTA_SECURE
void ota_service_begin(char *ip);
#endif

#endif
