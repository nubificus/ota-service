#pragma once

#ifdef OTA_SECURE

#ifndef __OTA_TLS_H__
#define __OTA_TLS_H__

#include <mbedtls/ssl.h>
#include <stddef.h>

int tls_establish(mbedtls_ssl_context *ssl, char *server_ip);

int tls_send_dice_cert(mbedtls_ssl_context *ssl, void *cert, size_t len);

void tls_kill_connection(mbedtls_ssl_context *ssl);

int cert_ok(mbedtls_ssl_context *ssl); 

int update_wait(mbedtls_ssl_context *ssl);

int tls_next_chunk(mbedtls_ssl_context *ssl, unsigned char* buf);

#endif

#endif
