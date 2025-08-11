#ifndef TLS_H
#define TLS_H

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"

typedef struct {
    mbedtls_net_context net;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_x509_crt cacert;
} tls_session_t;

int tls_establish(tls_session_t *session, const char *server_ip);
void tls_cleanup(tls_session_t *session);
int tls_send_dice_cert(tls_session_t *session, void *cert, size_t len);
int tls_safe_read(tls_session_t *session, unsigned char *buf, size_t len);

#endif /* TLS_H */
