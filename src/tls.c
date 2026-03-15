#ifdef OTA_SECURE

#include <string.h>
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/psa_util.h"
#include "mbedtls/debug.h"
#include "psa/crypto.h"
#include "tls.h"
#include "esp_log.h"
#include <lwip/sockets.h>
#include <fcntl.h>

static const char *TAG = "tls";

extern const uint8_t server_cert_pem_start[] asm("_binary_server_crt_start");
extern const uint8_t server_cert_pem_end[] asm("_binary_server_crt_end");

const char *server_port = "4433";
#include "freertos/FreeRTOS.h"
#include "esp_log.h"

#define RETRY_DELAY_MS 500
#define MAX_RETRY_TIME_MS 3000


int tls_establish(tls_session_t *session, const char *server_ip) {
    if (!session) return -1;
    memset(session, 0, sizeof(*session));

    const char *pers = "ssl_client";
    char err_buf[100];

    psa_crypto_init();

    mbedtls_net_init(&session->net);
    mbedtls_ssl_init(&session->ssl);
    mbedtls_ssl_config_init(&session->conf);
    mbedtls_x509_crt_init(&session->cacert);

    int ret = mbedtls_x509_crt_parse(&session->cacert, server_cert_pem_start,
                                 server_cert_pem_end - server_cert_pem_start);
    if (ret < 0) {
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        ESP_LOGE(TAG, "Failed to parse server certificate: %s", err_buf);
        return -1;
    }

    ret = mbedtls_ssl_config_defaults(&session->conf,
                                      MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        ESP_LOGE(TAG, "Failed to configure SSL defaults: %s", err_buf);
        return -1;
    }

    mbedtls_ssl_conf_min_tls_version(&session->conf, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(&session->conf, MBEDTLS_SSL_VERSION_TLS1_2);

    mbedtls_ssl_conf_authmode(&session->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&session->conf, &session->cacert, NULL);
    mbedtls_ssl_conf_rng(&session->conf, mbedtls_psa_get_random, MBEDTLS_PSA_RANDOM_STATE);
    mbedtls_ssl_conf_read_timeout(&session->conf, 500);

    ret = mbedtls_ssl_setup(&session->ssl, &session->conf);
    if (ret != 0) {
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        ESP_LOGE(TAG, "Failed to setup SSL: %s", err_buf);
        return -1;
    }

    mbedtls_net_set_nonblock(&session->net);
    int sflags = fcntl(session->net.fd, F_GETFL, 0);
    ESP_LOGI(TAG, "Socket flags after nonblock: 0x%x", sflags);

    ESP_LOGI(TAG, "Connecting to %s:%s...", server_ip, server_port);
    ret = mbedtls_net_connect(&session->net, server_ip, server_port, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0) {
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        ESP_LOGE(TAG, "Failed TCP connect: %s", err_buf);
        return -1;
    }

    ESP_LOGI(TAG, "Connected, starting handshake...");
    mbedtls_ssl_set_bio(&session->ssl, &session->net,
                        mbedtls_net_send, mbedtls_net_recv, NULL);
    mbedtls_ssl_set_hostname(&session->ssl, "ota-agent");

    while ((ret = mbedtls_ssl_handshake(&session->ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_strerror(ret, err_buf, sizeof(err_buf));
            ESP_LOGE(TAG, "Handshake failed: %s", err_buf);
            return -1;
        }
    }

    ESP_LOGI(TAG, "Handshake done");

    uint32_t flags = mbedtls_ssl_get_verify_result(&session->ssl);
    if (flags != 0) {
        char vrfy_buf[512];
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "", flags);
        ESP_LOGE(TAG, "Certificate verify failed: %s", vrfy_buf);
        return -1;
    }
    ESP_LOGI(TAG, "TLS ready");
    return 1;
}

void tls_cleanup(tls_session_t *session) {
    if (!session) return;
    mbedtls_ssl_close_notify(&session->ssl);
    mbedtls_net_free(&session->net);
    mbedtls_x509_crt_free(&session->cacert);
    mbedtls_ssl_free(&session->ssl);
    mbedtls_ssl_config_free(&session->conf);
    memset(session, 0, sizeof(*session));
}
#define RETRY_DELAY_MS 500
#define MAX_RETRY_TIME_MS 3000

int tls_send_dice_cert(tls_session_t *session, void *cert, size_t len) {
    ESP_LOGI(TAG, "Sending DICE certificate...");
    int total_sleep_time = 0;
    int bytes_sent = 0;
    unsigned char *ptr = cert;

    while (bytes_sent < len) {
        int ret = mbedtls_ssl_write(&session->ssl, ptr + bytes_sent, len - bytes_sent);

        if (ret > 0) {
            bytes_sent += ret;
            total_sleep_time = 0;
            continue;
        }

        // Handle connection closed by peer immediately
        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            ESP_LOGE(TAG, "Peer closed the connection during certificate send");
            return -1;
        }

        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            vTaskDelay(pdMS_TO_TICKS(RETRY_DELAY_MS));
            total_sleep_time += RETRY_DELAY_MS;
            if (total_sleep_time >= MAX_RETRY_TIME_MS) {
                ESP_LOGE(TAG, "Retry timeout sending certificate");
                return -1;
            }
            continue;
        }

        if (ret == 0) {
            ESP_LOGE(TAG, "Connection closed unexpectedly during certificate send");
            return -1;
        }

        // Other fatal error
        char errbuf[128];
        mbedtls_strerror(ret, errbuf, sizeof(errbuf));
        ESP_LOGE(TAG, "mbedtls_ssl_write failed: %s", errbuf);
        return -1;
    }

    ESP_LOGI(TAG, "Certificate sent successfully");
    return 1;
}

int tls_safe_read(tls_session_t *session, unsigned char *buf, size_t len) {
    int ret = mbedtls_ssl_read(&session->ssl, buf, len);
    if (ret > 0 || ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return ret;  // bytes read or retry
    }
    if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || ret < 0) {
        // other errors
        return -1;
    }
    return ret; //Connection closed (should be only when ret = 0)
}


#if 0
int tls_safe_read(tls_session_t *session, unsigned char *buf, size_t len) {
    int ret = mbedtls_ssl_read(&session->ssl, buf, len);
    if (ret > 0) return ret;
    if (ret == 0 || ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY ||
        ret == MBEDTLS_ERR_SSL_INVALID_RECORD ||
        ret < 0) {
        return -1;
    }
    return ret;
}
#endif

#endif
