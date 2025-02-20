#ifdef OTA_SECURE

#include <string.h>
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "tls.h"
#include "esp_log.h"
#include <lwip/sockets.h>

static const char *TAG = "tls";

extern const uint8_t server_cert_pem_start[] asm("_binary_server_crt_start");
extern const uint8_t server_cert_pem_end[] asm("_binary_server_crt_end");

const char *server_port = "4433";

int tls_establish(mbedtls_ssl_context *ssl, char *server_ip) {
    if (ssl == NULL)
	    return -1;

    const char *pers = "ssl_client";
    char err_buf[100];
    mbedtls_net_context server_fd;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_x509_crt cacert;

    mbedtls_net_init(&server_fd);
    
    mbedtls_ssl_init(ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_x509_crt_init(&cacert);

    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char *) pers, strlen(pers));
    if (ret != 0) {
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        ESP_LOGE(TAG, "Failed to seed RNG: %s", err_buf);
        goto exit;
    }

    ret = mbedtls_x509_crt_parse(&cacert, server_cert_pem_start,
                                 server_cert_pem_end - server_cert_pem_start);
    if (ret < 0) {
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        ESP_LOGE(TAG, "Failed to parse server certificate: %s", err_buf);
        goto exit;
    }

    ret = mbedtls_ssl_config_defaults(&conf,
                                      MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        ESP_LOGE(TAG, "Failed to configure SSL defaults: %s", err_buf);
        goto exit;
    }

    mbedtls_ssl_conf_min_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED); 
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_read_timeout(&conf, 5000);

    ret = mbedtls_ssl_setup(ssl, &conf);
    if (ret != 0) {
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        ESP_LOGE(TAG, "Failed to setup SSL context: %s", err_buf);
        goto exit;
    }

    //int fd = server_fd.fd;
    //fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    //if (fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK)
	//    printf("Blocking mode enabled\n");
    //else
//	    printf("Blocking mode disabled\n");
    
    ESP_LOGI(TAG, "Connecting to %s:%s...", server_ip, server_port);
    ret = mbedtls_net_connect(&server_fd, server_ip, server_port, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0) {
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        ESP_LOGE(TAG, "Failed to connect to server: %s", err_buf);
        goto exit;
    }

    ESP_LOGI(TAG, "Connected to server");

    mbedtls_ssl_set_bio(ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    ESP_LOGI(TAG, "Performing SSL handshake...");
    while ((ret = mbedtls_ssl_handshake(ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_strerror(ret, err_buf, sizeof(err_buf));
            ESP_LOGE(TAG, "SSL handshake failed: %s", err_buf);
            goto exit;
        }
    }

    ESP_LOGI(TAG, "SSL handshake successful");

    uint32_t flags = mbedtls_ssl_get_verify_result(ssl);
    if (flags != 0) {
        char vrfy_buf[512];
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "", flags);
        ESP_LOGE(TAG, "Failed to verify server certificate: %s", vrfy_buf);
        goto exit;
    }

    ESP_LOGI(TAG, "Server certificate verified");
    mbedtls_net_set_nonblock(&server_fd);
    return 1;

exit:
    mbedtls_net_free(&server_fd);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_ssl_free(ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    
    ESP_LOGE(TAG, "Could not establish connection");
    return -1;
}

#define RETRY_DELAY_MS 500
#define MAX_RETRY_TIME_MS 3000

int tls_send_dice_cert(mbedtls_ssl_context *ssl, void *cert, size_t len) {
	ESP_LOGI(TAG, "Attemting to send the Certificate..");
	int total_sleep_time = 0;
	int bytes_sent = 0;

	while (bytes_sent < len) {
		const unsigned char *read_from = cert + bytes_sent;
		int nr_bytes = len - bytes_sent;
		int ret = mbedtls_ssl_write(ssl, read_from, nr_bytes);

		if (ret > 0) {
			bytes_sent += ret;
			total_sleep_time = 0;
			continue;
		}

		/* Handle errors */
		if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
			ESP_LOGE(TAG, "Connection closed before sending the certificate");
			return -1;
		} else if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
			ESP_LOGW(TAG, "mbedtls_ssl_write() wants read/write, retrying...");
		} else if (ret == 0) {
			ESP_LOGE(TAG, "Connection closed unexpectedly");
		} else {
			ESP_LOGE(TAG, "mbedtls_ssl_write() failed with error code: %d", ret);
		}

		/* Wait for an amount of time before retrying */
		if (total_sleep_time < MAX_RETRY_TIME_MS) {
			vTaskDelay(pdMS_TO_TICKS(RETRY_DELAY_MS));
			total_sleep_time += RETRY_DELAY_MS;
		} else {
			ESP_LOGE(TAG, "Max retry time exceeded, aborting.");
			return -1;
		}
	}
	ESP_LOGI(TAG, "Message sent to server");
	return 1;
}

void tls_kill_connection(mbedtls_ssl_context *ssl) {
	mbedtls_ssl_close_notify(ssl);
}

int cert_ok(mbedtls_ssl_context *ssl) {
	unsigned char status;
	int ret = mbedtls_ssl_read(ssl, &status, 1);
	if (ret < 0) {
		ESP_LOGE(TAG, "Failed to read response from server");
		return 0;
	}
	return status - '0';
}


int update_wait(mbedtls_ssl_context *ssl) {
	ESP_LOGI(TAG, "Waiting for update over the air...");
	unsigned char buf[25] = {0};
	while (1) {
		#if 0
		size_t bytes = mbedtls_ssl_get_bytes_avail(ssl);
		if (bytes > 0) {
			int ret = mbedtls_ssl_read(ssl, buf, sizeof(buf) - 1);
			printf("ret: %d - Message: %s\n", ret, buf);
			return 1;
		} else {
			ESP_LOGI(TAG, "No available bytes yet..");
			vTaskDelay(1000 / portTICK_PERIOD_MS);
			continue;
		}
		#endif
		int ret = mbedtls_ssl_read(ssl, buf, sizeof(buf));
		if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
			ESP_LOGI(TAG, "No data available yet..");
			vTaskDelay(500 / portTICK_PERIOD_MS);
			continue;
		} else if (ret == 0 || ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
			ESP_LOGE(TAG, "Connection has been closed from the server");
			return 0;
		} else if (ret < 0) {
			vTaskDelay(500 / portTICK_PERIOD_MS);
			continue;
		} else {
			printf("Server's Response(%d): %s", ret, buf);
			return 1;
		}
	}
}

#define CHUNK 64
int tls_next_chunk(mbedtls_ssl_context *ssl, unsigned char* buf) {
	static bool unset_nonblock = false;

	if (!unset_nonblock) {
		mbedtls_net_context *net_ctx =
			(mbedtls_net_context *) ssl->MBEDTLS_PRIVATE(p_bio);
		if (net_ctx == NULL)
			return -1;

		int fd = net_ctx->fd;
		int oldfl = fcntl(fd, F_GETFL);
		fcntl(fd, F_SETFL, oldfl & ~O_NONBLOCK);
		unset_nonblock = true;
	}
	return mbedtls_ssl_read(ssl, buf, CHUNK);
}

#endif
