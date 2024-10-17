file(GLOB OTA_SRCS "src/*.c")

idf_component_register(SRCS ${OTA_SRCS} INCLUDE_DIRS "src" "include"
		       EMBED_TXTFILES certs/server.crt
		       REQUIRES mbedtls nvs_flash app_update esp_netif esp_event)
