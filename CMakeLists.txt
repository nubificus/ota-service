# Embed the server root certificate into the final binary
#
# (If this was a component, we would set COMPONENT_EMBED_TXTFILES here.)
file(GLOB OTA_SRCS "src/*.c")
idf_component_register(SRCS ${OTA_SRCS} INCLUDE_DIRS "include"
			    EMBED_TXTFILES certs/server.crt)
