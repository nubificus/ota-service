# ota-service
ESP32 Component for performing Over the Air updates

## How to use
```
cd <path-to-your-esp-idf-project>
mkdir -p components
cd components
git clone https://github.com/nubificus/ota-service.git
```
Add the component to your project by simply adding the following line inside `idf_component_register()` of `<path-to-your-esp-idf-project>/main/CMakeLists.txt`:
```
REQUIRES ota-service
```
E.g:
```
idf_component_register(SRCS "test.c"
                       INCLUDE_DIRS "."
                       REQUIRES ota-service)
```
You may also have to add the following line inside your project's `sdkconfig` file to resolve some `mbedtls` issues:
```
CONFIG_MBEDTLS_HKDF_C=y
```
Afterwards, you can include the component's header file:
```c
#include "ota-service.h"
```

And enable the OTA Service to run **on the background** by calling:
```c
ota_service_begin(<OTA-Server-IP-Addr>);
```
Make sure you have connected the device on the internet previously.
