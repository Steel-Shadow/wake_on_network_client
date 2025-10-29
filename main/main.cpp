/*
 * SPDX-FileCopyrightText: 2006-2016 ARM Limited
 * SPDX-FileCopyrightText: 2015-2025 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "esp_eap_client.h"
#include "esp_crt_bundle.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_log_level.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_websocket_client.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/idf_additions.h"
#include "freertos/projdefs.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include <cassert>
#include <string.h>

/* The examples use simple WiFi configuration that you can set via
   project configuration menu.

   If you'd rather not, just change the below entries to strings with
   the config you want - ie #define EXAMPLE_WIFI_SSID "mywifissid"

   You can choose EAP method via project configuration according to the
   configuration of AP.
*/
#define EXAMPLE_WIFI_SSID CONFIG_EXAMPLE_WIFI_SSID
#define EXAMPLE_EAP_METHOD CONFIG_EXAMPLE_EAP_METHOD

#define EXAMPLE_EAP_ID CONFIG_EXAMPLE_EAP_ID
#define EXAMPLE_EAP_USERNAME CONFIG_EXAMPLE_EAP_USERNAME
#define EXAMPLE_EAP_PASSWORD CONFIG_EXAMPLE_EAP_PASSWORD
#define EXAMPLE_SERVER_CERT_DOMAIN CONFIG_EXAMPLE_SERVER_CERT_DOMAIN

namespace WiFi {
static const char *LOG_TAG = "WiFi";

/* FreeRTOS event group to signal when we are connected & ready to make a
 * request */
static EventGroupHandle_t wifi_event_group;

/* esp netif object representing the WIFI station */
inline static esp_netif_t *sta_netif = nullptr;

/* The event group allows multiple bits for each event,
   but we only care about one event - are we connected
   to the AP with an IP? */
static const int CONNECTED_BIT = BIT0;


/* CA cert, taken from ca.pem
   Client cert, taken from client.crt
   Client key, taken from client.key

   The PEM, CRT and KEY file were provided by the person or organization
   who configured the AP with wifi enterprise.

   To embed it in the app binary, the PEM, CRT and KEY file is named
   in the component.mk COMPONENT_EMBED_TXTFILES variable.
*/
#if defined(CONFIG_EXAMPLE_VALIDATE_SERVER_CERT) || defined(CONFIG_EXAMPLE_WPA3_ENTERPRISE) || defined(CONFIG_EXAMPLE_WPA3_192BIT_ENTERPRISE) || defined(CONFIG_ESP_WIFI_EAP_TLS1_3)
#define SERVER_CERT_VALIDATION_ENABLED
#endif

#ifdef SERVER_CERT_VALIDATION_ENABLED
extern uint8_t ca_pem_start[] asm("_binary_ca_pem_start");
extern uint8_t ca_pem_end[] asm("_binary_ca_pem_end");
#endif /* SERVER_CERT_VALIDATION_ENABLED */

#ifdef CONFIG_EXAMPLE_EAP_METHOD_TLS
extern uint8_t client_crt_start[] asm("_binary_client_crt_start");
extern uint8_t client_crt_end[] asm("_binary_client_crt_end");
extern uint8_t client_key_start[] asm("_binary_client_key_start");
extern uint8_t client_key_end[] asm("_binary_client_key_end");
#endif /* CONFIG_EXAMPLE_EAP_METHOD_TLS */

#if defined CONFIG_EXAMPLE_EAP_METHOD_TTLS
esp_eap_ttls_phase2_types TTLS_PHASE2_METHOD =
        CONFIG_EXAMPLE_EAP_METHOD_TTLS_PHASE_2;
#endif /* CONFIG_EXAMPLE_EAP_METHOD_TTLS */

static void event_handler(void *arg, esp_event_base_t event_base,
                          int32_t event_id, void *event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        esp_wifi_connect();
        xEventGroupClearBits(wifi_event_group, CONNECTED_BIT);
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        xEventGroupSetBits(wifi_event_group, CONNECTED_BIT);
    }
}

static void initialise_wifi() {
    esp_eap_method_t eap_methods = ESP_EAP_TYPE_ALL;
#ifdef SERVER_CERT_VALIDATION_ENABLED
    unsigned int ca_pem_bytes = ca_pem_end - ca_pem_start;
#endif /* SERVER_CERT_VALIDATION_ENABLED */

#ifdef CONFIG_EXAMPLE_EAP_METHOD_TLS
    unsigned int client_crt_bytes = client_crt_end - client_crt_start;
    unsigned int client_key_bytes = client_key_end - client_key_start;
    eap_methods = ESP_EAP_TYPE_TLS;
#endif /* CONFIG_EXAMPLE_EAP_METHOD_TLS */

    ESP_ERROR_CHECK(esp_netif_init());
    wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    sta_netif = esp_netif_create_default_wifi_sta();
    assert(sta_netif);

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                               &event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                               &event_handler, NULL));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    wifi_config_t wifi_config = {
            .sta =
                    {
                            .ssid = EXAMPLE_WIFI_SSID,
#if defined(CONFIG_EXAMPLE_WPA3_192BIT_ENTERPRISE) || defined(CONFIG_EXAMPLE_WPA3_ENTERPRISE)
                            .pmf_cfg = {.required = true},
#endif
                    },
    };
    ESP_LOGI(LOG_TAG, "Setting WiFi configuration SSID %s...", wifi_config.sta.ssid);
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_eap_client_set_identity((uint8_t *) EXAMPLE_EAP_ID,
                                                strlen(EXAMPLE_EAP_ID)));

#ifdef SERVER_CERT_VALIDATION_ENABLED
    ESP_ERROR_CHECK(esp_eap_client_set_ca_cert(ca_pem_start, ca_pem_bytes));
#endif /* SERVER_CERT_VALIDATION_ENABLED */

#ifdef CONFIG_EXAMPLE_EAP_METHOD_TLS
    ESP_ERROR_CHECK(esp_eap_client_set_certificate_and_key(
            client_crt_start, client_crt_bytes, client_key_start, client_key_bytes,
            NULL, 0));
#endif /* CONFIG_EXAMPLE_EAP_METHOD_TLS */

#if defined(CONFIG_EXAMPLE_EAP_METHOD_PEAP) || defined(CONFIG_EXAMPLE_EAP_METHOD_TTLS)
    ESP_ERROR_CHECK(esp_eap_client_set_username((uint8_t *) EXAMPLE_EAP_USERNAME,
                                                strlen(EXAMPLE_EAP_USERNAME)));
    ESP_ERROR_CHECK(esp_eap_client_set_password((uint8_t *) EXAMPLE_EAP_PASSWORD,
                                                strlen(EXAMPLE_EAP_PASSWORD)));
#endif /* CONFIG_EXAMPLE_EAP_METHOD_PEAP || CONFIG_EXAMPLE_EAP_METHOD_TTLS */

#if defined CONFIG_EXAMPLE_EAP_METHOD_TTLS
    ESP_ERROR_CHECK(esp_eap_client_set_ttls_phase2_method(TTLS_PHASE2_METHOD));
    eap_methods = ESP_EAP_TYPE_TTLS;
#endif /* CONFIG_EXAMPLE_EAP_METHOD_TTLS */
#if defined(CONFIG_EXAMPLE_EAP_METHOD_PEAP)
    eap_methods = ESP_EAP_TYPE_PEAP;
#endif /* CONFIG_EXAMPLE_EAP_METHOD_PEAP */

#if defined(CONFIG_EXAMPLE_WPA3_192BIT_ENTERPRISE)
    ESP_LOGI(LOG_TAG, "Enabling 192 bit certification");
    ESP_ERROR_CHECK(esp_eap_client_set_suiteb_192bit_certification(true));
#endif
#ifdef CONFIG_EXAMPLE_USE_DEFAULT_CERT_BUNDLE
    ESP_ERROR_CHECK(esp_eap_client_use_default_cert_bundle(true));
#endif
#ifdef CONFIG_EXAMPLE_VALIDATE_SERVER_CERT_DOMAIN
    ESP_ERROR_CHECK(esp_eap_client_set_domain_name(EXAMPLE_SERVER_CERT_DOMAIN));
#endif
    ESP_ERROR_CHECK(esp_eap_client_set_eap_methods(eap_methods));
    ESP_ERROR_CHECK(esp_wifi_sta_enterprise_enable());
    ESP_ERROR_CHECK(esp_wifi_start());
}

/* static void wifi_enterprise_example_task(void *pvParameters) {
    esp_netif_ip_info_t ip;
    memset(&ip, 0, sizeof(esp_netif_ip_info_t));
    vTaskDelay(2000 / portTICK_PERIOD_MS);

    while (1) {
        vTaskDelay(2000 / portTICK_PERIOD_MS);

        if (esp_netif_get_ip_info(sta_netif, &ip) == 0) {
            ESP_LOGI(LOG_TAG, "~~~~~~~~~~~");
            ESP_LOGI(LOG_TAG, "IP:" IPSTR, IP2STR(&ip.ip));
            ESP_LOGI(LOG_TAG, "MASK:" IPSTR, IP2STR(&ip.netmask));
            ESP_LOGI(LOG_TAG, "GW:" IPSTR, IP2STR(&ip.gw));
            ESP_LOGI(LOG_TAG, "~~~~~~~~~~~");
        }
    }
} */
}; // namespace WiFi

namespace Websocket_app {
static const char *LOG_TAG = "Websocket";
static SemaphoreHandle_t sema_shutdown;

static void log_error_if_nonzero(const char *message, int error_code) {
    if (error_code != 0) {
        ESP_LOGE(LOG_TAG, "Last error %s: 0x%x", message, error_code);
    }
}

static void websocket_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data) {
    esp_websocket_event_data_t *data = (esp_websocket_event_data_t *) event_data;
    switch (event_id) {
        case WEBSOCKET_EVENT_BEGIN:
            ESP_LOGI(LOG_TAG, "WEBSOCKET_EVENT_BEGIN");
            break;
        case WEBSOCKET_EVENT_CONNECTED:
            ESP_LOGI(LOG_TAG, "WEBSOCKET_EVENT_CONNECTED");
            break;
        case WEBSOCKET_EVENT_DISCONNECTED:
            ESP_LOGI(LOG_TAG, "WEBSOCKET_EVENT_DISCONNECTED");
            log_error_if_nonzero("HTTP status code", data->error_handle.esp_ws_handshake_status_code);
            if (data->error_handle.error_type == WEBSOCKET_ERROR_TYPE_TCP_TRANSPORT) {
                log_error_if_nonzero("reported from esp-tls", data->error_handle.esp_tls_last_esp_err);
                log_error_if_nonzero("reported from tls stack", data->error_handle.esp_tls_stack_err);
                log_error_if_nonzero("captured as transport's socket errno", data->error_handle.esp_transport_sock_errno);
            }
            break;
        case WEBSOCKET_EVENT_DATA:
            if (data->op_code == 0x2) { // Opcode 0x2 indicates binary data
                ESP_LOG_BUFFER_HEX("Received binary data", data->data_ptr, data->data_len);
            } else if (data->op_code == 0x08 && data->data_len == 2) {
                ESP_LOGW(LOG_TAG, "Received closed message with code=%d", 256 * data->data_ptr[0] + data->data_ptr[1]);
            } else if (data->op_code == 0x09 || data->op_code == 0x0a) {
                // ping pong
            } else {
                ESP_LOGW(LOG_TAG, "Total payload length=%d, data_len=%d, current payload offset=%d\r\n", data->payload_len, data->data_len, data->payload_offset);
                ESP_LOGW(LOG_TAG, "Received=%.*s\n\n", data->data_len, (char *) data->data_ptr);

                const char *welcome = "welcome";
                const char *online = "online";
                if (strncmp(welcome, data->data_ptr, strlen(welcome)) == 0) {
                    xSemaphoreGive(sema_shutdown);
                } else if (strncmp(online, data->data_ptr, strlen(online)) == 0) {
                    ESP_LOGW(LOG_TAG, "online!");
                }
            }
            break;
        case WEBSOCKET_EVENT_ERROR:
            ESP_LOGI(LOG_TAG, "WEBSOCKET_EVENT_ERROR");
            log_error_if_nonzero("HTTP status code", data->error_handle.esp_ws_handshake_status_code);
            if (data->error_handle.error_type == WEBSOCKET_ERROR_TYPE_TCP_TRANSPORT) {
                log_error_if_nonzero("reported from esp-tls", data->error_handle.esp_tls_last_esp_err);
                log_error_if_nonzero("reported from tls stack", data->error_handle.esp_tls_stack_err);
                log_error_if_nonzero("captured as transport's socket errno", data->error_handle.esp_transport_sock_errno);
            }
            break;
        case WEBSOCKET_EVENT_FINISH:
            ESP_LOGI(LOG_TAG, "WEBSOCKET_EVENT_FINISH");
            break;
    }
}

esp_websocket_client_config_t websocket_cfg = {};

static void websocket_begin_task() {
    // shutdown this task after "welcome"
    sema_shutdown = xSemaphoreCreateBinary();

    // wss://echo.websocket.org
    // wss://wol.steel-shadow.duckdns.org/ws/Steel-Shadow_secret 8443
    // wss://wol.steel-shadow.me/ws/Steel-Shadow_secret 443
    const char *uri = "wss://wol.steel-shadow.me/ws/Steel-Shadow_secret";
    websocket_cfg.uri = uri;
    websocket_cfg.port = 443;


#if CONFIG_WS_OVER_TLS_MUTUAL_AUTH
    /* Configuring client certificates for mutual authentification */
    extern const char cacert_start[] asm("_binary_ca_cert_pem_start"); // CA certificate
    extern const char cert_start[] asm("_binary_client_cert_pem_start"); // Client certificate
    extern const char cert_end[] asm("_binary_client_cert_pem_end");
    extern const char key_start[] asm("_binary_client_key_pem_start"); // Client private key
    extern const char key_end[] asm("_binary_client_key_pem_end");

    websocket_cfg.cert_pem = cacert_start;
    websocket_cfg.client_cert = cert_start;
    websocket_cfg.client_cert_len = cert_end - cert_start;
    websocket_cfg.client_key = key_start;
    websocket_cfg.client_key_len = key_end - key_start;
#elif CONFIG_WS_OVER_TLS_SERVER_AUTH
    // Using certificate bundle as default server certificate source
    websocket_cfg.crt_bundle_attach = esp_crt_bundle_attach;
    // If using a custom certificate it could be added to certificate bundle, added to the build similar to client certificates in this examples,
    // or read from NVS.
    /* extern const char cacert_start[] asm("ADDED_CERTIFICATE"); */
    /* websocket_cfg.cert_pem = cacert_start; */
#endif

#if CONFIG_WS_OVER_TLS_SKIP_COMMON_NAME_CHECK
    websocket_cfg.skip_cert_common_name_check = true;
#endif

    ESP_LOGI(LOG_TAG, "Connecting to %s...", websocket_cfg.uri);

    esp_websocket_client_handle_t client = esp_websocket_client_init(&websocket_cfg);
    esp_websocket_register_events(client, WEBSOCKET_EVENT_ANY, websocket_event_handler, (void *) client);

    esp_websocket_client_start(client);

    while (!esp_websocket_client_is_connected(client)) {
        ESP_LOGI(LOG_TAG, "Websocket is not connected, delaying...");
        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }

    char data[32] = "hello ESP32";
    esp_websocket_client_send_text(client, data, 32, portMAX_DELAY);

    // delete the task after welcome
    xSemaphoreTake(sema_shutdown, portMAX_DELAY);
    ESP_LOGI(LOG_TAG, "task delete but remain the websocket");
    // esp_websocket_client_close(client, portMAX_DELAY);
    // ESP_LOGI(LOG_TAG, "Websocket Stopped");
    // esp_websocket_unregister_events(client, WEBSOCKET_EVENT_ANY, websocket_event_handler);
    // esp_websocket_client_destroy(client);
    vTaskDelete(NULL);
}
}; // namespace Websocket_app

extern "C" void app_main(void) {
    const char *LOG_TAG = "Main";
    ESP_LOGI(LOG_TAG, "[APP] Startup..");
    ESP_LOGI(LOG_TAG, "[APP] Free memory: %" PRIu32 " bytes", esp_get_free_heap_size());
    ESP_LOGI(LOG_TAG, "[APP] IDF version: %s", esp_get_idf_version());
    esp_log_level_set("*", ESP_LOG_INFO);
    esp_log_level_set("websocket_client", ESP_LOG_INFO);
    esp_log_level_set("transport_ws", ESP_LOG_INFO);
    esp_log_level_set("trans_tcp", ESP_LOG_INFO);

    ESP_ERROR_CHECK(nvs_flash_init());

    WiFi::initialise_wifi();
    while (1) {
        ESP_LOGI(LOG_TAG, "-----------Waiting for WiFi Init----------");
        esp_netif_ip_info_t ip;
        memset(&ip, 0, sizeof(esp_netif_ip_info_t));
        vTaskDelay(1000 / portTICK_PERIOD_MS);
        if (esp_netif_get_ip_info(WiFi::sta_netif, &ip) == 0) {
            if (ip.ip.addr != 0) {
                ESP_LOGI(LOG_TAG, "IP:" IPSTR, IP2STR(&ip.ip));
                ESP_LOGI(LOG_TAG, "MASK:" IPSTR, IP2STR(&ip.netmask));
                ESP_LOGI(LOG_TAG, "GW:" IPSTR, IP2STR(&ip.gw));
                ESP_LOGI(LOG_TAG, "-----WiFi Successfully Init-----");
                break;
            }
        }
    }

    // while (1) { // // 测试 ip6 地址
    //     esp_ip6_addr_t ip6[5];
    //     memset(&ip6, 0, 5 * sizeof(esp_ip6_addr_t));
    //     vTaskDelay(1000 / portTICK_PERIOD_MS);

    //     if (WiFi::sta_netif != NULL) {
    //         esp_err_t err = esp_netif_create_ip6_linklocal(WiFi::sta_netif);
    //         if (err != ESP_OK) {
    //             ESP_LOGE(WiFi::LOG_TAG, "Failed to create IPv6 link-local address on start: %s", esp_err_to_name(err));
    //         }
    //     } else {
    //         ESP_LOGE(WiFi::LOG_TAG, "WiFi::sta_netif is NULL on start");
    //     }

    //     if (esp_netif_get_all_ip6(WiFi::sta_netif, ip6) == 0) {
    //         if (ip6->addr[0] || ip6->addr[1] || ip6->addr[2] || ip6->addr[3] != 0) {
    //             for (int i = 0; i < 4; ++i) {
    //                 ESP_LOGI(LOG_TAG, "IP%d:%d", i, (&ip6->addr[0]));
    //             }
    //             break;
    //         }
    //     }
    // }

    xTaskCreate((TaskFunction_t) &Websocket_app::websocket_begin_task, "ws",
                4096, NULL, 5, NULL);

    // Websocket_app::websocket_task_start();
}
