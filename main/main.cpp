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
#include <cstddef>
#include <string.h>
#include "driver/gpio.h"
#include "portmacro.h"

/* 
    Set WIFI connection config in sdkconfig.
    Or directly replace the following macros with strings.
*/
#define WON_WIFI_SSID CONFIG_WON_WIFI_SSID
#define WON_EAP_METHOD CONFIG_WON_EAP_METHOD

#define WON_EAP_ID CONFIG_WON_EAP_ID
#define WON_EAP_USERNAME CONFIG_WON_EAP_USERNAME
#define WON_EAP_PASSWORD CONFIG_WON_EAP_PASSWORD
#define WON_SERVER_CERT_DOMAIN CONFIG_WON_SERVER_CERT_DOMAIN

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
#if defined(CONFIG_WON_VALIDATE_SERVER_CERT) || defined(CONFIG_WON_WPA3_ENTERPRISE) || defined(CONFIG_WON_WPA3_192BIT_ENTERPRISE) || defined(CONFIG_ESP_WIFI_EAP_TLS1_3)
#define SERVER_CERT_VALIDATION_ENABLED
#endif

#ifdef SERVER_CERT_VALIDATION_ENABLED
extern uint8_t ca_pem_start[] asm("_binary_ca_pem_start");
extern uint8_t ca_pem_end[] asm("_binary_ca_pem_end");
#endif /* SERVER_CERT_VALIDATION_ENABLED */

#ifdef CONFIG_WON_EAP_METHOD_TLS
extern uint8_t client_crt_start[] asm("_binary_client_crt_start");
extern uint8_t client_crt_end[] asm("_binary_client_crt_end");
extern uint8_t client_key_start[] asm("_binary_client_key_start");
extern uint8_t client_key_end[] asm("_binary_client_key_end");
#endif /* CONFIG_WON_EAP_METHOD_TLS */

#if defined CONFIG_WON_EAP_METHOD_TTLS
esp_eap_ttls_phase2_types TTLS_PHASE2_METHOD =
        CONFIG_WON_EAP_METHOD_TTLS_PHASE_2;
#endif /* CONFIG_WON_EAP_METHOD_TTLS */

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

#ifdef CONFIG_WON_EAP_METHOD_TLS
    unsigned int client_crt_bytes = client_crt_end - client_crt_start;
    unsigned int client_key_bytes = client_key_end - client_key_start;
    eap_methods = ESP_EAP_TYPE_TLS;
#endif /* CONFIG_WON_EAP_METHOD_TLS */

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
                            .ssid = WON_WIFI_SSID,
#if defined(CONFIG_WON_WPA3_192BIT_ENTERPRISE) || defined(CONFIG_WON_WPA3_ENTERPRISE)
                            .pmf_cfg = {.required = true},
#endif
                    },
    };
    ESP_LOGI(LOG_TAG, "Setting WiFi configuration SSID %s...", wifi_config.sta.ssid);
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_eap_client_set_identity((uint8_t *) WON_EAP_ID,
                                                strlen(WON_EAP_ID)));

#ifdef SERVER_CERT_VALIDATION_ENABLED
    ESP_ERROR_CHECK(esp_eap_client_set_ca_cert(ca_pem_start, ca_pem_bytes));
#endif /* SERVER_CERT_VALIDATION_ENABLED */

#ifdef CONFIG_WON_EAP_METHOD_TLS
    ESP_ERROR_CHECK(esp_eap_client_set_certificate_and_key(
            client_crt_start, client_crt_bytes, client_key_start, client_key_bytes,
            NULL, 0));
#endif /* CONFIG_WON_EAP_METHOD_TLS */

#if defined(CONFIG_WON_EAP_METHOD_PEAP) || defined(CONFIG_WON_EAP_METHOD_TTLS)
    ESP_ERROR_CHECK(esp_eap_client_set_username((uint8_t *) WON_EAP_USERNAME,
                                                strlen(WON_EAP_USERNAME)));
    ESP_ERROR_CHECK(esp_eap_client_set_password((uint8_t *) WON_EAP_PASSWORD,
                                                strlen(WON_EAP_PASSWORD)));
#endif /* CONFIG_WON_EAP_METHOD_PEAP || CONFIG_WON_EAP_METHOD_TTLS */

#if defined CONFIG_WON_EAP_METHOD_TTLS
    ESP_ERROR_CHECK(esp_eap_client_set_ttls_phase2_method(TTLS_PHASE2_METHOD));
    eap_methods = ESP_EAP_TYPE_TTLS;
#endif /* CONFIG_WON_EAP_METHOD_TTLS */
#if defined(CONFIG_WON_EAP_METHOD_PEAP)
    eap_methods = ESP_EAP_TYPE_PEAP;
#endif /* CONFIG_WON_EAP_METHOD_PEAP */

#if defined(CONFIG_WON_WPA3_192BIT_ENTERPRISE)
    ESP_LOGI(LOG_TAG, "Enabling 192 bit certification");
    ESP_ERROR_CHECK(esp_eap_client_set_suiteb_192bit_certification(true));
#endif
#ifdef CONFIG_WON_USE_DEFAULT_CERT_BUNDLE
    ESP_ERROR_CHECK(esp_eap_client_use_default_cert_bundle(true));
#endif
#ifdef CONFIG_WON_VALIDATE_SERVER_CERT_DOMAIN
    ESP_ERROR_CHECK(esp_eap_client_set_domain_name(WON_SERVER_CERT_DOMAIN));
#endif
    ESP_ERROR_CHECK(esp_eap_client_set_eap_methods(eap_methods));
    ESP_ERROR_CHECK(esp_wifi_sta_enterprise_enable());
    ESP_ERROR_CHECK(esp_wifi_start());
}

}; // namespace WiFi

namespace Pin {
auto pin = GPIO_NUM_4;

static void init_pin() {
    gpio_config_t io_conf = {
            .pin_bit_mask = (1ULL << pin),
            .mode = GPIO_MODE_OUTPUT,
            .pull_up_en = GPIO_PULLUP_DISABLE,
            .pull_down_en = GPIO_PULLDOWN_DISABLE,
            .intr_type = GPIO_INTR_DISABLE,
    };
    gpio_config(&io_conf);
}

static void open_pc_power() {
    gpio_set_level(pin, 1);
    vTaskDelay(1000 / portTICK_PERIOD_MS);
    gpio_set_level(pin, 0);
}
} // namespace Pin

namespace Websocket_app {
static const char *LOG_TAG = "Websocket";
static SemaphoreHandle_t sema_allow_reconnect_ws;
static bool flag_first_message;

static void log_error_if_nonzero(const char *message, int error_code) {
    if (error_code != 0) {
        ESP_LOGE(LOG_TAG, "Last error %s: 0x%x", message, error_code);
    }
}

static void websocket_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data) {
    esp_websocket_event_data_t *data = (esp_websocket_event_data_t *) event_data;
    esp_websocket_client_handle_t client = (esp_websocket_client_handle_t) handler_args;
    switch (event_id) {
        case WEBSOCKET_EVENT_BEGIN:
            // The client thread is running.
            ESP_LOGI(LOG_TAG, "WEBSOCKET_EVENT_BEGIN");
            break;
        case WEBSOCKET_EVENT_BEFORE_CONNECT:
            // The client is about to connect.
            ESP_LOGI(LOG_TAG, "WEBSOCKET_EVENT_BEFORE_CONNECT");
            break;
        case WEBSOCKET_EVENT_CONNECTED:
            // The client has successfully established a connection to the server. The client is now ready to send and receive data. Contains no event data.
            ESP_LOGI(LOG_TAG, "WEBSOCKET_EVENT_CONNECTED");
            ESP_LOGI(LOG_TAG, "Say \"hello ESP32\"");
            {
                static const char data[32] = "hello ESP32";
                esp_websocket_client_send_text(client, data, 32, portMAX_DELAY);
            }
            break;
        case WEBSOCKET_EVENT_DATA:
            // The client has successfully received and parsed a WebSocket frame.
            // The event data contains a pointer to the payload data, the length of the payload data as well as the opcode of the received frame.
            // A message may be fragmented into multiple events if the length exceeds the buffer size.
            // This event will also be posted for non-payload frames, e.g. pong or connection close frames.
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
                const char *trigger = "trigger";
                if (flag_first_message) {
                    flag_first_message = false;
                    size_t len_welcome = strlen(welcome);
                    if (!(len_welcome == data->data_len && strncmp(welcome, data->data_ptr, len_welcome) == 0)) {
                        ESP_LOGE(LOG_TAG, "First message is not \"welcome\"!");
                    }
                } else if (strncmp(trigger, data->data_ptr, strlen(trigger)) == 0) {
                    // [%*.*s]\n
                    ESP_LOGW(LOG_TAG, "Server say: [%.*s]\n", data->data_len, data->data_ptr);
                    Pin::open_pc_power();
                }
            }
            break;
        case WEBSOCKET_EVENT_ERROR:
            // The client has experienced an error. Examples include transport write or read failures.
            ESP_LOGI(LOG_TAG, "WEBSOCKET_EVENT_ERROR");
            log_error_if_nonzero("HTTP status code", data->error_handle.esp_ws_handshake_status_code);
            if (data->error_handle.error_type == WEBSOCKET_ERROR_TYPE_TCP_TRANSPORT) {
                log_error_if_nonzero("reported from esp-tls", data->error_handle.esp_tls_last_esp_err);
                log_error_if_nonzero("reported from tls stack", data->error_handle.esp_tls_stack_err);
                log_error_if_nonzero("captured as transport's socket errno", data->error_handle.esp_transport_sock_errno);
            }
            break;
        case WEBSOCKET_EVENT_DISCONNECTED:
            //  The client has aborted the connection due to the transport layer failing to read data,
            //  e.g. because the server is unavailable.
            // Contains no event data.
            ESP_LOGI(LOG_TAG, "WEBSOCKET_EVENT_DISCONNECTED");
            log_error_if_nonzero("HTTP status code", data->error_handle.esp_ws_handshake_status_code);
            if (data->error_handle.error_type == WEBSOCKET_ERROR_TYPE_TCP_TRANSPORT) {
                log_error_if_nonzero("reported from esp-tls", data->error_handle.esp_tls_last_esp_err);
                log_error_if_nonzero("reported from tls stack", data->error_handle.esp_tls_stack_err);
                log_error_if_nonzero("captured as transport's socket errno", data->error_handle.esp_transport_sock_errno);
            }
            break;
        case WEBSOCKET_EVENT_CLOSED:
            // The connection has been closed cleanly.
            ESP_LOGI(LOG_TAG, "WEBSOCKET_EVENT_CLOSED");
            break;
        case WEBSOCKET_EVENT_FINISH:
            // The client thread is about to exit.
            ESP_LOGI(LOG_TAG, "WEBSOCKET_EVENT_FINISH");
            xSemaphoreGive(sema_allow_reconnect_ws);
            break;
        default:
            ESP_LOGW(LOG_TAG, "Websocket event handler get bad event_id: %d", event_id);
    }
}

static esp_websocket_client_handle_t client;
static esp_websocket_client_config_t websocket_cfg;

// shutdown this task after "welcome"
static void init_config() {
    sema_allow_reconnect_ws = xSemaphoreCreateBinary();

    flag_first_message = true;
    websocket_cfg = {};
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
}

static void websocket_autoreconnect_task() {
    init_config();

    do {
        ESP_LOGI(LOG_TAG, "Connecting to %s...", websocket_cfg.uri);
        client = esp_websocket_client_init(&websocket_cfg);
        esp_websocket_register_events(client, WEBSOCKET_EVENT_ANY, websocket_event_handler, (void *) client);
        esp_websocket_client_start(client);

        xSemaphoreTake(sema_allow_reconnect_ws, portMAX_DELAY);

        esp_websocket_client_close(client, portMAX_DELAY);
        esp_websocket_unregister_events(client, WEBSOCKET_EVENT_ANY, websocket_event_handler);
        esp_websocket_client_close(client, portMAX_DELAY);

        vTaskDelay(1000 / portTICK_PERIOD_MS);
    } while (1);

    vSemaphoreDelete(sema_allow_reconnect_ws);
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

    Pin::init_pin();

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

    xTaskCreate((TaskFunction_t) Websocket_app::websocket_autoreconnect_task, "ws",
                4096, NULL, 5, NULL);
}
