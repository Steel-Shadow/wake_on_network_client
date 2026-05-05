/*
 * SPDX-FileCopyrightText: 2022-2024 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */

#include <stdlib.h>
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "tinyusb.h"
#include "class/hid/hid_device.h"

static const char *TAG = "tusb_hid";

/************* TinyUSB descriptors ****************/

#define TUSB_DESC_TOTAL_LEN (TUD_CONFIG_DESC_LEN + CFG_TUD_HID * TUD_HID_DESC_LEN)

/**
 * @brief HID report descriptor
 *
 * This device exposes only a keyboard HID report.
 */
const uint8_t hid_report_descriptor[] = {
        TUD_HID_REPORT_DESC_KEYBOARD(HID_REPORT_ID(HID_ITF_PROTOCOL_KEYBOARD)),
        // TUD_HID_REPORT_DESC_MOUSE(HID_REPORT_ID(HID_ITF_PROTOCOL_MOUSE)),
};

/**
 * @brief String descriptor
 */
const char *hid_string_descriptor[5] = {
        // array of pointer to string descriptors
        (char[]) {0x09, 0x04}, // 0: is supported language is English (0x0409)
        "TinyUSB", // 1: Manufacturer
        "TinyUSB Device", // 2: Product
        "123456", // 3: Serials, should use chip ID
        "Example HID interface", // 4: HID
};

/**
 * @brief Configuration descriptor
 *
 * This is a simple configuration descriptor that defines 1 configuration and 1 HID interface
 */
static const uint8_t hid_configuration_descriptor[] = {
        // Configuration number, interface count, string index, total length, attribute, power in mA
        TUD_CONFIG_DESCRIPTOR(1, 1, 0, TUSB_DESC_TOTAL_LEN, TUSB_DESC_CONFIG_ATT_REMOTE_WAKEUP, 100),

        // Interface number, string index, boot protocol, report descriptor len, EP In address, size & polling interval
        TUD_HID_DESCRIPTOR(0, 4, false, sizeof(hid_report_descriptor), 0x81, 16, 10),
};

/********* TinyUSB HID callbacks ***************/

// Invoked when received GET HID REPORT DESCRIPTOR request
// Application return pointer to descriptor, whose contents must exist long enough for transfer to complete
uint8_t const *tud_hid_descriptor_report_cb(uint8_t instance) {
    // We use only one interface and one HID report descriptor, so we can ignore parameter 'instance'
    return hid_report_descriptor;
}

// Invoked when received GET_REPORT control request
// Application must fill buffer report's content and return its length.
// Return zero will cause the stack to STALL request
uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t report_id, hid_report_type_t report_type, uint8_t * buffer, uint16_t reqlen) {
    (void) instance;
    (void) report_id;
    (void) report_type;
    (void) buffer;
    (void) reqlen;

    return 0;
}

// Invoked when received SET_REPORT control request or
// received data on OUT endpoint ( Report ID = 0, Type = 0 )
void tud_hid_set_report_cb(uint8_t instance, uint8_t report_id, hid_report_type_t report_type, uint8_t const *buffer, uint16_t bufsize) {
}

/********* Application ***************/

#include "tusb_hid.h"

void tusb_hid_init(void) {
    ESP_LOGI(TAG, "USB HID initialization");
    const tinyusb_config_t tusb_cfg = {
            .device_descriptor = NULL,
            .string_descriptor = hid_string_descriptor,
            .string_descriptor_count = sizeof(hid_string_descriptor) / sizeof(hid_string_descriptor[0]),
            .external_phy = false,
#if (TUD_OPT_HIGH_SPEED)
            .fs_configuration_descriptor = hid_configuration_descriptor,
            .hs_configuration_descriptor = hid_configuration_descriptor,
            .qualifier_descriptor = NULL,
#else
            .configuration_descriptor = hid_configuration_descriptor,
#endif // TUD_OPT_HIGH_SPEED
    };

    ESP_ERROR_CHECK(tinyusb_driver_install(&tusb_cfg));
    ESP_LOGI(TAG, "USB HID initialization DONE");
}

static bool tusb_hid_prepare_report(const char *action) {
    if (!tud_mounted()) {
        ESP_LOGW(TAG, "USB HID not mounted, cannot %s", action);
        return false;
    }

    // Send remote wakeup signal if supported and suspended
    if (tud_suspended()) {
        ESP_LOGI(TAG, "Sending remote wakeup signal");
        tud_remote_wakeup();
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    if (!tud_hid_ready()) {
        ESP_LOGW(TAG, "USB HID not ready, cannot %s", action);
        return false;
    }

    return true;
}

void tusb_hid_press_key(uint8_t modifier, uint8_t keycode) {
    if (!tusb_hid_prepare_report("send keyboard key")) {
        return;
    }

    uint8_t keycodes[6] = {keycode};
    ESP_LOGI(TAG, "Sending HID keyboard key modifier=0x%02x keycode=0x%02x", modifier, keycode);
    tud_hid_keyboard_report(HID_ITF_PROTOCOL_KEYBOARD, modifier, keycodes);
    vTaskDelay(pdMS_TO_TICKS(50));
    tud_hid_keyboard_report(HID_ITF_PROTOCOL_KEYBOARD, 0, NULL);
}

void tusb_hid_wakeup(void) {
    tusb_hid_press_key(KEYBOARD_MODIFIER_RIGHTSHIFT, 0);
}
