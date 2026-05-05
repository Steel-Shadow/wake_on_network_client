/*
 * SPDX-FileCopyrightText: 2022-2024 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize USB HID device
 */
void tusb_hid_init(void);

/**
 * @brief Send HID wakeup signal to wake PC from sleep
 *
 * Sends a keyboard event to wake the PC from sleep state.
 * If the device is suspended, it will first send a remote wakeup signal.
 */
void tusb_hid_wakeup(void);

/**
 * @brief Send a keyboard key press and release
 *
 * @param modifier TinyUSB KEYBOARD_MODIFIER_* bit mask, or 0
 * @param keycode TinyUSB HID_KEY_* key code, or 0 for modifier-only keys
 */
void tusb_hid_press_key(uint8_t modifier, uint8_t keycode);

#ifdef __cplusplus
}
#endif
