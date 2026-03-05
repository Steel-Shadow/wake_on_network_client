/*
 * SPDX-FileCopyrightText: 2022-2024 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */

#pragma once

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
 * Sends a small mouse movement to wake the PC from sleep state.
 * If the device is suspended, it will first send a remote wakeup signal.
 */
void tusb_hid_wakeup(void);

#ifdef __cplusplus
}
#endif
