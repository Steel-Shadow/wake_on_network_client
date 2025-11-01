# Wake on Network Client

Wake on Network Client is an ESP-IDF application that connects an ESP32-series device to a WPA/WPA2/WPA3 Enterprise (EAP) Wi‑Fi network and maintains a TLS WebSocket connection to a remote server. When the server sends a "trigger" message, the board toggles a GPIO pin (used here to pulse a PC power pin) to wake a machine on the local network.

This project is built from the Espressif `WiFi enterprise` and `Websocket` examples and is intended as a starting point for a secure Wake-on-LAN-like workflow using a remote control server.

## Features

- Connect to WPA/WPA2/WPA3 Enterprise networks using EAP (PEAP, TTLS, TLS, etc.)
- Optionally validate server certificate and domain name
- WebSocket client over TLS (wss://) with optional client certs
- On receiving a `trigger` message from the server the application pulses a configurable GPIO pin
- Example demonstrates embedding certificates into the firmware image

## Hardware

- ESP32 series (example was developed for ESP32-S3 but should work on other ESP32 variants with minor changes)
- A target device (PC) connected to the same local network. The example pulses GPIO4 to simulate a power-button press. Change `Pin::pin` in `main.cpp` if you use a different GPIO.

WARNING: Take care wiring the pin to a PC power header. Use an appropriate transistor/optocoupler or relay — do not connect MCU pins directly to AC mains or to pins that may exceed voltage/current limits.

## Repository layout

- `main/` — application source (contains `main.cpp`, `ca.pem` etc.)
- `CMakeLists.txt` / build files — ESP-IDF project meta
- `generate_certs/` — helper script (if present) for generating certs

## Configuration

This project uses SDK config options (Kconfig) for EAP and WebSocket options. You can set these with `idf.py menuconfig` (recommended) or by editing your `sdkconfig`.

Important options (these map to Kconfig entries used in `main.cpp`):

- `CONFIG_WON_WIFI_SSID` — SSID of the enterprise AP
- `CONFIG_WON_EAP_METHOD` — EAP method (PEAP / TTLS / TLS, etc.)
- `CONFIG_WON_EAP_ID` — EAP identity
- `CONFIG_WON_EAP_USERNAME` — username for PEAP/TTLS
- `CONFIG_WON_EAP_PASSWORD` — password for PEAP/TTLS
- `CONFIG_WON_SERVER_CERT_DOMAIN` — domain name to validate the server certificate (optional)
- `CONFIG_WON_VALIDATE_SERVER_CERT` — enable CA validation (if set, embed `ca.pem`)
- `CONFIG_WON_EAP_METHOD_TLS` — enable client cert auth (if set, embed client cert & key)

## Embedding certificates and keys for Websocket client

The example can embed `ca.pem`, client certificate and client key directly into the firmware image. Place your PEM files in the component source folder (e.g. `main/`) and register them as embedded text files.

Using CMake (recommended, modern ESP-IDF):

In `main/CMakeLists.txt` add the EMBED_TXTFILES directive to `idf_component_register`:

```cmake
idf_component_register(SRCS "main.cpp"
        INCLUDE_DIRS ""
        EMBED_TXTFILES "ca.pem" "client.crt" "client.key")
```

The code expects the embedded symbols named like `_binary_ca_pem_start` / `_binary_ca_pem_end` (these are generated automatically when files are embedded).

Detailed instructions to enable client verification can be found in examples of `espressif/esp_websocket_client`.

## WebSocket server URI

By default `main.cpp` uses the example URI:

```text
wss://wol.steel-shadow.me/ws/Steel-Shadow_secret
```

Change this to your server's WebSocket URI inside `main.cpp` (variable `uri` in `Websocket_app::init_config`) or make it configurable via menuconfig.

The client sends a small greeting on connect (`"hello ESP32"`). The server is expected to send a `"welcome"` message first; afterwards, sending a message beginning with `trigger` will cause the pin pulse used to wake the PC.

## Runtime behavior

- On startup the app initializes NVS, the GPIO pin, EAP client and Wi‑Fi station
- When an IP is acquired the app starts a WebSocket reconnecting loop
- On receiving the first (welcome) message the websocket code will verify it; subsequent messages beginning with `trigger` will call `Pin::open_pc_power()` which pulses the configured GPIO
