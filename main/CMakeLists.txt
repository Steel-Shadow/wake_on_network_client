# Embed CA, certificate & key directly into binary
idf_component_register(SRCS "main.cpp"
                    INCLUDE_DIRS "."
                    PRIV_REQUIRES esp_wifi wpa_supplicant nvs_flash driver espressif__esp_websocket_client
                    EMBED_TXTFILES ca.pem)
                    