# Embed CA, certificate & key directly into binary
idf_component_register(SRCS "main.cpp"
                    INCLUDE_DIRS "."
                    REQUIRES esp_wifi wpa_supplicant nvs_flash)
