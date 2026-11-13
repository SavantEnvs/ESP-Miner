#ifndef SHIM_ESP_PSRAM_H
#define SHIM_ESP_PSRAM_H
#include <stdbool.h>
static inline bool esp_psram_is_initialized(void) { return false; }
#endif
