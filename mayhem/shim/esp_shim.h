#ifndef SHIM_ESP_SHIM_H
#define SHIM_ESP_SHIM_H
#include <stddef.h>
#include <stdint.h>
void shim_transport_feed(const uint8_t *data, size_t len, size_t chunk);
#endif
