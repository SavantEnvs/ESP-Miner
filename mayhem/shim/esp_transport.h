#ifndef SHIM_ESP_TRANSPORT_H
#define SHIM_ESP_TRANSPORT_H
#include <stddef.h>
#include <stdint.h>
typedef struct esp_transport_item_t *esp_transport_handle_t;
enum {
    ERR_TCP_TRANSPORT_CONNECTION_TIMEOUT = -1,
    ERR_TCP_TRANSPORT_CANNOT_RESOLVE_HOSTNAME = -2,
    ERR_TCP_TRANSPORT_CONNECTION_FAILED = -3,
    ERR_TCP_TRANSPORT_CONNECTION_CLOSED_BY_FIN = -4,
    ERR_TCP_TRANSPORT_NO_MEM = -5,
};
int esp_transport_read(esp_transport_handle_t t, char *buffer, int len, int timeout_ms);
int esp_transport_write(esp_transport_handle_t t, const char *buffer, int len, int timeout_ms);
int esp_transport_destroy(esp_transport_handle_t t);
#endif
