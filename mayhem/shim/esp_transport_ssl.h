#include "esp_transport.h"
esp_transport_handle_t esp_transport_ssl_init(void);
void esp_transport_ssl_crt_bundle_attach(esp_transport_handle_t t, void *fn);
void esp_transport_ssl_set_cert_data(esp_transport_handle_t t, const char *data, int len);
