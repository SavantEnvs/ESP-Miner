#ifndef SHIM_ESP_APP_DESC_H
#define SHIM_ESP_APP_DESC_H
typedef struct { char version[32]; char project_name[32]; } esp_app_desc_t;
const esp_app_desc_t *esp_app_get_description(void);
#endif
