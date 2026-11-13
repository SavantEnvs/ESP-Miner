#ifndef SHIM_ESP_HEAP_CAPS_H
#define SHIM_ESP_HEAP_CAPS_H
#include <stdlib.h>
#define MALLOC_CAP_SPIRAM 1
#define MALLOC_CAP_8BIT 2
static inline void *heap_caps_malloc(size_t n, int caps) { (void)caps; return malloc(n); }
static inline void *heap_caps_calloc(size_t c, size_t n, int caps) { (void)caps; return calloc(c, n); }
static inline void *heap_caps_realloc(void *p, size_t n, int caps) { (void)caps; return realloc(p, n); }
static inline void heap_caps_free(void *p) { free(p); }
#endif
