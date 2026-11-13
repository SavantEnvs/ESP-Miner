/* Host stand-ins for the ESP-IDF services the stratum/SV2 sources call. */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "esp_transport.h"
#include "esp_transport_tcp.h"
#include "esp_transport_ssl.h"
#include "esp_crt_bundle.h"
#include "esp_app_desc.h"
#include "esp_timer.h"
#include "psa/crypto.h"
#include "esp_shim.h"

/* ---- fake transport: esp_transport_read() serves bytes from a buffer the harness installs ---- */
static const uint8_t *s_rx;
static size_t s_rx_len, s_rx_pos, s_rx_chunk = 64;

void shim_transport_feed(const uint8_t *data, size_t len, size_t chunk)
{
    s_rx = data; s_rx_len = len; s_rx_pos = 0; s_rx_chunk = chunk ? chunk : 1;
}

int esp_transport_read(esp_transport_handle_t t, char *buffer, int len, int timeout_ms)
{
    (void)t; (void)timeout_ms;
    if (s_rx_pos >= s_rx_len) return ERR_TCP_TRANSPORT_CONNECTION_CLOSED_BY_FIN;
    size_t n = s_rx_len - s_rx_pos;
    if (n > s_rx_chunk) n = s_rx_chunk;
    if (n > (size_t)len) n = (size_t)len;
    memcpy(buffer, s_rx + s_rx_pos, n);
    s_rx_pos += n;
    return (int)n;
}

int esp_transport_write(esp_transport_handle_t t, const char *buffer, int len, int timeout_ms)
{
    (void)t; (void)buffer; (void)timeout_ms;
    return len;
}
int esp_transport_destroy(esp_transport_handle_t t) { (void)t; return 0; }
esp_transport_handle_t esp_transport_tcp_init(void) { return NULL; }
esp_transport_handle_t esp_transport_ssl_init(void) { return NULL; }
void esp_transport_ssl_crt_bundle_attach(esp_transport_handle_t t, void *fn) { (void)t; (void)fn; }
void esp_transport_ssl_set_cert_data(esp_transport_handle_t t, const char *d, int l) { (void)t; (void)d; (void)l; }
int esp_crt_bundle_attach(void *conf) { (void)conf; return 0; }

const esp_app_desc_t *esp_app_get_description(void)
{
    static const esp_app_desc_t d = { "host", "esp-miner" };
    return &d;
}
int64_t esp_timer_get_time(void) { return 0; }

/* stratum_socket.c is network-only; the parser never reaches it */
int stratum_socket_send_all(esp_transport_handle_t t, const void *d, int n)
{
    (void)t; (void)d; return n;
}

/* ---- SHA-256 (FIPS 180-4) behind the PSA call utils.c makes ---- */
static const uint32_t K[64] = {
 0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
 0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
 0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
 0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
 0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
 0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
 0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
 0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };
#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(uint32_t h[8], const uint8_t *p)
{
    uint32_t w[64], a, b, c, d, e, f, g, hh;
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)p[4*i] << 24 | (uint32_t)p[4*i+1] << 16 | (uint32_t)p[4*i+2] << 8 | p[4*i+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i-15], 7) ^ ROR(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROR(w[i-2], 17) ^ ROR(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4]; f = h[5]; g = h[6]; hh = h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = hh + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
        uint32_t t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

psa_status_t psa_hash_compute(psa_algorithm_t alg, const uint8_t *in, size_t len,
                              uint8_t *hash, size_t hash_size, size_t *hash_length)
{
    if (alg != PSA_ALG_SHA_256 || hash_size < 32) return PSA_ERROR_GENERIC_ERROR;
    uint32_t h[8] = { 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 };
    size_t i = 0;
    for (; i + 64 <= len; i += 64) sha256_block(h, in + i);
    uint8_t tail[128] = {0};
    size_t rem = len - i;
    if (rem) memcpy(tail, in + i, rem);
    tail[rem] = 0x80;
    size_t tl = rem + 9 <= 64 ? 64 : 128;
    uint64_t bits = (uint64_t)len * 8;
    for (int k = 0; k < 8; k++) tail[tl - 1 - k] = (uint8_t)(bits >> (8 * k));
    sha256_block(h, tail);
    if (tl == 128) sha256_block(h, tail + 64);
    for (int k = 0; k < 8; k++) {
        hash[4*k] = h[k] >> 24; hash[4*k+1] = h[k] >> 16; hash[4*k+2] = h[k] >> 8; hash[4*k+3] = h[k];
    }
    *hash_length = 32;
    return PSA_SUCCESS;
}

psa_status_t psa_hash_setup(psa_hash_operation_t *op, psa_algorithm_t alg)
{
    op->buf = NULL; op->len = op->cap = 0; op->alg = alg;
    return alg == PSA_ALG_SHA_256 ? PSA_SUCCESS : PSA_ERROR_GENERIC_ERROR;
}

psa_status_t psa_hash_update(psa_hash_operation_t *op, const uint8_t *in, size_t len)
{
    if (op->len + len > op->cap) {
        size_t nc = (op->len + len) * 2 + 64;
        uint8_t *nb = realloc(op->buf, nc);
        if (!nb) return PSA_ERROR_GENERIC_ERROR;
        op->buf = nb; op->cap = nc;
    }
    if (len) memcpy(op->buf + op->len, in, len);
    op->len += len;
    return PSA_SUCCESS;
}

psa_status_t psa_hash_finish(psa_hash_operation_t *op, uint8_t *hash, size_t hash_size, size_t *hash_length)
{
    psa_status_t st = psa_hash_compute(op->alg, op->buf ? op->buf : (const uint8_t *)"", op->len, hash, hash_size, hash_length);
    free(op->buf); op->buf = NULL; op->len = op->cap = 0;
    return st;
}

psa_status_t psa_hash_abort(psa_hash_operation_t *op)
{
    free(op->buf); op->buf = NULL; op->len = op->cap = 0;
    return PSA_SUCCESS;
}
