#ifndef SHIM_PSA_CRYPTO_H
#define SHIM_PSA_CRYPTO_H
#include <stddef.h>
#include <stdint.h>
typedef int32_t psa_status_t;
typedef uint32_t psa_algorithm_t;
#define PSA_SUCCESS ((psa_status_t)0)
#define PSA_ERROR_GENERIC_ERROR ((psa_status_t)-132)
#define PSA_ALG_SHA_256 ((psa_algorithm_t)0x02000009)
typedef struct { uint8_t *buf; size_t len, cap; psa_algorithm_t alg; } psa_hash_operation_t;
#define PSA_HASH_OPERATION_INIT { 0, 0, 0, 0 }
psa_status_t psa_hash_setup(psa_hash_operation_t *op, psa_algorithm_t alg);
psa_status_t psa_hash_update(psa_hash_operation_t *op, const uint8_t *input, size_t len);
psa_status_t psa_hash_finish(psa_hash_operation_t *op, uint8_t *hash, size_t hash_size, size_t *hash_length);
psa_status_t psa_hash_abort(psa_hash_operation_t *op);
psa_status_t psa_hash_compute(psa_algorithm_t alg, const uint8_t *input, size_t input_length,
                              uint8_t *hash, size_t hash_size, size_t *hash_length);
#endif
