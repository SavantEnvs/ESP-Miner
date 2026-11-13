// Fuzzes coinbase_process_miner_job (coinbase transaction decoder) with a fuzzer-built miner_job_t.
// Layout: version[4] en1_len en2_len flags user_len prefix_len[2] | user | prefix | suffix
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "coinbase_decoder.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 10) return -1;
    miner_job_t job;
    memset(&job, 0, sizeof(job));
    memcpy(&job.version, data, 4);
    job.extranonce1_len = data[4] % (sizeof(job.extranonce1) + 1);
    job.extranonce2_len = data[5] % (MAX_EXTRANONCE_2_LEN + 1);
    uint8_t flags = data[6];
    size_t user_len = data[7];
    size_t prefix_len = ((size_t)data[8] | ((size_t)data[9] << 8)) % (MAX_COINBASE_PREFIX_LEN + 1);
    const uint8_t *p = data + 10;
    size_t left = size - 10;

    if (user_len > left) user_len = left;
    char *user = malloc(user_len + 1);
    memcpy(user, p, user_len);
    user[user_len] = '\0';
    p += user_len; left -= user_len;

    if (prefix_len > left) prefix_len = left;
    size_t suffix_len = left - prefix_len;
    if (suffix_len > MAX_COINBASE_SUFFIX_LEN) suffix_len = MAX_COINBASE_SUFFIX_LEN;

    job.coinbase_prefix = malloc(MAX_COINBASE_PREFIX_LEN);
    job.coinbase_suffix = malloc(MAX_COINBASE_SUFFIX_LEN);
    memcpy(job.coinbase_prefix, p, prefix_len);
    memcpy(job.coinbase_suffix, p + prefix_len, suffix_len);
    job.coinbase_prefix_len = (uint16_t)prefix_len;
    job.coinbase_suffix_len = (uint16_t)suffix_len;
    memset(job.extranonce1, 0xab, sizeof(job.extranonce1));

    mining_notification_result_t res;
    memset(&res, 0, sizeof(res));
    coinbase_process_miner_job(&job, (flags & 1) ? user : NULL, (flags & 2) != 0, &res);

    char addr[MAX_ADDRESS_STRING_LEN];
    coinbase_decode_address_from_scriptpubkey(job.coinbase_suffix, suffix_len, addr, sizeof(addr),
                                              (flags & 4) ? "tb" : "bc", (flags & 8) != 0);
    int off = 0;
    coinbase_decode_varint(job.coinbase_suffix, suffix_len, &off);

    free(job.coinbase_prefix);
    free(job.coinbase_suffix);
    free(user);
    return 0;
}
