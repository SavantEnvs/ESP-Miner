// Fuzzes STRATUM_V1_parse: one pool JSON-RPC line (mining.notify, set_difficulty, results, ...).
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "stratum_api.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > STRATUM_V1_MAX_JSON_LINE_SIZE) return -1; // the API's own documented line limit

    char *line = malloc(size + 1);
    memcpy(line, data, size);
    line[size] = '\0';

    miner_job_pool_t pool = {0};
    miner_job_t *job = miner_job_pool_get_slot(&pool, 0);
    StratumApiV1Message msg;
    memset(&msg, 0, sizeof(msg));
    msg.message_id = -1;

    STRATUM_V1_parse(&msg, line, job);

    STRATUM_V1_reset_message(&msg);
    miner_job_pool_free(&pool);
    free(line);
    return 0;
}
