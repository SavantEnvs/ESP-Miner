// Fuzzes the SV1 line framer (STRATUM_V1_receive_jsonrpc_line) over a fake transport that serves
// the input in small chunks, then parses every complete line it returns.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "stratum_api.h"
#include "esp_shim.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1) return -1;
    size_t chunk = (data[0] % 128) + 1;
    data++; size--;

    shim_transport_feed(data, size, chunk);

    sv1_conn_t conn;
    memset(&conn, 0, sizeof(conn));
    conn.transport = (esp_transport_handle_t)&conn;

    miner_job_pool_t pool = {0};
    miner_job_t *job = miner_job_pool_get_slot(&pool, 0);
    StratumApiV1Message msg;
    memset(&msg, 0, sizeof(msg));

    for (int i = 0; i < 64; i++) {
        char *line = STRATUM_V1_receive_jsonrpc_line(&conn);
        if (!line) break;
        STRATUM_V1_parse(&msg, line, job);
        free(line);
    }

    STRATUM_V1_reset_message(&msg);
    STRATUM_V1_free_conn_buffer(&conn);
    miner_job_pool_free(&pool);
    return 0;
}
