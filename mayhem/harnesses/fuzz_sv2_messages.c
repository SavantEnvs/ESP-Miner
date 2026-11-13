// Fuzzes the Stratum V2 frame header and message-payload parsers: byte 0 selects the parser.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "sv2_protocol.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1) return -1;
    uint8_t sel = data[0] % 12;
    const uint8_t *p = data + 1;
    uint32_t len = (uint32_t)(size - 1);

    uint32_t u1, u2, u3, u4, u5;
    uint16_t s1, s2;
    bool b1, b2;
    uint8_t t32[32], t32b[32], ex[64], exlen = 0;
    char err[32];

    switch (sel) {
    case 0: {
        sv2_frame_header_t h;
        if (len >= SV2_FRAME_HEADER_SIZE && sv2_parse_frame_header(p, &h) == 0) {
            uint8_t out[SV2_FRAME_HEADER_SIZE];
            sv2_encode_frame_header(out, h.extension_type, h.msg_type, h.msg_length);
            if (memcmp(out, p, SV2_FRAME_HEADER_SIZE) != 0) __builtin_trap(); // header must round-trip
        }
        break;
    }
    case 1: sv2_parse_setup_connection_success(p, len, &s1, &u1); break;
    case 2: sv2_parse_open_channel_success(p, len, &u1, &u2, t32, ex, &exlen, &u3); break;
    case 3: sv2_parse_new_mining_job(p, len, &u1, &u2, &b1, &u3, &u4, t32); break;
    case 4: sv2_parse_set_new_prev_hash(p, len, &u1, &u2, t32, &u3, &u4); break;
    case 5: sv2_parse_set_extranonce_prefix(p, len, &u1, ex, &exlen); break;
    case 6: sv2_parse_set_target(p, len, &u1, t32); break;
    case 7: sv2_parse_submit_shares_success(p, len, &u1, &u2, &u3); break;
    case 8: sv2_parse_submit_shares_error(p, len, &u1, &u2, err, sizeof(err)); break;
    case 9: sv2_parse_open_extended_channel_success(p, len, &u1, &u2, t32b, &s2, ex, &exlen, &u5); break;
    case 10: {
        miner_job_t job;
        memset(&job, 0, sizeof(job));
        job.coinbase_prefix = calloc(1, MAX_COINBASE_PREFIX_LEN);
        job.coinbase_suffix = calloc(1, MAX_COINBASE_SUFFIX_LEN);
        sv2_parse_new_extended_mining_job(p, len, &u1, &job, &b1, &b2);
        free(job.coinbase_prefix);
        free(job.coinbase_suffix);
        break;
    }
    case 11: {
        // builders: the input supplies the strings; each must fit its frame or return -1
        char host[64], vendor[64], hw[64], fw[64], dev[64], user[128];
        size_t n = len > 63 ? 63 : len;
        memcpy(host, p, n); host[n] = 0;
        memcpy(vendor, p, n); vendor[n] = 0;
        memcpy(hw, p, n); hw[n] = 0;
        memcpy(fw, p, n); fw[n] = 0;
        memcpy(dev, p, n); dev[n] = 0;
        size_t m = len > 127 ? 127 : len;
        memcpy(user, p, m); user[m] = 0;
        uint8_t buf[512];
        sv2_build_setup_connection(buf, sizeof(buf), host, 3333, vendor, hw, fw, dev, len);
        sv2_build_open_standard_mining_channel(buf, sizeof(buf), len, user, 1e12f);
        sv2_build_open_extended_mining_channel(buf, sizeof(buf), len, user, 1e12f, (uint16_t)len);
        uint8_t xl = len > 40 ? 40 : (uint8_t)len;
        sv2_build_submit_shares(buf, sizeof(buf), 1, 2, 3, 4, 5, 6, p, xl);
        break;
    }
    }
    return 0;
}
