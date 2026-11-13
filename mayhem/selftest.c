// Known-answer tests for the host-buildable parts of ESP-Miner (stratum v1/v2 parsing, payout address
// codecs, coinbase decoding, hashing/target math). Expected values come from the Bitcoin BIPs and
// hashlib/base58 computed independently of this code. Prints one PASS/FAIL line per check and a
// final `SELFTEST_TOTAL <n>` marker (what mayhem/test.sh turns into CTRF counts).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stratum_api.h"
#include "coinbase_decoder.h"
#include "segwit_addr.h"
#include "sv2_protocol.h"
#include "utils.h"

static int g_total, g_failed;

#define CHECK(name, cond) do { g_total++; if (cond) printf("PASS %s\n", name); \
    else { g_failed++; printf("FAIL %s (line %d)\n", name, __LINE__); } } while (0)

static int hex_eq(const uint8_t *b, size_t n, const char *hex)
{
    char buf[256];
    return bin2hex(b, n, buf, sizeof(buf)) == n * 2 && strcmp(buf, hex) == 0;
}

static void test_hashing(void)
{
    uint8_t d[32];
    CHECK("sha256(abc)", sha256_bin((const uint8_t *)"abc", 3, d) &&
          hex_eq(d, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    CHECK("double_sha256(abc)", double_sha256_bin((const uint8_t *)"abc", 3, d) &&
          hex_eq(d, 32, "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358"));
    uint8_t a100[100];
    memset(a100, 'a', sizeof(a100));
    CHECK("sha256(a*100)", sha256_bin(a100, 100, d) &&
          hex_eq(d, 32, "2816597888e4a0d3a36b82b83316ab32680eb8f00f8cd3b904d681246d285a0e"));

    uint8_t bin[4];
    CHECK("hex2bin", hex2bin("deadBEEF", bin, 4) == 4 && hex_eq(bin, 4, "deadbeef"));
    CHECK("hex2bin rejects non-hex", hex2bin("zz", bin, 1) == 0);

    char dec[32];
    url_decode(dec, "a%20b+c%2F");
    CHECK("url_decode", strcmp(dec, "a b c/") == 0);
}

static void test_targets(void)
{
    uint8_t t[32], z[32] = {0};
    nbits_to_target(0x1d00ffff, t);
    CHECK("nbits 1d00ffff -> difficulty-1 target", t[26] == 0xff && t[27] == 0xff &&
          t[28] == 0 && t[25] == 0 && memcmp(t, z, 26) == 0 && memcmp(t + 28, z, 4) == 0);
    CHECK("target_to_diff(diff1) == 1", target_to_diff(t) == 1.0);
    diff_to_target(1.0, t);
    CHECK("diff_to_target(1) bytes", t[26] == 0xff && t[27] == 0xff && t[25] == 0 && t[28] == 0);
    diff_to_target(256.0, t);
    CHECK("diff_to_target(256) bytes", t[25] == 0xff && t[26] == 0xff && t[24] == 0 && t[27] == 0);
    CHECK("target_to_diff(zero) saturates", target_to_diff(z) == (double)UINT32_MAX);
    nbits_to_target(0x1b0404cb, t);
    CHECK("nbits 1b0404cb", t[24] == 0xcb && t[25] == 0x04 && t[26] == 0x04 && t[27] == 0x00);
}

static void test_addresses(void)
{
    struct { const char *addr; const char *script; } v[] = {
        { "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "76a91477bff20c60e522dfaa3350c39b030a5d004e839a88ac" },
        { "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", "a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb87" },
        { "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "0014751e76e8199196d454941c45d1b3a323f1433bd6" },
        { "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
          "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" },
        { "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
          "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262" },
    };
    for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
        uint8_t s[MAX_SCRIPTPUBKEY_LEN * 2];
        size_t n = coinbase_address_to_scriptpubkey(v[i].addr, s, sizeof(s));
        char name[96];
        snprintf(name, sizeof(name), "address->script %s", v[i].addr);
        CHECK(name, n == strlen(v[i].script) / 2 && hex_eq(s, n, v[i].script));

        uint8_t raw[64];
        size_t rl = hex2bin(v[i].script, raw, sizeof(raw));
        char out[MAX_ADDRESS_STRING_LEN];
        coinbase_decode_address_from_scriptpubkey(raw, rl, out, sizeof(out), "bc", false);
        snprintf(name, sizeof(name), "script->address %s", v[i].addr);
        CHECK(name, strcmp(out, v[i].addr) == 0);
    }

    uint8_t s[80];
    CHECK("bad base58 checksum rejected",
          coinbase_address_to_scriptpubkey("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3", s, sizeof(s)) == 0);
    CHECK("bad bech32 checksum rejected",
          coinbase_address_to_scriptpubkey("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", s, sizeof(s)) == 0);
    CHECK("garbage rejected", coinbase_address_to_scriptpubkey("not an address", s, sizeof(s)) == 0);

    int ver = -1;
    uint8_t prog[40];
    size_t pl = 0;
    CHECK("segwit_addr_decode bc v0", segwit_addr_decode(&ver, prog, &pl, "bc",
          "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4") && ver == 0 && pl == 20 &&
          hex_eq(prog, 20, "751e76e8199196d454941c45d1b3a323f1433bd6"));
    CHECK("segwit_addr_decode wrong hrp rejected", !segwit_addr_decode(&ver, prog, &pl, "tb",
          "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));

    uint8_t sc[4][MAX_SCRIPTPUBKEY_LEN];
    size_t sl[4];
    int n = coinbase_parse_user_scriptpubkeys("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2.worker1", sc, sl, 4);
    CHECK("user string with worker suffix", n == 1 && sl[0] == 25 && sc[0][0] == 0x76 && sc[0][3] == 0x77);

    int off = 0;
    const uint8_t v3[] = { 0xfd, 0x34, 0x12 };
    CHECK("varint fd", coinbase_decode_varint(v3, 3, &off) == 0x1234 && off == 3);
}

static const char *NOTIFY =
    "{\"id\":null,\"method\":\"mining.notify\",\"params\":"
    "[\"1b4c3d9041\","
    "\"ef4b9a48c7986466de4adc002f7337a6e121bc43000376ea0000000000000000\","
    "\"01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4b03a5020cfabe6d6d379ae882651f6469f2ed6b8b40a4f9a4b41fd838a3ad6de8cba775f4e8f1d3080100000000000000\","
    "\"41903d4c1b2f736c7573682f0000000003ca890d27000000001976a9147c154ed1dc59609e3d26abb2df2ea3d587cd8c4188ac00000000000000002c6a4c2952534b424c4f434b3a4cb4cb2ddfc37c41baf5ef6b6b4899e3253a8f1dfc7e5dd68a5b5b27005014ef0000000000000000266a24aa21a9ed5caa249f1af9fbf71c986fea8e076ca34ae3514fb2f86400561b28c7b15949bf00000000\","
    "[\"ae23055e00f0f697cc3640124812d96d4fe8bdfa03484c1c638ce5a1c0e9aa81\",\"980fb87cb61021dd7afd314fcb0dabd096f3d56a7377f6f320684652e7410a21\"],"
    "\"20000004\",\"1705c739\",\"64495522\",true]}";

static void test_stratum_v1(void)
{
    miner_job_pool_t pool = {0};
    miner_job_t *job = miner_job_pool_get_slot(&pool, 0);
    StratumApiV1Message m;
    memset(&m, 0, sizeof(m));

    CHECK("notify parses", STRATUM_V1_parse(&m, NOTIFY, job) && m.method == MINING_NOTIFY);
    CHECK("notify job_id", strcmp(job->job_id, "1b4c3d9041") == 0);
    CHECK("notify version/nbits/ntime", job->version == 0x20000004 && job->nbits == 0x1705c739 &&
          job->ntime == 0x64495522);
    CHECK("notify clean_jobs", job->clean_jobs);
    CHECK("notify merkle branches", job->merkle_path_count == 2 &&
          job->merkle_path[0][0] == 0xae && job->merkle_path[1][0] == 0x98);
    CHECK("notify coinbase prefix length", job->coinbase_prefix_len == 90 && job->coinbase_suffix_len > 12);

    mining_notification_result_t r;
    memset(&r, 0, sizeof(r));
    job->extranonce1_len = 7;
    job->extranonce2_len = 8;
    CHECK("coinbase decode ok", coinbase_process_miner_job(job, "1CK6KHY6MHgYvmRQ4PAafKYDrg1ejbH1cE", true, &r) == 0);
    CHECK("coinbase block height", r.block_height == 787109);
    CHECK("coinbase first output", r.output_count >= 1 && r.outputs[0].value_satoshis == 655198666ULL &&
          strcmp(r.outputs[0].address, "1CK6KHY6MHgYvmRQ4PAafKYDrg1ejbH1cE") == 0);
    CHECK("coinbase user payout verified", r.payout_status == COINBASE_PAYOUT_VERIFIED &&
          r.outputs[0].is_user_output && r.user_value_satoshis == 655198666ULL);
    miner_job_pool_free(&pool);

    CHECK("set_difficulty", STRATUM_V1_parse(&m, "{\"id\":null,\"method\":\"mining.set_difficulty\",\"params\":[100.5]}", NULL) &&
          m.method == MINING_SET_DIFFICULTY && m.new_difficulty == 100.5);
    CHECK("set_version_mask", STRATUM_V1_parse(&m, "{\"id\":1,\"method\":\"mining.set_version_mask\",\"params\":[\"1fffe000\"]}", NULL) &&
          m.method == MINING_SET_VERSION_MASK && m.version_mask == 0x1fffe000 && m.message_id == 1);
    CHECK("subscribe result", STRATUM_V1_parse(&m, "{\"result\":[[[\"mining.notify\",\"695482c0\"]],\"4de05269\",8],\"id\":2,\"error\":null}", NULL) &&
          m.extranonce_str && strcmp(m.extranonce_str, "4de05269") == 0 && m.extranonce_2_len == 8);
    CHECK("subscribe result malformed rejected", !STRATUM_V1_parse(&m, "{\"result\":[[[\"mining.notify\",\"abc\"]],\"4de05269\"],\"id\":2,\"error\":null}", NULL));
    CHECK("result success", STRATUM_V1_parse(&m, "{\"id\":4,\"error\":null,\"result\":true}", NULL) &&
          m.method == STRATUM_RESULT && m.response_success && m.message_id == 4);
    CHECK("result error text", STRATUM_V1_parse(&m, "{\"id\":4,\"result\":null,\"error\":[21,\"Job not found\",\"\"]}", NULL) &&
          !m.response_success && m.error_str && strcmp(m.error_str, "Job not found") == 0);
    CHECK("invalid json rejected", !STRATUM_V1_parse(&m, "{\"id\":", NULL));
    CHECK("negative id rejected", !STRATUM_V1_parse(&m, "{\"id\":-5,\"result\":true}", NULL));
    STRATUM_V1_reset_message(&m);
}

static void le32(uint8_t *p, uint32_t v) { p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24; }

static void test_sv2(void)
{
    uint8_t hdr[6];
    CHECK("sv2 encode header", sv2_encode_frame_header(hdr, 0x8000, SV2_MSG_SET_TARGET, 0x000123) == 6 &&
          hex_eq(hdr, 6, "008021230100"));
    sv2_frame_header_t h;
    CHECK("sv2 parse header", sv2_parse_frame_header(hdr, &h) == 0 && h.extension_type == 0x8000 &&
          h.msg_type == SV2_MSG_SET_TARGET && h.msg_length == 0x123);

    uint8_t pl[36], target[32];
    le32(pl, 77);
    for (int i = 0; i < 32; i++) pl[4 + i] = (uint8_t)i;
    uint32_t chan = 0;
    CHECK("sv2 set_target", sv2_parse_set_target(pl, 36, &chan, target) == 0 && chan == 77 &&
          target[0] == 0 && target[31] == 31);
    CHECK("sv2 set_target short rejected", sv2_parse_set_target(pl, 35, &chan, target) == -1);

    uint8_t buf[512];
    int n = sv2_build_submit_shares(buf, sizeof(buf), 5, 6, 7, 0x11223344, 0x55667788, 0x20000000, NULL, 0);
    CHECK("sv2 submit_shares frame", n >= 30 && sv2_parse_frame_header(buf, &h) == 0 &&
          h.msg_type == SV2_MSG_SUBMIT_SHARES_STANDARD && h.msg_length == (uint32_t)(n - 6) &&
          buf[6] == 5 && buf[10] == 6 && buf[14] == 7);

    uint8_t ok[8] = {2, 0, 0, 0, 0, 0, 0, 0};
    uint16_t used; uint32_t flags;
    CHECK("sv2 setup_connection_success", sv2_parse_setup_connection_success(ok, 6, &used, &flags) == 0 && used == 2);
    CHECK("sv2 setup_connection_success short", sv2_parse_setup_connection_success(ok, 2, &used, &flags) == -1);
}

int main(void)
{
    test_hashing();
    test_targets();
    test_addresses();
    test_stratum_v1();
    test_sv2();
    printf("SELFTEST_TOTAL %d\nSELFTEST_FAILED %d\n", g_total, g_failed);
    return g_failed ? 1 : 0;
}
