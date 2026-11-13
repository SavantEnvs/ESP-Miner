// Fuzzes the payout-address decoders: bech32/segwit, base58check, and the user-string -> scriptPubKey logic.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "coinbase_decoder.h"
#include "segwit_addr.h"
#include "libbase58.h"
#include "utils.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *s = malloc(size + 1);
    memcpy(s, data, size);
    s[size] = '\0';

    uint8_t script[MAX_SCRIPTPUBKEY_LEN * 2];
    coinbase_address_to_scriptpubkey(s, script, sizeof(script));

    uint8_t scripts[MAX_USER_ADDRESSES][MAX_SCRIPTPUBKEY_LEN];
    size_t lens[MAX_USER_ADDRESSES];
    coinbase_parse_user_scriptpubkeys(s, scripts, lens, MAX_USER_ADDRESSES);

    char hrp[84];
    uint8_t d[128];
    size_t dl = 0;
    bech32_decode(hrp, d, &dl, s);

    int ver;
    uint8_t prog[40];
    size_t pl;
    segwit_addr_decode(&ver, prog, &pl, "bc", s);
    segwit_addr_decode(&ver, prog, &pl, "tb", s);

    uint8_t bin[25];
    size_t bs = sizeof(bin);
    if (b58_sha256_impl && b58tobin(bin, &bs, s, size) && bs == sizeof(bin)) b58check(bin, bs, s, size);

    uint8_t out[40];
    hex2bin(s, out, sizeof(out));
    char *dec = malloc(size + 1);
    url_decode(dec, s);
    free(dec);

    free(s);
    return 0;
}
