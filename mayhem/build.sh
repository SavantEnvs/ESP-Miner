#!/usr/bin/env bash
#
# Builds ESP-Miner's host-portable firmware sources (stratum v1/v2 parsing, payout address codecs,
# coinbase decoding, hashing/target math) against mayhem/shim (stand-ins for the ESP-IDF headers),
# then the fuzz harnesses, their -standalone reproducers, and the normal-flags selftest.
# yyjson (a git submodule upstream) comes from the pinned copy in /opt/toolchains/deps.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${YYJSON_DIR:=/opt/toolchains/deps/yyjson-8b4a38d/src}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
OUT=/mayhem
B="$SRC/build-mayhem"
rm -rf "$B"
mkdir -p "$B/fuzz" "$B/plain"

INC=(-I"$SRC/mayhem/shim"
     -I"$SRC/components/stratum/include" -I"$SRC/components/stratum_v2/include"
     -I"$SRC/components/mining_job/include" -I"$SRC/components/yyjson/include"
     -I"$YYJSON_DIR/src")

STRATUM_SRCS=(utils hash_bytes mining mining_job stratum_api coinbase_decoder segwit_addr base58 miner_job)
SOURCES=()
for s in "${STRATUM_SRCS[@]}"; do SOURCES+=("$SRC/components/stratum/$s.c"); done
SOURCES+=("$SRC/components/stratum_v2/sv2_protocol.c"
          "$SRC/components/yyjson/yyjson_utils.c"
          "$YYJSON_DIR/src/yyjson.c"
          "$SRC/mayhem/shim/esp_shim.c")

compile_all() { # <outdir> <flags...>
  local dir="$1"; shift
  local pids=() s
  for s in "${SOURCES[@]}"; do
    "$CC" "$@" -std=gnu11 -w "${INC[@]}" -c "$s" -o "$dir/$(basename "${s%.c}").o" &
    pids+=($!)
    while [ "$(jobs -rp | wc -l)" -ge "$MAYHEM_JOBS" ]; do wait -n || true; done
  done
  local p; for p in "${pids[@]}"; do wait "$p"; done
}

# 1) sanitized project build: one copy with SanCov for the libFuzzer binaries, one without for the standalone reproducers
mkdir -p "$B/standalone"
compile_all "$B/fuzz" -O1 $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link
compile_all "$B/standalone" -O1 $SANITIZER_FLAGS $DEBUG_FLAGS
rm -f "$B/libminer-fuzz.a" "$B/libminer-standalone.a"
ar rcs "$B/libminer-fuzz.a" "$B"/fuzz/*.o
ar rcs "$B/libminer-standalone.a" "$B"/standalone/*.o
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$B/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone_main.o"

# 2) harnesses: fuzzer + standalone reproducer
for h in fuzz_stratum_v1_parse fuzz_stratum_v1_stream fuzz_sv2_messages fuzz_coinbase_address fuzz_coinbase_tx; do
  f="$SRC/mayhem/harnesses/$h.c"
  $CC -O1 -std=gnu11 -w $SANITIZER_FLAGS $DEBUG_FLAGS "${INC[@]}" $LIB_FUZZING_ENGINE "$f" \
      "$B/lsan_off.o" "$B/libminer-fuzz.a" -lm -o "$OUT/$h"
  $CC -O1 -std=gnu11 -w $SANITIZER_FLAGS $DEBUG_FLAGS "${INC[@]}" "$B/standalone_main.o" "$f" \
      "$B/lsan_off.o" "$B/libminer-standalone.a" -lm -o "$OUT/$h-standalone"
done

# 3) selftest with normal flags
compile_all "$B/plain" -O2 $COVERAGE_FLAGS
rm -f "$B/libminer-plain.a"; ar rcs "$B/libminer-plain.a" "$B"/plain/*.o
$CC -O2 -std=gnu11 -w $COVERAGE_FLAGS "${INC[@]}" "$SRC/mayhem/selftest.c" "$B/libminer-plain.a" -lm \
    -o "$OUT/esp_miner_selftest"
