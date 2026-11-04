#!/usr/bin/env bash
# Runs the signer core's own test suites (unit, ssz_static, bls/sign,
# EIP-3076) against the core library built here (scripts/build-core.sh,
# with this repo's compiler flags). Reads the tests and vectors of the same
# signer-core read-only (the signer-core folder of this repo, common.sh);
# skipped if its tests or vectors are absent.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

UP="$SIGNER_CORE"
if [ ! -f "$UP/tests/test_unit.c" ] || [ ! -d "$UP/vectors/consensus-spec-tests" ]; then
  log "upstream signer-core tests or vectors not found at $UP; skipped"
  exit 0
fi
UP="$(cd "$UP" && pwd)"
bash "$ROOT/scripts/build-core.sh" "$HOST_ARCH" >/dev/null
OUT="$BUILD/upstream-tests"
mkdir -p "$OUT"
SRC="$BUILD/core-src"
LIB="$BUILD/$HOST_ARCH/lib"
for t in test_unit test_ssz_static test_bls_sign test_eip3076; do
  gcc -std=c11 -O2 -D_DEFAULT_SOURCE -Wall -Wextra -Werror -Wno-format-truncation \
    -I"$ROOT/markformat" -I"$SRC/src" -I"$SRC/include" -I"$BLST_DIR/bindings" -I"$UP/tests" \
    "$UP/tests/$t.c" "$ROOT/markformat/markformat.c" -o "$OUT/$t" "$LIB/libsigner_core.a" "$LIB/libblst.a"
done
ssz="$(ls -d "$UP"/vectors/consensus-spec-tests/v1.6.0-beta.0/tests/minimal)"
bls="$(ls -d "$UP"/vectors/consensus-spec-tests/v1.5.0/tests/general/phase0/bls/sign)"
python3 -I "$UP/tests/eip3076_convert.py" "$UP/vectors/slashing-protection-interchange-tests/tests/generated" >"$OUT/eip3076.txt"
status=0
"$OUT/test_unit" "$UP/tests/data" >"$OUT/unit.log" 2>&1 || status=1
"$OUT/test_ssz_static" "$ssz" >"$OUT/ssz.log" 2>&1 || status=1
"$OUT/test_bls_sign" "$bls" >"$OUT/bls.log" 2>&1 || status=1
"$OUT/test_eip3076" "$OUT/eip3076.txt" >"$OUT/eip3076.log" 2>&1 || status=1
grep -hE "^(UNIT|SSZ_STATIC|BLS_SIGN|EIP3076|restart property)" "$OUT"/*.log
if [ "$status" = 0 ]; then
  log "upstream suites PASS against the core built here"
else
  log "upstream suites FAILED"
fi
exit "$status"
