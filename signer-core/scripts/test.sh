#!/usr/bin/env bash
# Builds signer-core and runs every test suite. Exits non-zero on any failure.
#   ARCH=<x86_64|aarch64>   build to test (default: this machine)
#   RUNNER=qemu-aarch64     prefix for running cross-built test binaries
#   NO_BUILD=1              skip make (scripts/cross-aarch64.sh builds first)
#   FUZZ=0                  skip the short fuzz run (scripts/fuzz.sh ci)
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

ARCH="${ARCH:-$HOST_ARCH}"
RUNNER="${RUNNER:-}"
BUILD="$CORE_DIR/build/$ARCH"
LOGS="$BUILD/test-logs"

if [ "${NO_BUILD:-0}" != 1 ]; then
  make -C "$CORE_DIR" -j"$(nproc)" ARCH="$ARCH" all >/dev/null
fi
for d in "$CST_SSZ_DIR" "$CST_BLS_DIR" "$SPIT_DIR/tests/generated"; do
  [ -d "$d" ] || { echo "missing $d; run scripts/fetch.sh" >&2; exit 1; }
done
mkdir -p "$LOGS"
python3 -I "$CORE_DIR/tests/eip3076_convert.py" "$SPIT_DIR/tests/generated" >"$BUILD/eip3076.txt"

status=0
# run <name> <regex of summary lines to print> <command...>
run() {
  local name="$1" pat="$2" res=PASS
  shift 2
  # RUNNER is intentionally unquoted: empty means "run directly".
  # shellcheck disable=SC2086
  $RUNNER "$@" >"$LOGS/$name.log" 2>&1 || { res=FAIL; status=1; }
  grep -E "$pat" "$LOGS/$name.log" | sed 's/^/  /' || true
  echo "$res $name ($ARCH${RUNNER:+ via $RUNNER}, log: ${LOGS#"$REPO_ROOT"/}/$name.log)"
}

run unit '^(UNIT|memory|registration_go|gloas|commit-ahead|write counts|repeat after restart|non-finality restart|hash cache|restart property|device restart property|bench)' \
  "$BUILD/test_unit" "$CORE_DIR/tests/data"
run ssz_static '^SSZ_STATIC' "$BUILD/test_ssz_static" "$CST_SSZ_DIR"
run bls_sign '^BLS_SIGN' "$BUILD/test_bls_sign" "$CST_BLS_DIR"
# The converter must refuse a malformed vector: tests/data/eip3076-bad holds
# one vector per fault (a signed number, a number with a space, one above
# u64, an unknown field, a missing field, a bool given as a string).
res=PASS nbad=0
for f in "$CORE_DIR"/tests/data/eip3076-bad/*.json; do
  nbad=$((nbad + 1))
  if python3 -I "$CORE_DIR/tests/eip3076_convert.py" "$f" >/dev/null 2>>"$LOGS/eip3076_convert.log"; then
    echo "  converter accepted $(basename "$f")"
    res=FAIL
    status=1
  fi
done
echo "$res eip3076_convert (refuses $nbad malformed vectors)"
run eip3076 '^EIP3076' "$BUILD/test_eip3076" "$BUILD/eip3076.txt"

# The core must not call into the OS. Its objects may only reference blst,
# the mem* functions, the compiler's stack protector hook and the
# linker-provided GOT symbol that -fPIC code uses.
CROSS_CC=""
[ "$ARCH" = "$HOST_ARCH" ] || CROSS_CC="CC=${ARCH}-linux-gnu-gcc"
# shellcheck disable=SC2086
syms="$(make -s -C "$CORE_DIR" ARCH="$ARCH" $CROSS_CC symbols)"
extra="$(echo "$syms" | grep -v -E '^(blst_[a-z0-9_]+|memcpy|memset|memcmp|__stack_chk_fail|_GLOBAL_OFFSET_TABLE_)$' || true)"
echo "  undefined symbols in core objects: $(echo "$syms" | grep -c . ) ($(echo "$syms" | grep -v '^blst_' | tr '\n' ' ')+ blst_*)"
if [ -n "$extra" ]; then
  echo "FAIL symbols: unexpected external references: $extra"
  status=1
else
  echo "PASS symbols ($ARCH)"
fi

# Fuzz targets with ASan and UBSan: the regression inputs, then a few
# seconds per target (scripts/fuzz.sh ci). Native builds only; FUZZ=0 skips.
if [ "$ARCH" = "$HOST_ARCH" ] && [ "${FUZZ:-1}" != 0 ]; then
  run fuzz '^(  FAIL|PASS fuzz|FAIL fuzz)' bash "$CORE_DIR/scripts/fuzz.sh" ci
fi
exit $status
