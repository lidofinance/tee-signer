#!/usr/bin/env bash
# Cross-compiles blst, the core and the tests for aarch64 (static), checks
# the object architecture, and runs the full test suite under qemu-user.
# On an aarch64 workbench this is a no-op: scripts/test.sh already builds
# and runs natively there.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

if [ "$HOST_ARCH" = aarch64 ]; then
  log "host is aarch64; scripts/test.sh already covers aarch64 natively"
  exit 0
fi

CROSS_CC="${CROSS_CC:-aarch64-linux-gnu-gcc}"
command -v "$CROSS_CC" >/dev/null || { echo "$CROSS_CC not found; run scripts/deps.sh" >&2; exit 1; }

log "cross-building with $("$CROSS_CC" --version | head -1)"
make -C "$CORE_DIR" -j"$(nproc)" ARCH=aarch64 CC="$CROSS_CC" LDFLAGS=-static all >/dev/null

BUILD="$CORE_DIR/build/aarch64"
echo "  $(cd "$BUILD" && file libsigner_core.a | head -1)"
echo "  core objects: $(aarch64-linux-gnu-objdump -f "$BUILD"/obj/*.o | grep -o 'file format [a-z0-9-]*' | sort -u | tr '\n' ' ')"
echo "  $(cd "$BUILD" && file test_unit | cut -c1-140)"

if command -v qemu-aarch64 >/dev/null; then
  ARCH=aarch64 RUNNER=qemu-aarch64 NO_BUILD=1 bash "$CORE_DIR/scripts/test.sh"
else
  log "qemu-aarch64 not installed; built but did not run the aarch64 tests"
fi
