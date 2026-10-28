#!/usr/bin/env bash
# Builds the C signer core and blst as static libraries for cgo.
#
#   build/core-src/              include/ and src/ of signer-core, and
#                                SOURCE.txt (where they came from, sha256)
#   build/<arch>/lib/libsigner_core.a
#   build/<arch>/lib/libblst.a
#
# signer-core is the signer-core folder of this repo (common.sh).
#
# Usage: build-core.sh [x86_64|aarch64 ...]   default: the host arch, plus
# the other arch when its cross compiler is installed.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

[ -f "$SIGNER_CORE/include/signer_core.h" ] ||
  { echo "signer-core not found at $SIGNER_CORE" >&2; exit 1; }
SIGNER_CORE="$(cd "$SIGNER_CORE" && pwd)"
[ -f "$BLST_DIR/build.sh" ] || bash "$ROOT/scripts/fetch.sh"

archs=("$@")
if [ ${#archs[@]} -eq 0 ]; then
  archs=("$HOST_ARCH")
  for a in x86_64 aarch64; do
    [ "$a" = "$HOST_ARCH" ] && continue
    command -v "$(cc_for "$a")" >/dev/null 2>&1 && archs+=("$a")
  done
fi

# A snapshot of the core sources, so one build uses one version. Recreated
# every run; it is a handful of small files.
SRC="$BUILD/core-src"
rm -rf "$SRC.tmp"
mkdir -p "$SRC.tmp"
cp -r "$SIGNER_CORE/include" "$SIGNER_CORE/src" "$SRC.tmp/"
if git -C "$SIGNER_CORE" rev-parse --git-dir >/dev/null 2>&1; then
  ver="last commit of include/ and src/: $(git -C "$SIGNER_CORE" log -1 --format='%h %cI' -- include src 2>/dev/null || echo none)"
  [ -z "$(git -C "$SIGNER_CORE" status --porcelain -- include src)" ] || ver="$ver, with local changes"
else
  ver="not in a git repo"
fi
{
  echo "signer-core: $SIGNER_CORE ($ver)"
  (cd "$SRC.tmp" && find include src -type f | sort | xargs sha256sum)
} >"$SRC.tmp/SOURCE.txt"
if [ -d "$SRC" ] && diff -rq "$SRC" "$SRC.tmp" >/dev/null; then
  rm -rf "$SRC.tmp"
else
  rm -rf "$SRC"
  mv "$SRC.tmp" "$SRC"
  log "core sources from $SIGNER_CORE copied into $SRC"
fi

WARN="-Wall -Wextra -Werror -Wshadow -Wstrict-prototypes -Wmissing-prototypes"
for arch in "${archs[@]}"; do
  cc="$(cc_for "$arch")"
  command -v "$cc" >/dev/null || { echo "missing compiler $cc for $arch" >&2; exit 1; }
  ar="ar"
  [ "$arch" != "$HOST_ARCH" ] && ar="$arch-linux-gnu-ar"
  out="$BUILD/$arch"
  mkdir -p "$out/lib" "$out/obj" "$out/blst"

  if [ ! -f "$out/lib/libblst.a" ]; then
    flags=()
    # Runtime ADX detection keeps x86_64 binaries portable between CPUs.
    [ "$arch" = x86_64 ] && flags+=(-D__BLST_PORTABLE__)
    (cd "$out/blst" && CC="$cc" "$BLST_DIR/build.sh" "${flags[@]}" >build.log 2>&1) \
      || { cat "$out/blst/build.log"; exit 1; }
    cp "$out/blst/libblst.a" "$out/lib/libblst.a"
    log "blst built for $arch"
  fi

  objs=()
  for c in "$SRC"/src/*.c; do
    o="$out/obj/$(basename "${c%.c}").o"
    if [ ! -f "$o" ] || [ "$c" -nt "$o" ] || [ "$SRC/include/signer_core.h" -nt "$o" ]; then
      # shellcheck disable=SC2086
      "$cc" -std=c11 -O2 -fPIC -ffreestanding -fno-common $WARN \
        -I"$SRC/include" -I"$BLST_DIR/bindings" -c "$c" -o "$o"
    fi
    objs+=("$o")
  done
  rm -f "$out/lib/libsigner_core.a"
  "$ar" rcs "$out/lib/libsigner_core.a" "${objs[@]}"
  log "libsigner_core.a built for $arch"
done
