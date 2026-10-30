#!/usr/bin/env bash
# Builds libsigner_nts.a, the Rust NTS library (nts/), for x86_64 and aarch64
# inside the toolchain image (trusted-time/toolchain/toolchain.Dockerfile), offline.
#
#   build/nts/<arch>/lib/libsigner_nts.a
#   build/nts/<arch>/nostd-check/    the no_std checks of signer-nts-core:
#       core-features.txt                  cargo tree -e features, no "std" in it
#       libsigner_nts_nostd_check.a        the core in a no_std staticlib
#       undefined.txt                      the symbols that archive needs from outside
#       undefined-core.txt                 the same for the core's own object
#   build/nts/SHA256SUMS
#
# build/<arch>/, which the image builds read, is not touched.
#
# Usage: build-nts.sh [--no-test] [x86_64|aarch64 ...]
# Default: both architectures, and the tests of signer-nts and signer-nts-core
# (x86_64, run in the container).
#
# What keeps the archive the same on every build:
#   - one pinned compiler (the image's rustc must have NTS_RUSTC_COMMIT), the
#     crates of Cargo.lock from trusted-time/third_party/nts-vendor (checked first by
#     fetch-nts.sh --check), and cargo --locked --offline --frozen;
#   - a fresh container for every build, started with --network none and as
#     the calling user, so no state and no umask of the host gets in;
#   - --remap-path-prefix for the mount point of the sources and for the
#     cargo, rustup and target folders (nts-container.sh), no debug info
#     (Cargo.toml), no build script of our own;
#   - the script sets its own umask, and the archive is written with mode 0644.
# After each build the script checks that the archive holds the 17 exports,
# is for the right architecture, and names no path of this machine.
set -euo pipefail
umask 022
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

run_tests=1
archs=()
for a in "$@"; do
  case "$a" in
    --no-test) run_tests=0 ;;
    x86_64|aarch64) archs+=("$a") ;;
    *) echo "usage: build-nts.sh [--no-test] [x86_64|aarch64 ...]" >&2; exit 2 ;;
  esac
done
[ ${#archs[@]} -gt 0 ] || archs=(x86_64 aarch64)

# Where the sources are mounted in the container. The compiler maps it to
# /build, so the archive does not depend on it. nts-repro.sh builds with
# another one to show that.
CROOT="${NTS_CONTAINER_ROOT:-/src}"

bash "$ROOT/scripts/fetch-nts.sh" --check
nts_toolchain_image
mkdir -p "$NTS_OUT" "$LOGS"

for arch in "${archs[@]}"; do
  out="$NTS_OUT/$arch/lib"
  lib="$out/libsigner_nts.a"
  chk="$NTS_OUT/$arch/nostd-check"
  rm -rf "${out:?}" "${chk:?}"
  mkdir -p "$out" "$chk"
  tests=0
  [ "$arch" = x86_64 ] && [ "$run_tests" = 1 ] && tests=1
  docker run --rm --pull=never --network none --user "$(id -u):$(id -g)" \
    -e HOME=/tmp/home -e CARGO_HOME=/tmp/cargo-home -e CARGO_TARGET_DIR=/tmp/target \
    -e SOURCE_DATE_EPOCH=0 -e NTS_TARGET="$arch-unknown-linux-gnu" -e NTS_CROOT="$CROOT" \
    -e NTS_RUSTC_COMMIT="$NTS_RUSTC_COMMIT" -e NTS_TEST="$tests" \
    -v "$ROOT/scripts/nts-container.sh:/nts-container.sh:ro" \
    -v "$NTS_DIR:$CROOT/nts:ro" \
    -v "$NTS_VENDOR_DIR:$CROOT/third_party/nts-vendor:ro" \
    -v "$out:/out" \
    "$NTS_IMAGE" bash /nts-container.sh >"$LOGS/nts-build-$arch.log" 2>&1 ||
    { tail -40 "$LOGS/nts-build-$arch.log" >&2; echo "build-nts: the $arch build failed" >&2; exit 1; }
  [ "$tests" != 1 ] || grep -E '^test result' "$LOGS/nts-build-$arch.log" >&2
  chmod 0644 "$lib"
  mkdir -p "$NTS_OUT/$arch/licenses"
  mv "$out/RUST_STANDARD_LIBRARY.html" "$NTS_OUT/$arch/licenses/"
  # The no_std checks of the core go next to lib/, not into it.
  mv "$out/core-features.txt" "$out/libsigner_nts_nostd_check.a" "$chk/"
  nostd="$chk/libsigner_nts_nostd_check.a"
  # undefined.txt: undefined in one object and defined in no other object of
  # the archive. undefined-core.txt: the same for the one object that holds
  # the core after LTO; the others are the target's precompiled
  # compiler_builtins.
  nm_arch="$(tool_for "$arch" nm)"
  LC_ALL=C comm -23 \
    <("$nm_arch" -u "$nostd" 2>/dev/null | awk '$1 == "U" { print $2 }' | LC_ALL=C sort -u) \
    <("$nm_arch" --defined-only "$nostd" 2>/dev/null | awk 'NF == 3 { print $3 }' | LC_ALL=C sort -u) >"$chk/undefined.txt"
  "$nm_arch" -u "$nostd" 2>/dev/null |
    awk '/:$/ { member = $0; next } member ~ /^signer_nts_nostd_check/ && $1 == "U" { print $2 }' |
    LC_ALL=C sort -u >"$chk/undefined-core.txt"
  [ -s "$chk/undefined-core.txt" ] || { echo "build-nts: no core object found in $nostd" >&2; exit 1; }
  log "no_std check $arch: no std feature in the core's graph ($(grep -c . "$chk/core-features.txt") lines of cargo tree); the core builds into a no_std staticlib; its object needs $(tr '\n' ' ' <"$chk/undefined-core.txt")(whole archive: $(tr '\n' ' ' <"$chk/undefined.txt" | sed 's/ $//'))"

  # The exports of signer_nts.h, as defined symbols.
  defined="$("$(tool_for "$arch" nm)" -g --defined-only "$lib" 2>/dev/null)"
  for sym in snts_version snts_aes_siv_selftest snts_reason_text snts_ke_alpn snts_ke_exporter_label \
    snts_ke_exporter_context snts_ke_request snts_ke_response_length snts_assoc_new snts_assoc_free \
    snts_assoc_cookies snts_assoc_port snts_assoc_server snts_ntp_request snts_request_free snts_ntp_verify snts_quorum; do
    grep -q " T $sym\$" <<<"$defined" || { echo "build-nts: $lib does not define $sym" >&2; exit 1; }
  done
  # Every object in the archive is for this architecture.
  case "$arch" in x86_64) machine="Advanced Micro Devices X86-64" ;; aarch64) machine="AArch64" ;; esac
  total="$(readelf -h "$lib" | grep -c 'Machine:')"
  right="$(readelf -h "$lib" | grep -c "Machine: *$machine\$")"
  [ "$total" -gt 0 ] && [ "$total" = "$right" ] ||
    { echo "build-nts: $lib has objects that are not $arch ($right of $total)" >&2; exit 1; }
  # No path of this machine or of the container. The standard library keeps
  # paths of the Rust project's own build (/rustc/<commit>/..., /build/<target>/stage1-std/...);
  # they are the same for every build with this compiler.
  for a in "$lib" "$nostd"; do
    leaks="$(grep -a -o -E "($ROOT|$HOME|$CROOT/(nts|third_party)|/tmp/(cargo-home|target|home)|/usr/local/(cargo|rustup))[A-Za-z0-9_./-]*" "$a" | sort -u || true)"
    [ -z "$leaks" ] || { echo "build-nts: $a names paths of the build:" >&2; echo "$leaks" >&2; exit 1; }
  done
  # The header is valid C and matches the library (the unit test also reads it).
  cc -std=c11 -Wall -Wextra -Werror -pedantic -fsyntax-only -I"$NTS_DIR/include" -x c - <<<'#include "signer_nts.h"'
  log "libsigner_nts.a $arch: $(stat -c %s "$lib") bytes, $total objects, sha256 $(sha256sum "$lib" | cut -c1-16)..."
done

(cd "$NTS_OUT" && sha256sum ./*/lib/libsigner_nts.a | sed 's| \./| |' >SHA256SUMS)
log "$NTS_OUT/SHA256SUMS: $(tr '\n' ' ' <"$NTS_OUT/SHA256SUMS")"
