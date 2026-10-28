#!/usr/bin/env bash
# Builds the runners with the build tag nts, which links the Rust NTS library
# (libsigner_nts.a, scripts/build-nts.sh) into the static runner through cgo:
#
#   build/nts/<arch>/bin/<name>-nts    for every runner build of build-runner.sh (RUNNER_BINS in common.sh)
#
# The flags are those of scripts/build-runner.sh plus the tag. The files in
# build/<arch>/bin are not touched. The cloud runners there have the tag
# already (common.sh runner_tags), so their -nts copies here are the same
# builds; the dev runners get it only here. Needs build/<arch>/lib/libsigner_core.a
# and libblst.a (scripts/build-core.sh) and the Rust archive of build-nts.sh.
#
# Each binary is checked: static, of the arch asked for, built with the tags
# of its platform plus nts, holding the library's version string, and linking
# the same Go modules as the same runner built without the tag (when that one
# is in build/<arch>/bin).
#
# Usage: build-runner-nts.sh [x86_64|aarch64 ...]   default: same arch list as build-runner.sh
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

archs=("$@")
if [ ${#archs[@]} -eq 0 ]; then
  archs=("$HOST_ARCH")
  for a in x86_64 aarch64; do
    [ "$a" = "$HOST_ARCH" ] && continue
    command -v "$(cc_for "$a")" >/dev/null 2>&1 && archs+=("$a")
  done
fi

# modules_of <binary>: the Go modules it links, with versions.
modules_of() { go version -m "$1" | awk '$1 == "dep" { print $2, $3 }' | LC_ALL=C sort; }

LDFLAGS="-s -w -buildid= -linkmode external -extldflags -static"
for arch in "${archs[@]}"; do
  for lib in "$BUILD/$arch/lib/libsigner_core.a" "$BUILD/$arch/lib/libblst.a" "$NTS_OUT/$arch/lib/libsigner_nts.a"; do
    [ -f "$lib" ] || { echo "build-runner-nts: $lib is missing (scripts/build-core.sh, scripts/build-nts.sh)" >&2; exit 1; }
  done
  out="$NTS_OUT/$arch/bin"
  mkdir -p "$out"
  for name in "${RUNNER_BINS[@]}"; do
    # The cloud builds have the tag already (common.sh runner_tags): their
    # -nts copy is the same build as build/<arch>/bin/<name>.
    tags="netgo,osusergo,$(runner_tags "$name")"
    has_nts "$name" || tags="$tags,nts"
    bin="$out/$name-nts"
    (cd "$ROOT/tee-signer" && \
      CGO_ENABLED=1 GOOS=linux GOARCH="$(goarch_of "$arch")" CC="$(cc_for "$arch")" \
      go build -trimpath -buildvcs=false -tags "$tags" -ldflags "$LDFLAGS" -o "$bin" .)

    info="$(file -b "$bin")"
    case "$info" in *"statically linked"*) ;; *) echo "$bin is not static: $info" >&2; exit 1 ;; esac
    case "$arch:$info" in x86_64:*"x86-64"*|aarch64:*"ARM aarch64"*) ;; *) echo "$bin is not an $arch binary: $info" >&2; exit 1 ;; esac
    got="$(go version -m "$bin" | awk '$1 == "build" && $2 ~ /^-tags=/ { sub(/^-tags=/, "", $2); print $2 }')"
    [ "$got" = "$tags" ] || { echo "$bin: built with -tags=$got, expected -tags=$tags" >&2; exit 1; }
    grep -qa "signer-nts " "$bin" || { echo "$bin does not hold the library's version string" >&2; exit 1; }
    plain="$BUILD/$arch/bin/$name"
    if [ -f "$plain" ]; then
      [ "$(modules_of "$bin")" = "$(modules_of "$plain")" ] ||
        { echo "$bin links other Go modules than $plain" >&2; exit 1; }
      note="$(( $(stat -c %s "$bin") - $(stat -c %s "$plain") )) bytes more than $name"
    else
      note="no $name in build/$arch/bin to compare"
    fi
    log "$arch $name-nts: $(stat -c %s "$bin") bytes ($note), sha256 $(sha256sum "$bin" | cut -c1-16)..."
  done
done
