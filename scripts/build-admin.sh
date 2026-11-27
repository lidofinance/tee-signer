#!/usr/bin/env bash
# signer-admin for this machine, into build/<arch>/bin (make admin). With
# DVT=1 it builds signer-admin-dvt, with the tag dvt and the DVT core: the
# commands of the dv_share exit route (dv-indices, dv-exit, dv-exit-post,
# signer-admin/cmd/signer-admin/dvexit.go). The default build has none of
# them. Needs the core of the variant (make core, make core DVT=1).
#
#   scripts/build-admin.sh
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

out="$BUILD/$HOST_ARCH/bin"
mkdir -p "$out"
name=signer-admin
tags=""
if [ "$DVT" = 1 ]; then
  name=signer-admin-dvt
  tags=dvt
fi
(cd "$ROOT/signer-admin" && CGO_ENABLED=1 CC="$(cc_for "$HOST_ARCH")" \
  go build -trimpath -buildvcs=false -tags "$tags" -o "$out/$name" ./cmd/signer-admin)
# wc, not stat -c: the stat of macOS has other flags.
log "$HOST_ARCH $name: $(($(wc -c <"$out/$name"))) bytes, sha256 $(sha256sum "$out/$name" | cut -c1-16)..."
