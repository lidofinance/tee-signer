#!/usr/bin/env bash
# Builds bin/gateway and bin/blsverify.
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

command -v go >/dev/null || die "go not found (Go 1.26 or later)"
mkdir -p "$GW_BIN"
# The gateway links the signer core and blst (cgo, build/<arch>/lib).
bash "$REPO_ROOT/scripts/build-core.sh" "$(uname -m)"
cd "$GW_DIR"
log "building gateway and blsverify ($(go env GOVERSION), $(go env GOARCH))"
# The C flags of the cgo code, as CGO_HARDEN in scripts/common.sh (Go's
# default -g -O2 with the stack protector named, so it does not depend on
# the compiler's default).
cgo_cflags="-g -O2 -fstack-protector-strong"
CGO_ENABLED=1 CGO_CFLAGS="$cgo_cflags" go build -trimpath -o "$GW_BIN/gateway" ./cmd/gateway
CGO_ENABLED=1 CGO_CFLAGS="$cgo_cflags" go build -trimpath -o "$GW_BIN/blsverify" ./cmd/blsverify
log "built $GW_BIN/gateway $GW_BIN/blsverify"
