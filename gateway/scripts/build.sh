#!/usr/bin/env bash
# Builds bin/gateway and bin/blsverify.
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

command -v go >/dev/null || die "go not found (Go 1.26 or later)"
mkdir -p "$GW_BIN"
cd "$GW_DIR"
log "building gateway and blsverify ($(go env GOVERSION), $(go env GOARCH))"
CGO_ENABLED=1 go build -trimpath -o "$GW_BIN/gateway" ./cmd/gateway
CGO_ENABLED=1 go build -trimpath -o "$GW_BIN/blsverify" ./cmd/blsverify
log "built $GW_BIN/gateway $GW_BIN/blsverify"
