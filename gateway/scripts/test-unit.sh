#!/usr/bin/env bash
# Runs go vet and the Go unit tests.
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# The gateway links the signer core and blst (cgo, build/<arch>/lib).
bash "$REPO_ROOT/scripts/build-core.sh" "$(uname -m)"
cd "$GW_DIR"
go vet ./...
go test -count=1 "$@" ./...
