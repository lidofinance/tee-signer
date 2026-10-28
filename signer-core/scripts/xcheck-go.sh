#!/usr/bin/env bash
# Regenerates the ValidatorRegistrationV1 vectors with attestantio
# go-builder-client (versions pinned in tools/xcheck-go/go.mod and go.sum)
# and checks they equal the committed tests/data/registration_go.txt.
# Needs Go; skipped with a message when Go is missing.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

if ! command -v go >/dev/null; then
  log "go not found; skipping the Go cross-check (tests/data/registration_go.txt is committed)"
  exit 0
fi
out="$CORE_DIR/build/registration_go.txt"
mkdir -p "$(dirname "$out")"
(cd "$CORE_DIR/tools/xcheck-go" && go run -mod=readonly . >"$out")
if diff -q "$out" "$CORE_DIR/tests/data/registration_go.txt" >/dev/null; then
  echo "PASS xcheck-go: $(grep -vc '^#' "$out") registrations regenerated with go-builder-client match tests/data/registration_go.txt"
else
  echo "FAIL xcheck-go: regenerated vectors differ from tests/data/registration_go.txt"
  exit 1
fi
