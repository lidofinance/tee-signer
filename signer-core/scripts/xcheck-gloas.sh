#!/usr/bin/env bash
# Regenerates the Gloas vectors with attestantio go-eth2-client v0.30.3
# (tools/xcheck-gloas, versions pinned in its go.mod and go.sum) and checks
# they equal the committed tests/data/gloas_go.txt. Needs Go and the modules
# in the local module cache (GOPROXY=off: nothing is downloaded); skipped
# with a message when Go is missing.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

if ! command -v go >/dev/null; then
  log "go not found; skipping the Gloas cross-check (tests/data/gloas_go.txt is committed)"
  exit 0
fi
out="$CORE_DIR/build/gloas_go.txt"
mkdir -p "$(dirname "$out")"
(cd "$CORE_DIR/tools/xcheck-gloas" && GOPROXY=off GOFLAGS=-mod=readonly go run . >"$out")
if diff -q "$out" "$CORE_DIR/tests/data/gloas_go.txt" >/dev/null; then
  echo "PASS xcheck-gloas: $(grep -vc '^#' "$out") Gloas vectors regenerated with go-eth2-client match tests/data/gloas_go.txt"
else
  echo "FAIL xcheck-gloas: regenerated vectors differ from tests/data/gloas_go.txt"
  exit 1
fi
bra="$CORE_DIR/build/builder_auth_go.txt"
(cd "$CORE_DIR/tools/xcheck-gloas" && GOPROXY=off GOFLAGS=-mod=readonly go run . -bra >"$bra")
if diff -q "$bra" "$CORE_DIR/tests/data/builder_auth_go.txt" >/dev/null; then
  echo "PASS xcheck-gloas -bra: $(grep -vc '^#' "$bra") BuilderRequestAuth vectors regenerated with go-eth2-client match tests/data/builder_auth_go.txt"
else
  echo "FAIL xcheck-gloas -bra: regenerated vectors differ from tests/data/builder_auth_go.txt"
  exit 1
fi
