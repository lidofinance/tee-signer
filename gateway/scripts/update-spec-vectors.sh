#!/usr/bin/env bash
# Regenerates web3signer-api/signing/testdata from the Web3Signer OpenAPI examples at
# WEB3SIGNER_TAG (sparse clone into .work/, which is git-ignored).
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

src="$GW_DIR/.work/web3signer"
if [ ! -d "$src/.git" ]; then
  git clone --quiet --depth 1 --branch "$WEB3SIGNER_TAG" --filter=blob:none --sparse "$WEB3SIGNER_REPO" "$src"
  git -C "$src" sparse-checkout set --no-cone "**/openapi-specs/eth2/**"
fi
git -C "$src" fetch --quiet --depth 1 origin tag "$WEB3SIGNER_TAG"
git -C "$src" checkout --quiet "tags/$WEB3SIGNER_TAG"
out="$REPO_ROOT/web3signer-api/signing/testdata/web3signer-$WEB3SIGNER_TAG-sign-examples.json"
(cd "$GW_DIR" && go run ./tools/specvectors "$src/openapi-specs/eth2/signing/paths/sign.yaml") >"$out"
log "wrote $out"
