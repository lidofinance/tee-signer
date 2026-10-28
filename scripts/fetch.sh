#!/usr/bin/env bash
# Fetches pinned third-party code into third_party/. Safe to re-run.
#   fetch.sh            checks the vendored blst only
#   fetch.sh --nitro    also fetches aws-nitro-enclaves-cli (network)
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# blst is vendored (signer-core/third_party/blst): check it, never fetch it.
(cd "$BLST_DIR" && sha256sum --quiet -c "$THIRD_PARTY/blst.sha256") ||
  { echo "signer-core/third_party/blst differs from blst.sha256 ($BLST_TAG, $BLST_COMMIT)" >&2; exit 1; }
if [ "${1:-}" = "--nitro" ]; then
  git_checkout_pinned "$NITRO_CLI_REPO" "$NITRO_CLI_DIR" "$NITRO_CLI_TAG" "$NITRO_CLI_COMMIT"
fi
