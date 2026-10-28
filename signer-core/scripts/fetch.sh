#!/usr/bin/env bash
# Fetches pinned third-party code and test vectors. Safe to re-run.
#   signer-core/third_party/blst is vendored: this script only checks it
#   signer-core/vectors/consensus-spec-tests/<ver>/     ssz_static and bls/sign subsets
#   signer-core/vectors/slashing-protection-interchange-tests/
# Usage: fetch.sh [--no-vectors]
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

WANT_VECTORS=1
[ "${1:-}" = "--no-vectors" ] && WANT_VECTORS=0

check_blst

[ "$WANT_VECTORS" = 1 ] || exit 0

git_checkout_pinned "$SPIT_REPO" "$SPIT_DIR" "$SPIT_TAG" "$SPIT_COMMIT"

# extract_subset <version> <asset> <sha256> <stamp-name> <pattern>...
# Downloads one release asset and extracts only the given paths. A stamp
# file per subset keeps re-runs cheap.
extract_subset() {
  local ver="$1" asset="$2" sha="$3" name="$4"
  shift 4
  local out="$VECTORS_DIR/consensus-spec-tests/$ver"
  local tarball="$VECTORS_DIR/downloads/$ver/$asset"
  local stamp="$out/.extracted-$name"
  [ -f "$stamp" ] && { log "$ver $name already extracted"; return 0; }
  download_verified "$CST_RELEASES/$ver/$asset" "$tarball" "$sha"
  mkdir -p "$out"
  log "extracting $name from $ver/$asset"
  # The v1.5.0 tarballs were packed on macOS: skip AppleDouble files and
  # silence the xattr header warnings.
  tar --warning=no-unknown-keyword --exclude='._*' -xzf "$tarball" -C "$out" \
    --wildcards "$@"
  touch "$stamp"
}

ssz_patterns=()
for c in $SSZ_CONTAINERS; do ssz_patterns+=("tests/minimal/*/ssz_static/$c/*"); done
extract_subset "$CST_SSZ_VERSION" "$CST_SSZ_ASSET" "$CST_SSZ_SHA256" ssz_static-gloas "${ssz_patterns[@]}"
extract_subset "$CST_BLS_VERSION" "$CST_BLS_ASSET" "$CST_BLS_SHA256" bls_sign 'tests/general/phase0/bls/sign/*'

log "vectors ready in $VECTORS_DIR"
