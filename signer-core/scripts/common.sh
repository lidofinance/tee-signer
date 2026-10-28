# shellcheck shell=bash disable=SC2034 # sourced; variables are used by the callers
# Shared settings for signer-core scripts. Source it, do not run it.
# Pinned versions of everything the scripts download live here.

CORE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$CORE_DIR/.." && pwd)"
# blst is vendored in signer-core/third_party/blst (blst.sha256 lists its files).
THIRD_PARTY="$CORE_DIR/third_party"
# The test vectors are not in the repo: scripts/fetch.sh downloads them at
# their pins. VECTORS_DIR may name a copy fetched before (offline runs).
VECTORS_DIR="${VECTORS_DIR:-$CORE_DIR/vectors}"

# supranational/blst (vendored, see check_blst)
BLST_REPO="https://github.com/supranational/blst.git"
BLST_TAG="v0.3.16"
BLST_COMMIT="e7f90de551e8df682f3cc99067d204d8b90d27ad"
BLST_DIR="$THIRD_PARTY/blst"

# ethereum/consensus-spec-tests.
# ssz_static comes from v1.6.0-beta.0, the newest release on the releases
# page (sha256 = the digest GitHub publishes for the asset).
# v1.6.0-beta.0 general.tar.gz no longer ships phase0/bls/sign, so the BLS
# sign vectors come from v1.5.0, the newest release that has them. GitHub
# publishes no digest for v1.5.0 assets; that sha256 was recorded on first
# download.
CST_RELEASES="https://github.com/ethereum/consensus-spec-tests/releases/download"
CST_SSZ_VERSION="v1.6.0-beta.0"
CST_SSZ_ASSET="minimal.tar.gz"
CST_SSZ_SHA256="c28c30c32bddd0a24bb04fa80ceb4f92b859c899dd26927495b5d8b0b1fa5c1c"
CST_BLS_VERSION="v1.5.0"
CST_BLS_ASSET="general.tar.gz"
CST_BLS_SHA256="708f8325edc15e567496bdbcc375128b696760e5147dd8bf619de726e4628985"
CST_SSZ_DIR="$VECTORS_DIR/consensus-spec-tests/$CST_SSZ_VERSION/tests/minimal"
CST_BLS_DIR="$VECTORS_DIR/consensus-spec-tests/$CST_BLS_VERSION/tests/general/phase0/bls/sign"

# eth-clients/slashing-protection-interchange-tests (EIP-3076)
SPIT_REPO="https://github.com/eth-clients/slashing-protection-interchange-tests.git"
SPIT_TAG="v5.3.0"
SPIT_COMMIT="bb7900688eecd287d8723154faac6addb5e63336"
SPIT_DIR="$VECTORS_DIR/slashing-protection-interchange-tests"

# Containers the core implements that also have ssz_static vectors.
SSZ_CONTAINERS="Checkpoint AttestationData BeaconBlockHeader VoluntaryExit ForkData SigningData PayloadAttestationData"

HOST_ARCH="$(uname -m)"
case "$HOST_ARCH" in
  x86_64|amd64) HOST_ARCH=x86_64 ;;
  aarch64|arm64) HOST_ARCH=aarch64 ;;
  *) echo "unsupported architecture: $HOST_ARCH" >&2; exit 1 ;;
esac

# check_blst: the vendored blst is the pinned release, file for file.
check_blst() {
  (cd "$BLST_DIR" && sha256sum --quiet -c "$THIRD_PARTY/blst.sha256") ||
    { echo "signer-core/third_party/blst differs from blst.sha256 (blst $BLST_TAG, $BLST_COMMIT)" >&2; return 1; }
}

log() { printf '[signer-core] %s\n' "$*" >&2; }

# git_checkout_pinned <url> <dir> <tag> <commit>
# Clones or updates <dir> so that HEAD is exactly <commit>.
git_checkout_pinned() {
  local url="$1" dir="$2" tag="$3" commit="$4"
  if [ ! -d "$dir/.git" ]; then
    rm -rf "$dir"
    mkdir -p "$(dirname "$dir")"
    git clone --quiet "$url" "$dir"
  fi
  if [ "$(git -C "$dir" rev-parse HEAD 2>/dev/null)" != "$commit" ]; then
    git -C "$dir" fetch --quiet --tags origin
    # The directory is managed by this script, so discard any partial checkout.
    git -C "$dir" -c advice.detachedHead=false checkout --quiet --force "$commit"
  fi
  if [ -n "$(git -C "$dir" status --porcelain --untracked-files=no)" ]; then
    git -C "$dir" reset --quiet --hard "$commit"
  fi
  local got
  got="$(git -C "$dir" rev-parse HEAD)"
  if [ "$got" != "$commit" ]; then
    echo "$dir: expected $commit ($tag), got $got" >&2
    return 1
  fi
  log "$(basename "$dir") at $tag ($commit)"
}

# download_verified <url> <dest> <sha256>
download_verified() {
  local url="$1" dest="$2" sha="$3"
  mkdir -p "$(dirname "$dest")"
  if [ -f "$dest" ] && echo "$sha  $dest" | sha256sum -c --status; then
    log "cached $(basename "$dest")"
    return 0
  fi
  log "downloading $url"
  curl -fsSL --retry 5 --retry-delay 5 -o "$dest.part" "$url"
  if ! echo "$sha  $dest.part" | sha256sum -c --status; then
    echo "sha256 mismatch for $url" >&2
    rm -f "$dest.part"
    return 1
  fi
  mv "$dest.part" "$dest"
}
