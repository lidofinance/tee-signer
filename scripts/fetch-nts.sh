#!/usr/bin/env bash
# Fetches the Rust crates of nts/ into trusted-time/third_party/nts-vendor/ (git-ignored,
# like blst). The pin is trusted-time/rust/Cargo.lock: cargo refuses a crate whose sha256
# differs from the one in the lock. Three checks on top, in every mode:
#
#   1. Cargo.lock holds the crates of trusted-time/rust/crates.allow (name and version) and
#      no others, all from the crates.io registry.
#   2. Every crate folder has the sha256 that Cargo.lock names. Every file in
#      it has the hash in its .cargo-checksum.json, and no file is extra.
#   3. The whole tree has the digest in nts/vendor.sha256.
#
#   fetch-nts.sh            vendor the crates of trusted-time/rust/Cargo.lock (network), then check
#   fetch-nts.sh --check    check trusted-time/third_party/nts-vendor/ only (no network, no docker)
#   fetch-nts.sh --relock   resolve the crates again into trusted-time/rust/Cargo.lock (network,
#                           index files only, no crate files), then check the list.
#                           Review the diff, edit trusted-time/rust/crates.allow, run fetch-nts.sh.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

LOCK="$NTS_DIR/Cargo.lock"
ALLOW="$NTS_DIR/crates.allow"
TREE_SUM="$NTS_DIR/vendor.sha256"
REGISTRY='registry+https://github.com/rust-lang/crates.io-index'

# lock_crates: "name version checksum" of each crate in Cargo.lock that has a checksum.
lock_crates() {
  awk '
    /^\[\[package\]\]/ { n = v = "" }
    /^name = /         { n = $3; gsub(/"/, "", n) }
    /^version = /      { v = $3; gsub(/"/, "", v) }
    /^checksum = /     { c = $3; gsub(/"/, "", c); print n, v, c }
  ' "$LOCK" | LC_ALL=C sort
}

check_lock() {
  [ -f "$LOCK" ] || { echo "$LOCK is missing: run scripts/fetch-nts.sh --relock" >&2; return 1; }
  [ -f "$ALLOW" ] || { echo "$ALLOW is missing" >&2; return 1; }
  if [ "$(grep '^source = ' "$LOCK" | sort -u)" != "source = \"$REGISTRY\"" ]; then
    echo "Cargo.lock has a source other than crates.io:" >&2
    grep '^source = ' "$LOCK" | sort -u >&2
    return 1
  fi
  if [ "$(grep -c '^source = ' "$LOCK")" != "$(grep -c '^checksum = ' "$LOCK")" ]; then
    echo "Cargo.lock: a crate has no checksum" >&2
    return 1
  fi
  if ! diff <(lock_crates | awk '{ print $1, $2 }' | LC_ALL=C sort) <(grep -v '^#' "$ALLOW" | LC_ALL=C sort) >&2; then
    echo "Cargo.lock and trusted-time/rust/crates.allow differ (< lock, > allow list). Do not vendor: review the crates." >&2
    return 1
  fi
}

# tree_digest: sha256 over the sorted sha256 list of every file in the vendor folder.
tree_digest() {
  (cd "$NTS_VENDOR_DIR" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1)
}

check_vendor() {
  [ -d "$NTS_VENDOR_DIR" ] || { echo "$NTS_VENDOR_DIR is missing: run scripts/fetch-nts.sh" >&2; return 1; }
  local name ver sum dir n
  while read -r name ver sum; do
    dir="$NTS_VENDOR_DIR/$name-$ver"
    [ -f "$dir/.cargo-checksum.json" ] || { echo "no vendored $name-$ver" >&2; return 1; }
    [ "$(jq -r .package "$dir/.cargo-checksum.json")" = "$sum" ] ||
      { echo "$name-$ver: package checksum differs from Cargo.lock" >&2; return 1; }
    n="$(jq '.files | length' "$dir/.cargo-checksum.json")"
    [ "$(find "$dir" -type f ! -name .cargo-checksum.json | wc -l)" = "$n" ] ||
      { echo "$name-$ver: files added or removed" >&2; return 1; }
    jq -r '.files | to_entries[] | "\(.value)  \(.key)"' "$dir/.cargo-checksum.json" | (cd "$dir" && sha256sum --check --quiet -) ||
      { echo "$name-$ver: a file differs from its checksum" >&2; return 1; }
  done < <(lock_crates)
  [ "$(find "$NTS_VENDOR_DIR" -mindepth 1 -maxdepth 1 | wc -l)" = "$(lock_crates | wc -l)" ] ||
    { echo "$NTS_VENDOR_DIR holds a folder that is not in Cargo.lock" >&2; return 1; }
  [ -z "$(find "$NTS_VENDOR_DIR" -type l)" ] || { echo "$NTS_VENDOR_DIR holds a symbolic link" >&2; return 1; }
  [ -f "$TREE_SUM" ] || { echo "$TREE_SUM is missing" >&2; return 1; }
  [ "$(tree_digest)" = "$(cat "$TREE_SUM")" ] || { echo "$NTS_VENDOR_DIR: the tree digest differs from trusted-time/rust/vendor.sha256" >&2; return 1; }
}

# in_toolchain <dir to mount at /work> <command...>: cargo as the calling user, with a network.
in_toolchain() {
  local work="$1"
  shift
  docker run --rm --pull=never --user "$(id -u):$(id -g)" \
    -e HOME=/tmp/home -e CARGO_HOME=/tmp/cargo-home -e CARGO_NET_RETRY=3 \
    -v "$work:/work" -w /work "$NTS_IMAGE" "$@"
}

# scratch_copy <dir>: the nts/ workspace (the root crate, core/, nostd-check/)
# without .cargo/, so cargo does not look for the vendor folder.
scratch_copy() {
  cp "$NTS_DIR/Cargo.toml" "$1/"
  cp -r "$NTS_DIR/src" "$1/"
  local member
  for member in core nostd-check; do
    mkdir -p "$1/$member"
    cp "$NTS_DIR/$member/Cargo.toml" "$1/$member/"
    cp -r "$NTS_DIR/$member/src" "$1/$member/"
  done
  [ ! -f "$LOCK" ] || cp "$LOCK" "$1/"
}

case "${1:-fetch}" in
  --check)
    check_lock
    check_vendor
    log "nts-vendor: matches Cargo.lock, crates.allow and vendor.sha256"
    ;;
  --relock)
    nts_toolchain_image
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    scratch_copy "$tmp"
    rm -f "$tmp/Cargo.lock"
    in_toolchain "$tmp" cargo generate-lockfile
    cp "$tmp/Cargo.lock" "$LOCK"
    rm -f "$TREE_SUM"
    log "trusted-time/rust/Cargo.lock written; crates:"
    lock_crates | awk '{ print "  " $1, $2 }' >&2
    check_lock
    ;;
  fetch)
    check_lock
    nts_toolchain_image
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    scratch_copy "$tmp"
    mkdir -p "$tmp/vendor"
    in_toolchain "$tmp" cargo vendor --locked --versioned-dirs vendor >"$tmp/vendor.log"
    rm -rf "$NTS_VENDOR_DIR"
    mkdir -p "$THIRD_PARTY"
    mv "$tmp/vendor" "$NTS_VENDOR_DIR"
    if [ ! -f "$TREE_SUM" ]; then
      tree_digest >"$TREE_SUM"
      log "recorded $TREE_SUM"
    fi
    check_vendor
    log "nts-vendor: $(lock_crates | wc -l) crates, $(du -sb "$NTS_VENDOR_DIR" | cut -f1) bytes unpacked, tree $(cut -c1-16 "$TREE_SUM")..."
    ;;
  *)
    echo "usage: fetch-nts.sh [--check|--relock]" >&2
    exit 2
    ;;
esac
