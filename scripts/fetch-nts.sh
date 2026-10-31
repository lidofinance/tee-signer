#!/usr/bin/env bash
# Fetches the Rust crates of trusted-time/rust/Cargo.lock from crates.io into
# build/nts/cargo-home (NTS_CARGO_HOME), the download cache that build-nts.sh
# mounts read-only into its offline build container. The pin is Cargo.lock,
# which names the sha256 of every crate archive.
#
# Checks, in this order:
#   1. Cargo.lock holds the crates of trusted-time/rust/crates.allow (name and
#      version) and no others, all from the crates.io registry (every mode).
#   2. nts-verify-crates.sh checks each archive in the cache against its
#      sha256 in Cargo.lock. If all are there and match, nothing is fetched.
#      If some are missing, cargo fetch --locked downloads them (cargo checks
#      the sha256 of what it downloads) and nts-verify-crates.sh runs again.
#      An archive that differs stops the script before cargo runs.
#   3. The extracted sources (registry/src) are deleted: nothing reads them.
#      The registry index files stay a download aid for cargo fetch; no build
#      reads them. nts-container.sh checks the archives again in the build
#      container and builds from them alone.
#
# The first build needs a network once. make clean removes build/, and with it
# the cache.
#
#   fetch-nts.sh            check the lock and the archives, fetch the missing
#                           ones (network, docker), check them again
#   fetch-nts.sh --check    check the lock only (no network, no docker; make check)
#   fetch-nts.sh --relock   resolve the crates again into trusted-time/rust/Cargo.lock (network,
#                           index files only, no crate files), then check the list.
#                           Review the diff, edit trusted-time/rust/crates.allow, run fetch-nts.sh.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

LOCK="$NTS_DIR/Cargo.lock"
ALLOW="$NTS_DIR/crates.allow"
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
    echo "Cargo.lock and trusted-time/rust/crates.allow differ (< lock, > allow list). Do not fetch: review the crates." >&2
    return 1
  fi
}

# in_toolchain <dir to mount at /work> <docker run options...> -- <command...>:
# cargo as the calling user, with a network.
in_toolchain() {
  local work="$1"
  shift
  local opts=()
  while [ $# -gt 0 ] && [ "$1" != -- ]; do opts+=("$1"); shift; done
  [ $# -gt 0 ] || { echo "in_toolchain: no -- before the command" >&2; return 2; }
  shift
  docker run --rm --pull=never --user "$(id -u):$(id -g)" \
    -e HOME=/tmp/home -e CARGO_HOME=/tmp/cargo-home -e CARGO_NET_RETRY=3 \
    -v "$work:/work" -w /work "${opts[@]}" "$NTS_IMAGE" "$@"
}

# scratch_copy <dir>: the workspace (the root crate, core/, nostd-check/), so
# that cargo writes nothing into the tree.
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
    log "nts crates: Cargo.lock matches crates.allow"
    ;;
  --relock)
    nts_toolchain_image
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    scratch_copy "$tmp"
    rm -f "$tmp/Cargo.lock"
    in_toolchain "$tmp" -- cargo generate-lockfile
    cp "$tmp/Cargo.lock" "$LOCK"
    log "trusted-time/rust/Cargo.lock written; crates:"
    lock_crates | awk '{ print "  " $1, $2 }' >&2
    check_lock
    ;;
  fetch)
    check_lock
    mkdir -p "$NTS_CARGO_HOME"
    # cargo fetch trusts archives already in the cache, so check them first:
    # 0 all there and matching, 3 some missing, anything else stops here.
    rc=0
    bash "$ROOT/scripts/nts-verify-crates.sh" "$LOCK" "$NTS_CARGO_HOME" >&2 || rc=$?
    if [ "$rc" = 3 ]; then
      nts_toolchain_image
      tmp="$(mktemp -d)"
      trap 'rm -rf "$tmp"' EXIT
      scratch_copy "$tmp"
      in_toolchain "$tmp" -v "$NTS_CARGO_HOME:/tmp/cargo-home" -- cargo fetch --locked
      rc=0
      bash "$ROOT/scripts/nts-verify-crates.sh" "$LOCK" "$NTS_CARGO_HOME" >&2 || rc=$?
      if [ "$rc" = 3 ]; then
        echo "cargo fetch did not add the missing archives: remove $NTS_CARGO_HOME and run scripts/fetch-nts.sh again" >&2
      fi
      [ "$rc" = 0 ] || exit "$rc"
    elif [ "$rc" != 0 ]; then
      exit "$rc"
    fi
    rm -rf "$NTS_CARGO_HOME/registry/src"
    log "nts crates: $(lock_crates | wc -l) crates of Cargo.lock in $NTS_CARGO_HOME"
    ;;
  *)
    echo "usage: fetch-nts.sh [--check|--relock]" >&2
    exit 2
    ;;
esac
