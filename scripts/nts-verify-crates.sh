#!/usr/bin/env bash
# Checks the crate archives of a cargo home against Cargo.lock. Each
# crates.io crate of the lock needs a .crate file in at least one folder of
# <cargo home>/registry/cache (one folder per registry index), and every file
# with a lock name, in any of these folders, must have the sha256 the lock
# names. Other files there are ignored and never used.
#
#   nts-verify-crates.sh <Cargo.lock> <cargo home>
#       check in place (fetch-nts.sh, on the host)
#   nts-verify-crates.sh <Cargo.lock> <cargo home> <new cargo home>
#       copy the files with lock names into <new cargo home>/registry/cache,
#       same folder names, and check the copies (nts-container.sh, from the
#       read-only host cache)
#
# Exit 0: all there and all match. 3: archives missing, none that differs
# (fetch-nts.sh then downloads them). 1: an archive differs from the lock.
# No network, no cargo: awk, sha256sum and cp only, so it runs on the host and
# in the toolchain image.
set -euo pipefail
[ $# -eq 2 ] || [ $# -eq 3 ] || { echo "usage: nts-verify-crates.sh <Cargo.lock> <cargo home> [<new cargo home>]" >&2; exit 2; }
lock="$1"
home="$2"
copy="${3:-}"

# "name-version.crate sha256" of each crate in the lock that has a checksum.
want="$(awk '
  /^\[\[package\]\]/ { n = v = "" }
  /^name = /         { n = $3; gsub(/"/, "", n) }
  /^version = /      { v = $3; gsub(/"/, "", v) }
  /^checksum = /     { c = $3; gsub(/"/, "", c); print n "-" v ".crate", c }
' "$lock" | LC_ALL=C sort)"
[ -n "$want" ] || { echo "$lock names no crates.io crate" >&2; exit 1; }

shopt -s nullglob
dirs=("$home"/registry/cache/*/)
[ ${#dirs[@]} -gt 0 ] || { echo "$home/registry/cache has no crate archives: run scripts/fetch-nts.sh" >&2; exit 3; }

# sums: "sha256  path" of every file to check, the copy in copy mode.
missing=0
files=0
sums=""
while read -r file sum; do
  found=0
  for dir in "${dirs[@]}"; do
    dir="${dir%/}"
    [ -f "$dir/$file" ] || continue
    found=1
    check="$dir"
    if [ -n "$copy" ]; then
      check="$copy/registry/cache/$(basename "$dir")"
      mkdir -p "$check"
      cp "$dir/$file" "$check/$file"
    fi
    sums+="$sum  $check/$file"$'\n'
    files=$((files + 1))
  done
  [ "$found" = 1 ] || { echo "$file is missing from $home/registry/cache" >&2; missing=1; }
done <<<"$want"
[ -z "$sums" ] || sha256sum --check --quiet --strict - <<<"${sums%$'\n'}" || {
  echo "a crate archive differs from its sha256 in Cargo.lock (changed, cut short or damaged)." >&2
  echo "Remove build/nts/cargo-home and run scripts/fetch-nts.sh again." >&2
  exit 1
}
[ "$missing" = 0 ] || { echo "crate archives are missing: run scripts/fetch-nts.sh" >&2; exit 3; }
echo "nts-verify-crates: $(wc -l <<<"$want") crate archives match Cargo.lock ($files files in ${#dirs[@]} registry folder(s))"
