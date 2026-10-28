#!/usr/bin/env bash
# Self-test for portability: copies the component (sources only, no build
# outputs, no vectors) to build/fresh-copy/repo/signer-core, a different
# repo root with an empty third_party/, and runs run-all.sh there.
# Already downloaded release tarballs are hard-linked in so the test does
# not download 490 MB again.
set -euo pipefail
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$SRC/build/fresh-copy/repo"
rm -rf "$SRC/build/fresh-copy"
mkdir -p "$ROOT/signer-core"
(cd "$SRC" && tar --exclude=./build --exclude=./vectors --exclude=./logs -cf - .) |
  tar -xf - -C "$ROOT/signer-core"
if [ -d "$SRC/vectors/downloads" ]; then
  mkdir -p "$ROOT/signer-core/vectors/downloads"
  cp -rl "$SRC/vectors/downloads/." "$ROOT/signer-core/vectors/downloads/"
fi
bash "$ROOT/signer-core/scripts/run-all.sh"
# shellcheck disable=SC2012 # listing for the reader only
echo "fresh copy used repo root $ROOT; third_party now has: $(ls "$ROOT/third_party" | tr '\n' ' ')"
