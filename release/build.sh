#!/usr/bin/env bash
# Runs inside the release builder (release/builder.Dockerfile), at the root
# of a clean checkout, with network:
#
#   release/build.sh fetch   Go modules of the release binaries into GOMODCACHE
#                            (network: the Go proxy, checked against go.sum)
#
# The build itself is scripts/build-runner.sh, which run_build_runner
# (scripts/common.sh) runs in the builder offline, on that module cache.
set -euo pipefail
umask 022
ROOT="$(pwd)"
[ -f "$ROOT/scripts/common.sh" ] || { echo "release/build.sh: run it at the repo root" >&2; exit 2; }

# The modules whose binaries a release ships.
MODULES=(tee-signer platform-aws signer-admin)

cmd_fetch() {
  local m
  for m in "${MODULES[@]}"; do
    (cd "$ROOT/$m" && go mod download)
  done
  # Every module zip in the cache matches go.sum (GOSUMDB checked it on download).
  (cd "$ROOT/tee-signer" && go mod verify)
}

case "${1:-}" in
  fetch) cmd_fetch ;;
  *) sed -n '2,/^set -euo/p' "$0" | sed '$d;s/^# \{0,1\}//' >&2; exit 2 ;;
esac
