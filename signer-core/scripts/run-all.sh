#!/usr/bin/env bash
# One command for the whole component: install deps, fetch pinned sources
# and vectors, build, test natively, cross-test aarch64 (on x86_64 hosts),
# run the Go cross-check if Go is present, and run the negative controls.
set -euo pipefail
SCRIPTS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

status=0
step() {
  echo "== $*"
  "$@" || status=1
}

[ "${SKIP_DEPS:-0}" = 1 ] || bash "$SCRIPTS/deps.sh"
bash "$SCRIPTS/fetch.sh"
step bash "$SCRIPTS/test.sh"
step bash "$SCRIPTS/cross-aarch64.sh"
step bash "$SCRIPTS/xcheck-go.sh"
step bash "$SCRIPTS/negative-controls.sh"
[ "$status" = 0 ] && echo "== ALL PASSED" || echo "== SOME STEPS FAILED"
exit $status
