#!/usr/bin/env bash
# Prints what CI tests for a change, as lines for $GITHUB_ENV. The jobs of
# .github/workflows/ci.yml read them; scripts/test.sh and
# scripts/test-modules.sh read them too, so a local run can mirror CI.
#
#   scripts/ci-scope.sh [BASE]   BASE as for scripts/affected.sh
#
# Prints:
#   CI_MODULES=   ALL, none, or the modules scripts/affected.sh prints
#   FUZZ_MODULES= the same, for scripts/fuzz.sh
#   CI_CORE=      1: the signer-core suites and the C fuzz targets run
#                 (a change to signer-core/, markformat/ or a shared input,
#                 so CI_MODULES=ALL)
#   CI_E2E=       1: the runner builds, the release gate, the chain and
#                 deploy checks and the e2e tests run (a module that goes
#                 into a runner changed, or tests/)
#   CI_E2E_GATEWAY= 1: the gateway e2e test runs (gateway/ or
#                 web3signer-api/ changed). With CI_E2E=1 it is 1 too: the
#                 full e2e run holds the gateway test.
#   CI_TESTS=     1: any of the above has work
# ALL when CI_ALL=1 or FUZZ_ALL=1, on any event but pull_request
# (GITHUB_EVENT_NAME), and when affected.sh prints ALL. The reason goes to
# stderr.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# The modules that go into a runner binary or test one.
RUNNER_MODULES=(tee-signer platform platform-aws platform-azure platform-gcp signer-protocol
  slashing-log governance attestation-verify signer-core trusted-time tests)
# The modules of the gateway that no runner holds.
GATEWAY_MODULES=(gateway web3signer-api)

# emit <modules> <core> <e2e> <gateway e2e> <tests>
emit() {
  printf 'CI_MODULES=%s\nFUZZ_MODULES=%s\nCI_CORE=%s\nCI_E2E=%s\nCI_E2E_GATEWAY=%s\nCI_TESTS=%s\n' "$1" "$1" "$2" "$3" "$4" "$5"
}

event="${GITHUB_EVENT_NAME:-}"
if [ -n "$event" ] && [ "$event" != pull_request ]; then
  log "ci-scope: event $event: ALL"
  CI_ALL=1
fi
m="$(CI_ALL="${CI_ALL:-0}" bash "$ROOT/scripts/affected.sh" "$@")"
case "$m" in
  ALL)
    log "ci-scope: every test runs"
    emit ALL 1 1 1 1 ;;
  "")
    log "ci-scope: only docs changed: no tests"
    emit none 0 0 0 0 ;;
  *)
    e2e=0
    for r in "${RUNNER_MODULES[@]}"; do
      [[ " $m " != *" $r "* ]] || { e2e=1; break; }
    done
    gw="$e2e"
    for g in "${GATEWAY_MODULES[@]}"; do
      [[ " $m " != *" $g "* ]] || gw=1
    done
    if [ "$e2e" = 1 ]; then
      log "ci-scope: modules $m; runner code changed: e2e runs; signer-core suites skipped"
    elif [ "$gw" = 1 ]; then
      log "ci-scope: modules $m; gateway code changed: the gateway e2e test runs; the other e2e tests and the signer-core suites skipped"
    else
      log "ci-scope: modules $m; no runner code changed: e2e and signer-core suites skipped"
    fi
    emit "$m" 0 "$e2e" "$gw" 1 ;;
esac
