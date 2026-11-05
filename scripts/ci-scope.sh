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
#   CI_TESTS=     1: any of the above has work
#   CI_AWS_TF=    1: the AWS Terraform checks run (scripts/tf-validate.sh,
#                 scripts/aws-tf-test.sh): a file under platform-aws/deploy/
#                 other than *.md changed, or those scripts,
#                 scripts/tf-providers.sh, scripts/common.sh (the Terraform
#                 image) or .github/workflows/ci.yml. 1 also when CI_ALL=1
#                 and when the diff cannot be made.
# ALL when CI_ALL=1 or FUZZ_ALL=1, on any event but pull_request
# (GITHUB_EVENT_NAME), and when affected.sh prints ALL. The reason goes to
# stderr.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# The modules that go into a runner binary or test one.
RUNNER_MODULES=(tee-signer platform platform-aws platform-azure platform-gcp signer-protocol
  slashing-log governance attestation-verify signer-core trusted-time tests)

emit() {
  printf 'CI_MODULES=%s\nFUZZ_MODULES=%s\nCI_CORE=%s\nCI_E2E=%s\nCI_TESTS=%s\nCI_AWS_TF=%s\n' "$1" "$1" "$2" "$3" "$4" "$aws_tf"
}

# aws_tf_changed [BASE]: the change touches the AWS Terraform module or its
# checks, or the diff cannot be made. BASE as for scripts/affected.sh.
aws_tf_changed() {
  local base files f
  if [ -n "${1:-}" ]; then
    base="$1"
  elif [ -n "${GITHUB_BASE_REF:-}" ]; then
    base="origin/$GITHUB_BASE_REF"
  else
    base=origin/main
  fi
  files="$(git -C "$ROOT" diff --name-only --no-renames "$base...HEAD" 2>/dev/null)" || return 0
  while IFS= read -r f; do
    case "$f" in
      *.md) ;;
      platform-aws/deploy/* | scripts/tf-validate.sh | scripts/aws-tf-test.sh | scripts/tf-providers.sh | \
        scripts/common.sh | .github/workflows/ci.yml) return 0 ;;
    esac
  done <<<"$files"
  return 1
}

event="${GITHUB_EVENT_NAME:-}"
if [ -n "$event" ] && [ "$event" != pull_request ]; then
  log "ci-scope: event $event: ALL"
  CI_ALL=1
fi
m="$(CI_ALL="${CI_ALL:-0}" bash "$ROOT/scripts/affected.sh" "$@")"
aws_tf=0
if [ "${CI_ALL:-0}" = 1 ] || aws_tf_changed "$@"; then
  aws_tf=1
  log "ci-scope: the AWS Terraform checks run"
fi
case "$m" in
  ALL)
    log "ci-scope: every test runs"
    emit ALL 1 1 1 ;;
  "")
    log "ci-scope: only docs changed: no tests"
    emit none 0 0 0 ;;
  *)
    e2e=0
    for r in "${RUNNER_MODULES[@]}"; do
      [[ " $m " != *" $r "* ]] || { e2e=1; break; }
    done
    if [ "$e2e" = 1 ]; then
      log "ci-scope: modules $m; runner code changed: e2e runs; signer-core suites skipped"
    else
      log "ci-scope: modules $m; no runner code changed: e2e and signer-core suites skipped"
    fi
    emit "$m" 0 "$e2e" 1 ;;
esac
