#!/usr/bin/env bash
# Builds everything and runs every local test. Exits non-zero on failure.
# Logs: logs/test-*.log, logs/e2e-*.log.
#
#   guards           scripts/check-imports.sh (module boundaries) and
#                    scripts/check-forbidden.sh (names and markers no file may hold)
#   release gate     scripts/release-gate-test.sh (the gate's own test) and
#                    release-gate.sh tree; build-runner.sh checks every binary
#                    and its dependencies against the forbid lists
#   dependencies     scripts/check-deps.sh (through build-runner.sh): no runner
#                    binary links the code of a cloud it does not run on
#   chains           scripts/chain-test.sh
#   modules          scripts/test-modules.sh: gofmt, vet and unit tests of every
#                    Go module, under the race detector
#   e2e (native)     tests/e2e against the static runners of build/<arch>/bin;
#                    TestE2EHandoverGate must run and pass
#   e2e (other arch) the static aarch64 runners under qemu-aarch64 (x86_64 hosts)
#   signer-core      its own suites (signer-core/scripts/test.sh: unit, SSZ and
#                    BLS vectors, EIP-3076, symbols, fuzz replay)
#   PCR3             scripts/kms-policy.sh self-test
#   deploy names     scripts/side-by-side-test.sh
#   fuzz             scripts/fuzz.sh: every Go fuzz target for FUZZ_TIME (3s)
#   clock check      runner-dev -clock-check against public HTTPS sites
#
# Every go test runs with -race (RACE= turns it off). NO_NETWORK=1 skips
# the tests that need public HTTPS.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
mkdir -p "$LOGS"
RACE="${RACE--race}"
export RACE

log "guards: module boundaries, forbidden names and markers"
bash "$ROOT/scripts/check-imports.sh"
bash "$ROOT/scripts/check-forbidden.sh"

bash "$ROOT/scripts/build-runner.sh"

log "release gate: self-test, and this tree's history holds no approver reset commit"
bash "$ROOT/scripts/release-gate-test.sh"
bash "$ROOT/scripts/release-gate.sh" tree "$ROOT"

log "chains: governance/chains/chain.sh and the chain checks of the image builds and deploy steps"
bash "$ROOT/scripts/chain-test.sh" >"$LOGS/test-chain.log" 2>&1 || { cat "$LOGS/test-chain.log"; exit 1; }
tail -n 1 "$LOGS/test-chain.log"

net=0
if [ "${NO_NETWORK:-0}" != 1 ] && curl -sfI --max-time 10 https://www.cloudflare.com/ >/dev/null; then
  net=1
fi

summary() {
  grep -E "^(--- |ok |FAIL|PASS$)|(e2e|cloud)_test.go:[0-9]+:" "$1" || true
}

bash "$ROOT/scripts/test-modules.sh"

# bin_env <arch>: the variables that name the runner binaries for tests/e2e.
bin_env() {
  local d="$BUILD/$1/bin"
  echo "RUNNER_BIN=$d/runner-dev" "RUNNER_DEBUG_BIN=$d/runner-dev-debugimport" \
    "RUNNER_AWS_BIN=$d/runner-aws" "RUNNER_AWS_DEBUG_BIN=$d/runner-aws-debugimport" \
    "RUNNER_AZURE_BIN=$d/runner-azure" "RUNNER_AZURE_DEBUG_BIN=$d/runner-azure-debugimport" \
    "RUNNER_GCP_BIN=$d/runner-gcp" "RUNNER_GCP_DEBUG_BIN=$d/runner-gcp-debugimport" "RUNNER_DKG_BIN=$d/runner-dev-dkg-dev"
}

log "e2e: static $HOST_ARCH runners"
# shellcheck disable=SC2046 # the variables of bin_env, split on purpose
(cd "$ROOT/tests" && env E2E_NETWORK="$net" $(bin_env "$HOST_ARCH") go test $RACE -count=1 -v -timeout 40m -tags platform_aws ./e2e/) \
  >"$LOGS/e2e-$HOST_ARCH.log" 2>&1 || { tail -80 "$LOGS/e2e-$HOST_ARCH.log"; exit 1; }
summary "$LOGS/e2e-$HOST_ARCH.log" | grep -E '^(ok|FAIL)'
grep -q -- "--- PASS: TestE2EHandoverGate " "$LOGS/e2e-$HOST_ARCH.log" && ! grep -q -- "--- SKIP: TestE2EHandoverGate" "$LOGS/e2e-$HOST_ARCH.log" ||
  { echo "TestE2EHandoverGate did not run and pass in the e2e set" >&2; exit 1; }

log "e2e: the Nitro runner's NTS clock through udprelay ($HOST_ARCH)"
# shellcheck disable=SC2046 # the variables of bin_env, split on purpose
(cd "$ROOT/tests" && env $(bin_env "$HOST_ARCH") UDPRELAY_BIN="$BUILD/$HOST_ARCH/bin/udprelay" \
  go test $RACE -count=1 -v -tags platform_aws,nts -run 'TestE2ENTS' ./e2e/) \
  >"$LOGS/e2e-nts-$HOST_ARCH.log" 2>&1 || { tail -80 "$LOGS/e2e-nts-$HOST_ARCH.log"; exit 1; }
summary "$LOGS/e2e-nts-$HOST_ARCH.log" | grep -E '^(ok|FAIL)'

if [ "$HOST_ARCH" = x86_64 ] && command -v qemu-aarch64 >/dev/null && [ -x "$BUILD/aarch64/bin/runner-dev" ]; then
  log "e2e: static aarch64 runners under qemu-aarch64"
  # shellcheck disable=SC2046 # the variables of bin_env, split on purpose
  (cd "$ROOT/tests" && env RUNNER_WRAPPER=qemu-aarch64 $(bin_env aarch64) \
    go test $RACE -count=1 -v -tags platform_aws -run 'TestE2E$|TestE2EClockSkewBreaksFloor|TestE2ESealedImport|TestE2EMutualTLS|TestE2EClientCertificateUsesTheRunnerClock|TestE2EVsockListenerIsTLS|TestE2ECloneSharedRecord|TestE2ECloudFlagChecks|TestE2EEachBinaryHasItsOwnPlatformOnly' ./e2e/) \
    >"$LOGS/e2e-aarch64-qemu.log" 2>&1 || { tail -80 "$LOGS/e2e-aarch64-qemu.log"; exit 1; }
  summary "$LOGS/e2e-aarch64-qemu.log" | grep -E '^(ok|FAIL)'
fi

log "signer-core: its own suites"
bash "$ROOT/signer-core/scripts/test.sh" >"$LOGS/test-signer-core-c.log" 2>&1 || { tail -40 "$LOGS/test-signer-core-c.log"; exit 1; }
grep -E '^(PASS|FAIL)' "$LOGS/test-signer-core-c.log"

bash "$ROOT/scripts/kms-policy.sh" self-test
bash "$ROOT/scripts/side-by-side-test.sh"

if [ "${FUZZ_TIME:-3s}" != 0 ]; then
  FUZZ_TIME="${FUZZ_TIME:-3s}" bash "$ROOT/scripts/fuzz.sh"
fi

if [ "$net" = 1 ]; then
  log "clock check: HTTPS Date quorum"
  "$BUILD/$HOST_ARCH/bin/runner-dev" -platform dev -state-dir "$BUILD/clock-check" -clock https-date \
    -clock-urls https://www.cloudflare.com/,https://www.google.com/,https://github.com/,https://kms.eu-west-1.amazonaws.com/,https://sts.googleapis.com/ \
    -clock-check 2>&1 | tee "$LOGS/clock-check.log" | tail -1
else
  log "no network: skipped HTTPS Date tests"
fi
log "ALL TESTS PASSED"
