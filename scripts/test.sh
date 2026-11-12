#!/usr/bin/env bash
# Builds everything and runs every local test. Exits non-zero on failure.
# Logs: logs/test-*.log, logs/e2e-*.log.
#
#   guards           scripts/check-imports.sh (module boundaries) and
#                    scripts/check-forbidden.sh (secrets no file may hold)
#   release gate     scripts/release-gate-test.sh (the gate's own test) and
#                    release-gate.sh tree; build-runner.sh checks every binary
#                    and its dependencies against the forbid lists
#   dependencies     scripts/check-deps.sh (through build-runner.sh): no runner
#                    binary links the code of a cloud it does not run on
#   chains           scripts/chain-test.sh
#   modules          scripts/test-modules.sh: gofmt, vet and unit tests of every
#                    Go module, under the race detector; the signer-admin
#                    tests that start a dev runner get the runner-dev of
#                    build/<arch>/bin (SIGNER_ADMIN_RUNNER)
#   e2e (native)     tests/e2e against the static runners of build/<arch>/bin
#   e2e (other arch) the static aarch64 runners under qemu-aarch64 (x86_64 hosts)
#   signer-core      its own suites (signer-core/scripts/test.sh: unit, SSZ and
#                    BLS vectors, EIP-3076, symbols, fuzz replay)
#   PCR3             scripts/kms-policy.sh self-test
#   EIF check        scripts/eif-check-test.sh
#   deploy names     scripts/side-by-side-test.sh
#   GCP deploy       scripts/gcp-deploy-test.sh: the public and private entries,
#                    the egress rules, a subnet of its own, a previous digest
#   AWS service      scripts/aws-parent-service-test.sh: the parent's systemd
#                    unit and its restart logic, with a fake nitro-cli
#   Azure template   scripts/azure-template-test.sh: the rendered group and
#                    its CCE policy with and without the optional parameters
#   fuzz             scripts/fuzz.sh: every Go fuzz target for FUZZ_TIME (3s),
#                    or those of FUZZ_MODULES; the C fuzz targets of markformat
#                    and signer-core run only when FUZZ_MODULES is unset or ALL
#
# Every go test runs with -race (RACE= turns it off).
#
# The variables of scripts/ci-scope.sh narrow the run; unset, everything
# runs. CI_MODULES picks the modules, CI_E2E=0 skips the runner builds and
# everything that needs them or checks them (release gate, EIF check,
# chains, e2e, PCR3, deploy names, GCP deploy, Azure template), CI_CORE=0 skips the signer-core suites.
# With CI_E2E=0, CI_E2E_GATEWAY=1 still runs the gateway e2e test
# (TestE2EGateway*) on a dev runner the test builds.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
mkdir -p "$LOGS"
RACE="${RACE--race}"
export RACE
e2e="${CI_E2E:-1}"
core="${CI_CORE:-1}"
gateway_e2e="${CI_E2E_GATEWAY:-1}"

log "guards: module boundaries, forbidden names and markers"
bash "$ROOT/scripts/check-imports.sh"
bash "$ROOT/scripts/check-forbidden.sh"

if [ "$e2e" = 1 ]; then
  bash "$ROOT/scripts/build-runner.sh"
  # The signer-admin tests start this dev runner (scripts/test-modules.sh
  # builds one when the build has no runner-dev, as with CHAIN=hoodi).
  if [[ " ${RUNNER_BINS[*]} " == *" runner-dev "* ]]; then
    export SIGNER_ADMIN_RUNNER="${SIGNER_ADMIN_RUNNER:-$BUILD/$HOST_ARCH/bin/runner-dev}"
  fi

  log "release gate: self-test, and this tree's history holds no forbidden commit"
  bash "$ROOT/scripts/release-gate-test.sh"
  bash "$ROOT/scripts/release-gate.sh" tree "$ROOT"

  log "eif-check: self-test on made-up EIF files"
  bash "$ROOT/scripts/eif-check-test.sh"

  log "chains: governance/chains/chain.sh and the chain checks of the image builds and deploy steps"
  bash "$ROOT/scripts/chain-test.sh" >"$LOGS/test-chain.log" 2>&1 || { cat "$LOGS/test-chain.log"; exit 1; }
  tail -n 1 "$LOGS/test-chain.log"
else
  log "CI_E2E=0: no runner code changed: skipped the runner builds, release gate, chains and e2e"
  if [ "$gateway_e2e" = 1 ]; then
    # The gateway's unit tests and its e2e test link the signer core (cgo).
    log "signer core for cgo: the gateway links it"
    bash "$ROOT/scripts/build-core.sh" "$HOST_ARCH"
  fi
fi

summary() {
  grep -E "^(--- |ok |FAIL|PASS$)|(e2e|cloud)_test.go:[0-9]+:" "$1" || true
}

bash "$ROOT/scripts/test-modules.sh"
# The tests behind the nts build tag (trusted-time/clock, trusted-time/nts,
# tee-signer, the e2e relay test): test-modules.sh runs none of them.
bash "$ROOT/scripts/test-nts.sh" "$HOST_ARCH"

# bin_env <arch>: the variables that name the runner binaries for tests/e2e.
bin_env() {
  local d="$BUILD/$1/bin"
  echo "RUNNER_BIN=$d/runner-dev" "RUNNER_DEBUG_BIN=$d/runner-dev-debugimport" \
    "RUNNER_AWS_BIN=$d/runner-aws" "RUNNER_AWS_DEBUG_BIN=$d/runner-aws-debugimport" \
    "RUNNER_AZURE_BIN=$d/runner-azure" "RUNNER_AZURE_DEBUG_BIN=$d/runner-azure-debugimport" \
    "RUNNER_GCP_BIN=$d/runner-gcp" "RUNNER_GCP_DEBUG_BIN=$d/runner-gcp-debugimport"
}

if [ "$e2e" = 1 ]; then
  log "e2e: static $HOST_ARCH runners"
  # shellcheck disable=SC2046 # the variables of bin_env, split on purpose
  (cd "$ROOT/tests" && env $(bin_env "$HOST_ARCH") go test $RACE -count=1 -v -timeout 40m -tags platform_aws ./e2e/) \
    >"$LOGS/e2e-$HOST_ARCH.log" 2>&1 || { tail -80 "$LOGS/e2e-$HOST_ARCH.log"; exit 1; }
  summary "$LOGS/e2e-$HOST_ARCH.log" | grep -E '^(ok|FAIL)'

  log "e2e: the Nitro runner's NTS clock through udprelay ($HOST_ARCH)"
  # shellcheck disable=SC2046 # the variables of bin_env, split on purpose
  (cd "$ROOT/tests" && env $(bin_env "$HOST_ARCH") UDPRELAY_BIN="$BUILD/$HOST_ARCH/bin/udprelay" \
    go test $RACE -count=1 -v -tags platform_aws,nts -run 'TestE2ENTS' ./e2e/) \
    >"$LOGS/e2e-nts-$HOST_ARCH.log" 2>&1 || { tail -80 "$LOGS/e2e-nts-$HOST_ARCH.log"; exit 1; }
  summary "$LOGS/e2e-nts-$HOST_ARCH.log" | grep -E '^(ok|FAIL)'

  log "e2e: the non-prod dev runners (hoodi, devnet, ci-test) start on their own chain only"
  (cd "$ROOT/tests" && go test $RACE -count=1 -v -timeout 20m -tags platform_aws,nonprod,chain_ci_test -run 'TestE2ENonProdChains' ./e2e/) \
    >"$LOGS/e2e-nonprod-$HOST_ARCH.log" 2>&1 || { tail -80 "$LOGS/e2e-nonprod-$HOST_ARCH.log"; exit 1; }
  summary "$LOGS/e2e-nonprod-$HOST_ARCH.log" | grep -E '^(ok|FAIL)'

  if [ "$HOST_ARCH" = x86_64 ] && command -v qemu-aarch64 >/dev/null && [ -x "$BUILD/aarch64/bin/runner-dev" ]; then
    log "e2e: static aarch64 runners under qemu-aarch64"
    # shellcheck disable=SC2046 # the variables of bin_env, split on purpose
    (cd "$ROOT/tests" && env RUNNER_WRAPPER=qemu-aarch64 $(bin_env aarch64) \
      go test $RACE -count=1 -v -tags platform_aws -run 'TestE2E$|TestE2EClockSkewBreaksFloor|TestE2ESealedImport|TestE2EMutualTLS|TestE2EClientCertificateUsesTheRunnerClock|TestE2EVsockListenerIsTLS|TestE2EMarkLogClone|TestE2ECloudFlagChecks|TestE2EEachBinaryHasItsOwnPlatformOnly' ./e2e/) \
      >"$LOGS/e2e-aarch64-qemu.log" 2>&1 || { tail -80 "$LOGS/e2e-aarch64-qemu.log"; exit 1; }
    summary "$LOGS/e2e-aarch64-qemu.log" | grep -E '^(ok|FAIL)'
  fi
elif [ "$gateway_e2e" = 1 ]; then
  log "e2e: the gateway only (CI_E2E_GATEWAY=1): TestE2EGateway on a dev runner it builds"
  (cd "$ROOT/tests" && go test $RACE -count=1 -v -timeout 20m -tags platform_aws -run 'TestE2EGateway' ./e2e/) \
    >"$LOGS/e2e-gateway-$HOST_ARCH.log" 2>&1 || { tail -80 "$LOGS/e2e-gateway-$HOST_ARCH.log"; exit 1; }
  summary "$LOGS/e2e-gateway-$HOST_ARCH.log" | grep -E '^(ok|FAIL)'
fi

if fuzz_everything; then
  make -C "$ROOT/markformat" fuzz FUZZ_SECONDS="${FUZZ_SECONDS:-3}" >"$LOGS/fuzz-markformat.log" 2>&1 || { tail -40 "$LOGS/fuzz-markformat.log"; exit 1; }
else
  log "C fuzz: skipped, FUZZ_MODULES=$FUZZ_MODULES leaves out signer-core and markformat"
  export FUZZ=0
fi

if [ "$core" = 1 ]; then
  log "signer-core: its own suites"
  bash "$ROOT/signer-core/scripts/test.sh" >"$LOGS/test-signer-core-c.log" 2>&1 || { tail -40 "$LOGS/test-signer-core-c.log"; exit 1; }
  grep -E '^(PASS|FAIL)' "$LOGS/test-signer-core-c.log"
else
  log "CI_CORE=0: signer-core, markformat and the shared inputs did not change: skipped the signer-core suites"
fi

if [ "$e2e" = 1 ]; then
  bash "$ROOT/scripts/kms-policy.sh" self-test
  bash "$ROOT/scripts/side-by-side-test.sh"
  bash "$ROOT/scripts/gcp-deploy-test.sh"
  bash "$ROOT/scripts/azure-template-test.sh"
fi

log "AWS parent service: the unit, restart after a failure, none after a stop"
bash "$ROOT/scripts/aws-parent-service-test.sh"

if [ "${FUZZ_TIME:-3s}" != 0 ]; then
  FUZZ_TIME="${FUZZ_TIME:-3s}" bash "$ROOT/scripts/fuzz.sh"
fi
log "ALL TESTS PASSED"
