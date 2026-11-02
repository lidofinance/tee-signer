#!/usr/bin/env bash
# NTS PoC from source to test: the Rust library for both architectures,
# the runners with the tag nts, the Go test (tag nts) on each architecture, and
# the end-to-end suite of the runner with the tagged binaries. The x86_64 tests
# run here, the aarch64 ones under qemu-aarch64. Exits non-zero on failure.
# Logs: logs/nts-*.log. Nothing is written to build/<arch>/bin. build-core.sh
# builds libsigner_core.a and libblst.a the way it always does.
#
# Usage: test-nts.sh [x86_64|aarch64 ...]   default: same arch list as build-core.sh
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
mkdir -p "$LOGS"

archs=("$@")
if [ ${#archs[@]} -eq 0 ]; then
  archs=("$HOST_ARCH")
  for a in x86_64 aarch64; do
    [ "$a" = "$HOST_ARCH" ] && continue
    command -v "$(cc_for "$a")" >/dev/null 2>&1 && archs+=("$a")
  done
fi

# qemu_for <arch>: the program that runs <arch> binaries here, empty for the host arch.
qemu_for() {
  if [ "$1" = "$HOST_ARCH" ]; then return 0; fi
  command -v "qemu-$1" >/dev/null 2>&1 || { echo "test-nts: qemu-$1 is not installed" >&2; return 1; }
  echo "qemu-$1"
}

# bin_env <arch>: the variables that name the runner binaries for tests/e2e,
# the same as in test.sh, with the binaries built with the tag nts.
bin_env() {
  local d="$NTS_OUT/$1/bin"
  echo "RUNNER_BIN=$d/runner-dev-nts" "RUNNER_DEBUG_BIN=$d/runner-dev-debugimport-nts" \
    "RUNNER_AWS_BIN=$d/runner-aws-nts" "RUNNER_AWS_DEBUG_BIN=$d/runner-aws-debugimport-nts" \
    "RUNNER_AZURE_BIN=$d/runner-azure-nts" "RUNNER_AZURE_DEBUG_BIN=$d/runner-azure-debugimport-nts" \
    "RUNNER_GCP_BIN=$d/runner-gcp-nts"
}

bash "$ROOT/scripts/build-core.sh" "${archs[@]}"
bash "$ROOT/scripts/build-nts.sh" "${archs[@]}"
bash "$ROOT/scripts/build-runner-nts.sh" "${archs[@]}"

log "nts: gofmt and vet (tag nts)"
( (cd "$ROOT/tee-signer" && [ -z "$(gofmt -l nts_on.go nts_servers_debug.go nts_servers_release.go platforms_nts.go)" ] &&
    go vet -tags netgo,osusergo,platform_dev,nts . && go vet -tags netgo,osusergo,platform_aws,platform_dev,debugimport,nts . &&
    CGO_ENABLED=1 go test -count=1 -tags netgo,osusergo,platform_dev,nts -run 'NTS' .) &&
  (cd "$ROOT/trusted-time" && [ -z "$(gofmt -l nts clock)" ] && go vet -tags netgo,osusergo,nts ./...) &&
  (cd "$ROOT/platform-aws" && [ -z "$(gofmt -l udprelay nitro)" ] && go vet -tags netgo,osusergo,platform_aws,platform_dev,debugimport,nts ./nitro) &&
  (cd "$ROOT/tests" && [ -z "$(gofmt -l e2e)" ] && go vet -tags netgo,osusergo,platform_aws,platform_dev,debugimport,nts ./e2e) ) \
  >"$LOGS/nts-vet.log" 2>&1 || { cat "$LOGS/nts-vet.log"; exit 1; }

for arch in "${archs[@]}"; do
  qemu="$(qemu_for "$arch")"
  bin="$NTS_OUT/$arch/bin"
  # The test binary is static and stripped, like the runner. Without -s the
  # glibc linker prints warnings about getaddrinfo and getpwuid_r, which the
  # standard library of Rust refers to in code that nothing calls.
  # The old binary goes first: go test -c keeps a file at -o whose build ID
  # matches, and that ID does not cover libsigner_nts.a, so a new library
  # would not get linked in. (The runners are built with -buildid=, so their
  # build relinks every time.)
  rm -f "$bin/nts.test" "$bin/clock-nts.test"
  for pkg in nts clock; do
    out="$bin/nts.test"
    [ "$pkg" = clock ] && out="$bin/clock-nts.test"
    (cd "$ROOT/trusted-time" && CGO_ENABLED=1 GOOS=linux GOARCH="$(goarch_of "$arch")" CC="$(cc_for "$arch")" \
      go test -c -trimpath -tags netgo,osusergo,nts -ldflags "-s -w -linkmode external -extldflags -static" -o "$out" "./$pkg")
    case "$(file -b "$out")" in *"statically linked"*) ;; *) echo "test-nts: $out is not static" >&2; exit 1 ;; esac
  done

  log "nts: Go tests (tag nts) of trusted-time/nts and trusted-time/clock on $arch${qemu:+ under $qemu}"
  # The test starts the runner built with the tag. For another arch the
  # test itself runs under qemu, and the binfmt entry of qemu-user-static runs
  # the runner it starts. The KE and NTP tests use loopback servers
  # (trusted-time/nts/ntstest). The interop test with public servers skips here
  # (scripts/nts-interop.sh runs it).
  (cd "$ROOT/trusted-time/nts" && RUNNER_NTS_BIN="$bin/runner-dev-nts" $qemu "$bin/nts.test" -test.v -test.count=1 &&
    cd .. &&
    cd clock && $qemu "$bin/clock-nts.test" -test.v -test.count=1) \
    >"$LOGS/nts-test-$arch.log" 2>&1 || { tail -40 "$LOGS/nts-test-$arch.log"; exit 1; }
  grep -E '^(--- |ok|PASS|FAIL)|signer-nts' "$LOGS/nts-test-$arch.log" | sed "s/^/  [$arch] /"

  log "nts: -nts-selftest of every runner build with the tag, on $arch"
  for name in "${RUNNER_BINS[@]}"; do
    $qemu "$bin/$name-nts" -nts-selftest | sed "s/^/  [$arch] $name-nts: /"
  done
done

# The end-to-end suite with the tagged runners: the library in the binary must
# not disturb the Go runtime (threads, signals, the cgo C core next to it).
log "nts: e2e with the runners built with the tag, $HOST_ARCH"
# shellcheck disable=SC2046 # the variables of bin_env, split on purpose
(cd "$ROOT/tests" && env $(bin_env "$HOST_ARCH") go test -count=1 -v -tags platform_aws,nts ./e2e/) \
  >"$LOGS/nts-e2e-$HOST_ARCH.log" 2>&1 || { tail -80 "$LOGS/nts-e2e-$HOST_ARCH.log"; exit 1; }
grep -E "^(--- |ok |FAIL|PASS$)" "$LOGS/nts-e2e-$HOST_ARCH.log" | sed "s/^/  [$HOST_ARCH] /"
if [ "$HOST_ARCH" = x86_64 ] && command -v qemu-aarch64 >/dev/null && [ -x "$NTS_OUT/aarch64/bin/runner-dev-nts" ]; then
  log "nts: e2e with the runners built with the tag, aarch64 under qemu-aarch64"
  # shellcheck disable=SC2046 # the variables of bin_env, split on purpose
  (cd "$ROOT/tests" && env RUNNER_WRAPPER=qemu-aarch64 $(bin_env aarch64) \
    go test -count=1 -v -tags platform_aws -run 'TestE2E$|TestE2EClockSkewBreaksFloor|TestE2ESealedImport|TestE2EMutualTLS|TestE2EClientCertificateUsesTheRunnerClock|TestE2EVsockListenerIsTLS|TestE2ECloneSharedRecord|TestE2ECloudFlagChecks|TestE2EEachBinaryHasItsOwnPlatformOnly' ./e2e/) \
    >"$LOGS/nts-e2e-aarch64-qemu.log" 2>&1 || { tail -80 "$LOGS/nts-e2e-aarch64-qemu.log"; exit 1; }
  grep -E "^(--- |ok |FAIL|PASS$)" "$LOGS/nts-e2e-aarch64-qemu.log" | sed "s/^/  [aarch64] /"
fi
log "NTS TESTS PASSED"
