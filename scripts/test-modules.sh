#!/usr/bin/env bash
# go vet and the unit tests of every Go module, each in its own folder with
# its own go.mod. Every go test runs under the race detector (RACE= turns it
# off). The end-to-end tests of the tests module need the runner binaries;
# scripts/test.sh runs them.
#
#   scripts/test-modules.sh [module ...]     default: CI_MODULES, else every module
#
# CI_MODULES (scripts/ci-scope.sh): unset or ALL for every module, none for
# no module, else the modules to test, separated by spaces.
#
# Tags: the runner modules test with all four platform tags at once, as the
# platform packages need; tee-signer also with each tag alone (package main),
# with the tags of each non-prod chain and with the tags of a release runner.
# The signer-admin tests start a dev runner: SIGNER_ADMIN_RUNNER, else one
# built here (dev_runner).
# Logs: logs/test-<module>.log (tooling/<name>: logs/test-tooling-<name>.log).
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
mkdir -p "$LOGS"
RACE="${RACE--race}"
ALL_TAGS=platform_dev,platform_aws,platform_azure,platform_gcp

# NONPROD_CHAINS are the chains of the non-prod builds (common.sh).
NONPROD_CHAINS=()
for c in $CHAINS; do chain_is_prod "$c" || NONPROD_CHAINS+=("$c"); done

# vet_builds: go vet with the tags of every runner build, of every chain.
vet_builds() {
  local name tags c
  for name in "${RUNNER_BINS[@]}"; do go vet -tags "$(runner_tags "$name")" ./... || return 1; done
  for c in "${NONPROD_CHAINS[@]}"; do
    # shellcheck disable=SC2016 # the inner script's $1, expanded by the inner bash
    for tags in $(CHAIN="$c" bash -c '. "$1"; for n in "${RUNNER_BINS[@]}"; do runner_tags "$n"; done' _ "$ROOT/scripts/common.sh"); do
      go vet -tags "$tags" ./... || return 1
    done
  done
  go vet -tags "$ALL_TAGS" ./... && go vet -tags "$ALL_TAGS,debugimport" ./...
}

# dev_runner: prints the dev runner the signer-admin tests start. That is
# SIGNER_ADMIN_RUNNER when set (scripts/test.sh sets it to the runner-dev
# of scripts/build-runner.sh), else a runner-dev built here for this
# machine, as build-runner.sh builds it but not static.
dev_runner() {
  if [ -n "${SIGNER_ADMIN_RUNNER:-}" ]; then
    echo "$SIGNER_ADMIN_RUNNER"
    return
  fi
  local bin="$BUILD/$HOST_ARCH/test-bin/runner-dev"
  mkdir -p "$(dirname "$bin")" || return 1
  (cd "$ROOT/tee-signer" && CGO_ENABLED=1 CC="$(cc_for "$HOST_ARCH")" \
    go build -trimpath -buildvcs=false -tags "$(runner_tags runner-dev)" -o "$bin" .) >&2 || return 1
  echo "$bin"
}

# checks <module>: every command ends in "|| return 1"; set -e does not apply
# in a function on the left of ||.
checks() {
  cd "$ROOT/$1" || return 1
  [ -z "$(gofmt -l . | grep -v '^third_party/' || true)" ] || { echo "gofmt: $(gofmt -l .)"; return 1; }
  go vet ./... || return 1
  case "$1" in
    markformat)
      make test || return 1
      go test $RACE -count=1 -v ./... || return 1 ;;
    signer-protocol)
      go test $RACE -count=1 -v ./... || return 1
      go vet -tags platform_aws ./... && go test $RACE -count=1 -v -tags platform_aws ./transport || return 1 ;;
    governance)
      go test $RACE -count=1 -v ./... || return 1
      local c
      for c in "${NONPROD_CHAINS[@]}"; do
        go vet -tags "$(chain_tags "$c")" ./... && go test $RACE -count=1 -v -tags "$(chain_tags "$c")" ./setupwire ./setuptext ./runnerchain || return 1
      done ;;
    tee-signer)
      vet_builds || return 1
      local tags
      for tags in "" platform_dev platform_aws platform_azure platform_gcp; do go test $RACE -count=1 -tags "$tags" . || return 1; done
      go test $RACE -count=1 -tags platform_dev,platform_azure,platform_gcp ./attls || return 1
      go test $RACE -count=1 -v -tags "$ALL_TAGS" ./... || return 1
      go test $RACE -count=1 -tags "$ALL_TAGS,lockcheck" ./server ./state || return 1
      local c
      for c in "${NONPROD_CHAINS[@]}"; do
        go test $RACE -count=1 -v -tags "platform_dev,$(chain_tags "$c")" . ./attls || return 1
        go test $RACE -count=1 -v -tags "$(chain_tags "$c")" -run 'NamesTheBuild|ImageCheck|RoleTable' ./server || return 1
      done
      # The tags a release runner is built with (scripts/common.sh runner_tags).
      go test $RACE -count=1 -tags "$(runner_tags runner-dev)" ./server . || return 1 ;;
    trusted-time)
      # The clock builds without the runner tags; the NTS client has code
      # with the tag nts only (the cloud runners' build). Its C core is
      # the archive ntscore/c/Makefile builds freestanding and checks for
      # outside symbols; the Go binding links it. The core's tests run
      # once more under the sanitizers (an archive built with them), which
      # exclude the race detector, and, where the cross compiler and
      # qemu-user are installed (scripts/deps.sh on x86_64), once on the
      # other architecture: the AES is hand-written and the arithmetic
      # 128-bit, so one architecture's pass does not vouch for the other.
      go test $RACE -count=1 -v ./... || return 1
      make -C ntscore/c check || return 1
      go vet -tags nts ./... && go test $RACE -count=1 -v -tags nts ./... || return 1
      make -C ntscore/c asan || return 1
      go test -asan -count=1 -tags nts ./ntscore/go ./nts || return 1
      # COV=1: the C core's line coverage by its Go tests (gcov).
      if [ "${COV:-0}" = 1 ]; then
        make -C ntscore/c cov || return 1
        go test -count=1 -tags nts,ntscov ./ntscore/go ./nts || return 1
        make -C ntscore/c cov-report || return 1
      fi
      local other qemu
      case "$HOST_ARCH" in x86_64) other=aarch64; qemu=qemu-aarch64 ;; *) other=x86_64; qemu=qemu-x86_64 ;; esac
      if command -v "$(cc_for "$other")" >/dev/null 2>&1 && command -v "$qemu" >/dev/null 2>&1; then
        make -C ntscore/c lib ARCH="$other" CC="$(cc_for "$other")" || return 1
        CGO_ENABLED=1 GOOS=linux GOARCH="$(goarch_of "$other")" CC="$(cc_for "$other")" \
          go test -c -tags nts -ldflags '-linkmode external -extldflags -static' -o "$LOGS/ntscore-$other.test" ./ntscore/go || return 1
        (cd ntscore/go && "$qemu" "$LOGS/ntscore-$other.test" -test.short -test.count=1) || return 1
        log "trusted-time: ntscore tests passed on $other under $qemu"
      else
        log "trusted-time: no cross compiler or $qemu for $other, the ntscore tests ran on $HOST_ARCH only"
      fi ;;
    platform|slashing-log|platform-aws|platform-azure|platform-gcp)
      vet_builds || return 1
      go test $RACE -count=1 -v -tags "$ALL_TAGS" ./... || return 1 ;;
    signer-admin)
      # The operator tools build without the runner tags. Some tests drive
      # a real dev runner (SIGNER_ADMIN_RUNNER).
      local runner
      runner="$(dev_runner)" || return 1
      SIGNER_ADMIN_RUNNER="$runner" go test $RACE -count=1 -v -tags "$ALL_TAGS" ./... || return 1 ;;
    attestation-verify)
      # The clients against the debug runners, when they are built.
      # Pass a debug runner only when it was built, so the tests skip instead of failing.
      local dbg=() b
      b="$BUILD/$HOST_ARCH/bin/runner-azure-debugimport"; [ -x "$b" ] && dbg+=(RUNNER_AZURE_DEBUG_BIN="$b")
      b="$BUILD/$HOST_ARCH/bin/runner-aws-debugimport"; [ -x "$b" ] && dbg+=(RUNNER_AWS_DEBUG_BIN="$b")
      env "${dbg[@]}" go test $RACE -count=1 -v ./... || return 1 ;;
    devkit)
      go test $RACE -count=1 -v ./... || return 1
      go test $RACE -count=1 -tags lockcheck ./lockorder || return 1 ;;
    tests)
      go vet -tags platform_aws ./... || return 1 ;;
    *)
      go test $RACE -count=1 -v ./... || return 1 ;;
  esac
}

mods=("$@")
if [ ${#mods[@]} -eq 0 ]; then
  case "${CI_MODULES:-ALL}" in
    ALL) mods=("${GO_MODULES[@]}") ;;
    none) log "test-modules: CI_MODULES=none, no module to test"; exit 0 ;;
    *)
      read -r -a mods <<<"$CI_MODULES"
      for m in "${mods[@]}"; do
        [[ " ${GO_MODULES[*]} " == *" $m "* ]] || { echo "CI_MODULES: $m is not a Go module of this repo" >&2; exit 1; }
      done
      log "test-modules: only ${mods[*]} (CI_MODULES)" ;;
  esac
fi
for m in "${mods[@]}"; do
  start=$SECONDS
  # tooling/<name> logs to test-tooling-<name>.log.
  lf="test-${m//\//-}.log"
  if (checks "$m") >"$LOGS/$lf" 2>&1; then
    log "$m: vet and tests passed ($((SECONDS - start)) s, $(grep -c '^ok ' "$LOGS/$lf") package runs)"
  else
    tail -40 "$LOGS/$lf"
    echo "test-modules: $m failed (log: logs/$lf)" >&2
    exit 1
  fi
done
