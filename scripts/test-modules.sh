#!/usr/bin/env bash
# go vet and the unit tests of every Go module, each in its own folder with
# its own go.mod. Every go test runs under the race detector (RACE= turns it
# off). The end-to-end tests of the tests module need the runner binaries;
# scripts/test.sh runs them.
#
#   scripts/test-modules.sh [module ...]     default: every module
#
# Tags: the runner modules test with all four platform tags at once, as the
# platform packages need; tee-signer also with each tag alone (package main),
# with testnet and with the tags of a release runner.
# Logs: logs/test-<module>.log.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
mkdir -p "$LOGS"
RACE="${RACE--race}"
ALL_TAGS=platform_dev,platform_aws,platform_azure,platform_gcp

# vet_builds: go vet with the tags of every runner build, both flavours.
vet_builds() {
  local name tags
  for name in "${RUNNER_BINS[@]}"; do go vet -tags "$(runner_tags "$name")" ./... || return 1; done
  # shellcheck disable=SC2016 # the inner script's $1, expanded by the inner bash
  for tags in $(IMAGE_FLAVOR=testnet bash -c '. "$1"; for n in "${RUNNER_BINS[@]}"; do runner_tags "$n"; done' _ "$ROOT/scripts/common.sh"); do
    go vet -tags "$tags" ./... || return 1
  done
  go vet -tags "$ALL_TAGS" ./... && go vet -tags "$ALL_TAGS,debugimport" ./...
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
      go vet -tags testnet ./... && go test $RACE -count=1 -v -tags testnet ./setupwire ./setuptext ./flavor ./handoverorder || return 1 ;;
    tee-signer)
      vet_builds || return 1
      local tags
      for tags in "" platform_dev platform_aws platform_azure platform_gcp; do go test $RACE -count=1 -tags "$tags" . || return 1; done
      go test $RACE -count=1 -tags platform_dev,platform_azure,platform_gcp ./record ./attls || return 1
      go test $RACE -count=1 -v -tags "$ALL_TAGS" ./... || return 1
      go test $RACE -count=1 -tags "$ALL_TAGS,lockcheck" ./server ./state || return 1
      go test $RACE -count=1 -v -tags platform_dev,testnet . ./attls || return 1
      go test $RACE -count=1 -v -tags testnet -run 'Flavor|ImageCheck' ./server || return 1
      # The tags a release runner is built with (scripts/common.sh runner_tags).
      go test $RACE -count=1 -tags "$(runner_tags runner-dev)" ./server . || return 1 ;;
    platform|slashing-log|platform-aws|platform-azure|platform-gcp|trusted-time|signer-admin)
      # The operator tools and the clock build without the runner tags.
      case "$1" in trusted-time|signer-admin) ;; *) vet_builds || return 1 ;; esac
      go test $RACE -count=1 -v -tags "$ALL_TAGS" ./... || return 1 ;;
    attestation-verify)
      # The clients against the debug runners, when they are built.
      # Pass a debug runner only when it was built, so the tests skip instead of failing.
      local dbg=() b
      b="$BUILD/$HOST_ARCH/bin/runner-azure-debugimport"; [ -x "$b" ] && dbg+=(RUNNER_AZURE_DEBUG_BIN="$b")
      b="$BUILD/$HOST_ARCH/bin/runner-aws-debugimport"; [ -x "$b" ] && dbg+=(RUNNER_AWS_DEBUG_BIN="$b")
      env "${dbg[@]}" go test $RACE -count=1 -v ./... || return 1
      local p
      for p in azure aws gcp dev; do go test $RACE -count=1 -tags "verifierselect,platform_$p" ./runnerclient/verify || return 1; done ;;
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
[ ${#mods[@]} -gt 0 ] || mods=("${GO_MODULES[@]}")
for m in "${mods[@]}"; do
  start=$SECONDS
  if (checks "$m") >"$LOGS/test-$m.log" 2>&1; then
    log "$m: vet and tests passed ($((SECONDS - start)) s, $(grep -c '^ok ' "$LOGS/test-$m.log") package runs)"
  else
    tail -40 "$LOGS/test-$m.log"
    echo "test-modules: $m failed (log: logs/test-$m.log)" >&2
    exit 1
  fi
done
