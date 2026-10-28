#!/usr/bin/env bash
# The handover release gate (signer-protocol/docs/protocol.md, "Handover"): runs
# tests/e2e TestE2EHandoverGate, in which a dev release runner of this
# tree hands its shares over to another runner of this tree, which then
# hands over to a third, with signing above the mark after each step. It
# runs once per build flavour: the default build (runner-dev) and the
# testnet build (runner-dev-testnet, test with -tags testnet). The test
# must run and pass in both; a skip, a missing test or
# a failure fails the gate. On success it writes build/handover-gate.stamp with the source
# id of the tree (common.sh handover_source_id), which every image build
# checks (require_handover_gate in platform-azure/deploy/build-image.sh,
# platform-gcp/deploy/build-image.sh and scripts/nitro-eif.sh).
#
# The runners are built here from this tree into a temp dir, with the tags
# of runner-dev and runner-dev-testnet, linking the core libraries build/<arch>/lib already
# holds (run scripts/build-core.sh first if there are none). It does not
# touch build/core-src or build/<arch>/lib.
#
# Usage: scripts/handover-gate.sh
set -euo pipefail
# shellcheck source=common.sh
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
export PATH=/usr/local/go/bin:$PATH
[ -f "$BUILD/$HOST_ARCH/lib/libsigner_core.a" ] ||
  { echo "no core library in $BUILD/$HOST_ARCH/lib (run scripts/build-core.sh)" >&2; exit 1; }
rm -f "$HANDOVER_GATE_STAMP"
id="$(handover_source_id)"
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
mkdir -p "$LOGS"
# gate <flavour> <runner build> <variable that names it> <go test tags>
gate() {
  local flavour="$1" name="$2" var="$3" tags="$4" glog="$LOGS/handover-gate-$1.log" rc
  # The build overlay goes into the testnet build only, as in build-runner.sh.
  local ov=()
  [ "$flavour" != testnet ] || mapfile -t ov < <(go_overlay_flags)
  (cd "$ROOT/tee-signer" && CGO_ENABLED=1 go build -trimpath -buildvcs=false ${ov[@]+"${ov[@]}"} -tags "netgo,osusergo,$(runner_tags "$name")" \
    -ldflags "-s -w -buildid= -linkmode external -extldflags -static" -o "$out/$name" .)
  log "handover gate ($flavour): TestE2EHandoverGate on $name (log $glog)"
  set +e
  (cd "$ROOT/tests" && env "$var=$out/$name" go test -count=1 -v -timeout 15m -tags "$tags" -run '^TestE2EHandoverGate$' ./e2e) \
    >"$glog" 2>&1
  rc=$?
  set -e
  if [ "$rc" != 0 ]; then
    tail -n 40 "$glog" >&2
    echo "handover gate ($flavour): FAILED" >&2
    exit 1
  fi
  if grep -q -- '--- SKIP: TestE2EHandoverGate' "$glog" ||
    ! grep -q -- '--- PASS: TestE2EHandoverGate ' "$glog"; then
    echo "handover gate ($flavour): TestE2EHandoverGate did not run and pass (missing or skipped)" >&2
    exit 1
  fi
}
gate default runner-dev RUNNER_BIN ""
gate testnet runner-dev-testnet RUNNER_TESTNET_BIN testnet
# The sources must be the ones the test ran on.
[ "$(handover_source_id)" = "$id" ] || { echo "handover gate: the sources changed during the run" >&2; exit 1; }
mkdir -p "$BUILD"
printf '%s\n' "$id" >"$HANDOVER_GATE_STAMP"
log "handover gate: passed on sources $id ($(git -C "$ROOT" rev-parse --short HEAD)); stamp $HANDOVER_GATE_STAMP"
