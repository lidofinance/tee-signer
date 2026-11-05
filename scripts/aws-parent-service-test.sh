#!/usr/bin/env bash
# platform-aws/deploy/signer-runner.service and parent-service.sh, with a
# fake nitro-cli and a fake parent-run.sh. No enclave, no systemd unit is
# started, nothing outside a temp folder is written.
#
#   unit      systemd-analyze verify of the unit with its paths moved to the
#             temp folder (skipped, with a line saying so, without
#             systemd-analyze), and the settings the restart rules rest on:
#             start at boot after the allocator and the network, restart on
#             failure with no start limit, no restart on exit 3, SIGTERM to
#             the main process alone, the settings from an EnvironmentFile
#   start     a start with nothing running starts parent-run.sh once: one
#             enclave and one set of parent tools (the boot path); hostagent
#             starts 1 s after parent-run.sh returns, and run waits for it
#   crash     the enclave ends with a line in last-exit.txt: run exits 1
#             with that line, the tools are stopped, the failure count is 1;
#             the next run waits BACKOFF_BASE, a later one twice that, up to
#             BACKOFF_MAX
#   tool      a parent tool ends: run exits 1 and terminates the enclave
#   missing   a parent tool that never starts: run exits 1 after START_WAIT
#             and terminates the enclave
#   stop      SIGTERM (systemctl stop): run exits 0, the enclave is
#             terminated, the tools are stopped
#   refused   an enclave or a parent tool already running: run exits 3 and
#             touches neither; cleanup leaves the enclave alone
#   cleanup   after a run killed with SIGKILL, cleanup terminates the
#             enclave it started
# shellcheck disable=SC2016 # wait_for evaluates its condition later
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
cleanup_all() {
  pkill -9 -f "$work/" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup_all EXIT
fail=0
bad() { echo "FAIL $*"; fail=1; }
ok() { echo "ok   $*"; }
has() { grep -q -F -- "$1" <<<"$2"; }

UNIT="$ROOT/platform-aws/deploy/signer-runner.service"
mkdir -p "$work/opt" "$work/bin" "$work/tools" "$work/fake" "$work/state" "$work/run" "$work/etc"
cp "$ROOT/platform-aws/deploy/parent-service.sh" "$work/opt/"

# ---- unit -------------------------------------------------------------------
u="$(cat "$UNIT")"
for line in "Wants=network-online.target nitro-enclaves-allocator.service" \
  "After=network-online.target nitro-enclaves-allocator.service" \
  "WantedBy=multi-user.target" "Restart=on-failure" "RestartPreventExitStatus=3" \
  "KillMode=mixed" \
  "EnvironmentFile=/etc/signer-runner/parent.env" \
  "ExecStart=/opt/signer-runner/parent-service.sh run" \
  "ExecStopPost=/opt/signer-runner/parent-service.sh cleanup" \
  "RuntimeDirectoryPreserve=restart"; do
  grep -q -x -F -- "$line" <<<"$u" || bad "unit: no line $line"
done
grep -q -x "StartLimitIntervalSec=0" <<<"$u" && ! grep -q "^StartLimitBurst=" <<<"$u" || bad "unit: a start limit"
grep -q -E "^RestartSec=[1-9][0-9]*$" <<<"$u" || bad "unit: no RestartSec"
# Settings come from the EnvironmentFile, none on a command line.
grep -E '^(Exec[A-Za-z]*|Environment)=' <<<"$u" | grep -q -E 'SETUP|STATE_DIR|EIF' && bad "unit: a setting on a command line or in Environment="
ok "unit: boot order, restart rules and settings file"
if command -v systemd-analyze >/dev/null; then
  : >"$work/etc/parent.env"
  sed -e "s|/opt/signer-runner/|$work/opt/|g" -e "s|/etc/signer-runner/|$work/etc/|" \
    -e "s|^User=.*|User=$(id -un)|" "$UNIT" >"$work/signer-runner.service"
  # Units the parent has and this machine may not: stubs next to the unit.
  printf '[Unit]\nDescription=stub\n[Service]\nExecStart=/bin/true\n' >"$work/nitro-enclaves-allocator.service"
  if v="$(SYSTEMD_UNIT_PATH="$work:" systemd-analyze verify --man=no "$work/signer-runner.service" 2>&1)"; then
    ok "unit: systemd-analyze verify"
  else
    bad "unit: systemd-analyze verify: $v"
  fi
else
  echo "skip unit: no systemd-analyze"
fi

# ---- fakes ------------------------------------------------------------------
# nitro-cli: one enclave at most, its state in fake/enclave; calls logged.
cat >"$work/bin/nitro-cli" <<'X'
#!/usr/bin/env bash
f="$FAKE/enclave"
echo "$*" >>"$FAKE/nitro-cli.calls"
case "$1" in
  describe-enclaves)
    if [ -f "$f" ]; then
      printf '[\n  {\n    "EnclaveName": "runner",\n    "EnclaveID": "%s",\n    "EnclaveCID": 16,\n    "State": "RUNNING",\n    "Flags": "NONE"\n  }\n]\n' "$(cat "$f")"
    else
      echo "[]"
    fi ;;
  run-enclave)
    [ ! -f "$f" ] || { echo "an enclave is already running" >&2; exit 1; }
    echo "i-0-enc$RANDOM" >"$f"; echo "started" >>"$FAKE/starts" ;;
  terminate-enclave) rm -f "$f" ;;
esac
X
chmod +x "$work/bin/nitro-cli"
# The parent tools: copies of sleep under their names, so pgrep -x finds them.
for t in hostagent forwarder udprelay vsock-proxy; do cp "$(command -v sleep)" "$work/tools/$t"; done
# hostagent starts late, as on a slow machine: pgrep -x finds it only after
# the exec, 1 s after parent-run.sh has returned.
cat >"$work/tools/late-start" <<'X'
#!/usr/bin/env bash
sleep 1
exec "$(dirname "$0")/hostagent" "$@"
X
chmod +x "$work/tools/late-start"
cat >"$work/opt/parent-run.sh" <<'X'
#!/usr/bin/env bash
# As parent-run.sh: the tools in the background with nohup, the enclave.
set -euo pipefail
T="$(dirname "$FAKE")/tools"
for p in 8000 8001; do nohup "$T/vsock-proxy" 1000 >/dev/null 2>&1 & done
nohup "$T/udprelay" 1000 >/dev/null 2>&1 &
[ -n "${NO_HOSTAGENT:-}" ] || nohup "$T/late-start" 1000 >/dev/null 2>&1 &
nitro-cli run-enclave --eif-path x.eif --cpu-count 1 --memory 512 --enclave-cid 16
nohup "$T/forwarder" 1000 >/dev/null 2>&1 &
X
SVC="$work/opt/parent-service.sh"
envs=(FAKE="$work/fake" PATH="$work/bin:$PATH" STATE_DIR="$work/state" RUNTIME_DIRECTORY="$work/run"
  WATCH_INTERVAL=0.2 BACKOFF_BASE=1 BACKOFF_MAX=2 BACKOFF_RESET=600)
svc() { env "${envs[@]}" bash "$SVC" "$@"; }
# svc_bg LOG: run in the background; pid is parent-service.sh itself.
svc_bg() { env "${envs[@]}" bash "$SVC" run >"$1" 2>&1 & pid=$!; }
tools_up() { local n=0 t; for t in hostagent forwarder udprelay vsock-proxy; do pgrep -x -u "$(id -u)" "$t" >/dev/null && n=$((n + 1)); done; echo "$n"; }
# wait_for COND: up to 5 s.
wait_for() { local n; for ((n = 0; n < 50; n++)); do eval "$1" && return 0; sleep 0.1; done; return 1; }
reset() {
  pkill -f "$work/tools/late-start" 2>/dev/null || true
  for t in hostagent forwarder udprelay vsock-proxy; do pkill -x -u "$(id -u)" "$t" 2>/dev/null || true; done
  rm -rf "$work/fake" "$work/run" "$work/state"
  mkdir -p "$work/fake" "$work/run" "$work/state"
  wait_for '[ "$(tools_up)" = 0 ]' || true
}
for t in hostagent forwarder udprelay vsock-proxy; do
  ! pgrep -x "$t" >/dev/null || { echo "aws-parent-service-test: a process named $t is running on this machine; the test needs none" >&2; exit 1; }
done

# ---- start and crash ----------------------------------------------------------
reset
svc_bg "$work/run1.log"
if wait_for '[ -f "$work/fake/enclave" ] && [ "$(tools_up)" = 4 ]'; then
  [ "$(wc -l <"$work/fake/starts")" = 1 ] && [ "$(pgrep -x -u "$(id -u)" vsock-proxy | wc -l)" = 2 ] &&
    ok "start: one enclave and the parent tools" || bad "start: $(cat "$work/fake/starts")"
else
  bad "start: not running: $(cat "$work/run1.log")"
fi
sleep 0.5
echo "2026-11-04T10:00:00Z runner: setup: image measurement not allowed" >"$work/state/last-exit.txt"
rm -f "$work/fake/enclave"
rc=0
wait "$pid" || rc=$?
log1="$(cat "$work/run1.log")"
if [ "$rc" = 1 ] && has "the enclave ended (failure 1)" "$log1" && has "runner: setup: image measurement not allowed" "$log1" &&
  [ "$(cat "$work/run/failures")" = 1 ] && wait_for '[ "$(tools_up)" = 0 ]'; then
  ok "crash: exit 1 with the last-exit line, tools stopped, failure 1"
else
  bad "crash: rc $rc, tools $(tools_up): $log1"
fi
svc cleanup >/dev/null
# The restart after it: waits BACKOFF_BASE, starts again.
svc_bg "$work/run2.log"
if wait_for 'has "parent-service: running:" "$(cat "$work/run2.log" 2>/dev/null)"' && has "start after failure 1: waiting 1s" "$(cat "$work/run2.log")"; then
  ok "restart: waits 1s, starts again"
else
  bad "restart: $(cat "$work/run2.log")"
fi

# ---- tool ends ----------------------------------------------------------------
pkill -x -u "$(id -u)" forwarder
rc=0
wait "$pid" || rc=$?
log2="$(cat "$work/run2.log")"
if [ "$rc" = 1 ] && has "forwarder (pid" "$log2" && has "(failure 2)" "$log2" && [ ! -f "$work/fake/enclave" ] &&
  wait_for '[ "$(tools_up)" = 0 ]'; then
  ok "tool: a parent tool ends, exit 1, enclave terminated"
else
  bad "tool: rc $rc, enclave $(cat "$work/fake/enclave" 2>/dev/null), tools $(tools_up): $log2"
fi
svc cleanup >/dev/null
echo 5 >"$work/run/failures"
svc_bg "$work/run3.log"
wait_for 'has "start after failure 5: waiting 2s" "$(cat "$work/run3.log")"' && ok "backoff: capped at BACKOFF_MAX" || bad "backoff: $(cat "$work/run3.log")"

# ---- stop ---------------------------------------------------------------------
wait_for 'has "parent-service: running:" "$(cat "$work/run3.log" 2>/dev/null)"' || bad "stop: never started: $(cat "$work/run3.log")"
sleep 0.5
kill -TERM "$pid"
rc=0
wait "$pid" || rc=$?
if [ "$rc" = 0 ] && [ ! -f "$work/fake/enclave" ] && has "terminate-enclave --all" "$(cat "$work/fake/nitro-cli.calls")" &&
  wait_for '[ "$(tools_up)" = 0 ]' && has "parent-service: stopped" "$(cat "$work/run3.log")"; then
  ok "stop: exit 0, enclave terminated, tools stopped"
else
  bad "stop: rc $rc, tools $(tools_up): $(cat "$work/run3.log")"
fi
svc cleanup >/dev/null
# A stop during the backoff wait: exit 0, nothing started.
reset
echo 1 >"$work/run/failures"
svc_bg "$work/run4.log"
sleep 0.3
kill -TERM "$pid"
rc=0
wait "$pid" || rc=$?
[ "$rc" = 0 ] && [ ! -f "$work/fake/starts" ] && ok "stop during the wait: exit 0, no start" || bad "stop during the wait: rc $rc $(cat "$work/run4.log")"

# ---- refused ------------------------------------------------------------------
reset
echo "i-0-enc-other" >"$work/fake/enclave"
rc=0
svc run >"$work/run5.log" 2>&1 || rc=$?
svc cleanup >/dev/null
if [ "$rc" = 3 ] && [ "$(cat "$work/fake/enclave")" = "i-0-enc-other" ] && [ ! -f "$work/fake/starts" ] &&
  has "an enclave is already running" "$(cat "$work/run5.log")"; then
  ok "refused: an enclave it did not start, exit 3, left alone by run and cleanup"
else
  bad "refused enclave: rc $rc $(cat "$work/run5.log")"
fi
reset
nohup "$work/tools/hostagent" 1000 >/dev/null 2>&1 &
other=$!
rc=0
svc run >"$work/run6.log" 2>&1 || rc=$?
if [ "$rc" = 3 ] && kill -0 "$other" && [ ! -f "$work/fake/starts" ] && has "hostagent is already running" "$(cat "$work/run6.log")"; then
  ok "refused: parent tools already running, exit 3"
else
  bad "refused tools: rc $rc $(cat "$work/run6.log")"
fi
kill "$other" 2>/dev/null || true

# ---- cleanup after SIGKILL ----------------------------------------------------
reset
svc_bg "$work/run7.log"
wait_for 'has "parent-service: running:" "$(cat "$work/run7.log" 2>/dev/null)"' || bad "cleanup: never started: $(cat "$work/run7.log")"
kill -9 "$pid"
wait "$pid" 2>/dev/null || true
svc cleanup >/dev/null
[ ! -f "$work/fake/enclave" ] && [ ! -f "$work/run/owned" ] && ok "cleanup: terminates the enclave of a killed run" || bad "cleanup: enclave left"
reset

# ---- missing tool --------------------------------------------------------------
rc=0
t0="$(date +%s%N)"
env "${envs[@]}" START_WAIT=1 NO_HOSTAGENT=1 bash "$SVC" run >"$work/run8.log" 2>&1 || rc=$?
ms=$((($(date +%s%N) - t0) / 1000000))
svc cleanup >/dev/null
log8="$(cat "$work/run8.log")"
if [ "$rc" = 1 ] && [ "$ms" -ge 1000 ] && has "hostagent is not running after parent-run.sh" "$log8" &&
  has "a parent tool did not start (failure 1)" "$log8" && [ ! -f "$work/fake/enclave" ]; then
  ok "missing: a tool that never starts, exit 1 after START_WAIT, enclave terminated"
else
  bad "missing: rc $rc after ${ms} ms, enclave $(cat "$work/fake/enclave" 2>/dev/null): $log8"
fi

reset

[ "$fail" = 0 ] || exit 1
echo "aws-parent-service-test: all cases as expected"
