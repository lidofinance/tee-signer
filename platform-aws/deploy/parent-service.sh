#!/usr/bin/env bash
# The parent as a systemd service (signer-runner.service next to this file).
# It runs parent-run.sh, then watches the enclave and the parent tools that
# parent-run.sh started, and exits when any of them ends, so that systemd
# starts the whole set again.
#
#   parent-service.sh run       ExecStart: parent-run.sh, then the watch
#   parent-service.sh cleanup   ExecStopPost: terminates the enclave this
#                               service started, if one is left
#
# Exit status of run, which Restart=on-failure and RestartPreventExitStatus=3
# of the unit act on:
#   0  stopped by SIGTERM (systemctl stop): the enclave is terminated and the
#      parent tools are stopped. No restart.
#   1  the enclave ended, a parent tool ended, or parent-run.sh failed. The
#      enclave and the tools are stopped first. systemd starts it again.
#   3  an enclave or parent tools were already running when it started, so
#      this service did not start them. It touches neither. No restart.
#
# The runner in an enclave ends only on an error (it reports the line to
# the host agent, which writes it to $STATE_DIR/last-exit.txt), so every
# enclave exit counts as a failure, as a non-zero exit does for the
# OnFailure policy of the Azure and GCP deploys. Stop it with systemctl
# stop: an enclave terminated by hand with nitro-cli is started again.
#
# Settings (environment, from the unit's EnvironmentFile): those of
# parent-run.sh (SETUP, STATE_DIR, EIF, CPU_COUNT, MEMORY_MIB, ENTRY_PORT,
# ENCLAVE_CID), and
#   WATCH_INTERVAL  seconds between checks, default 10
#   BACKOFF_BASE    seconds before a start after one failure, default 10;
#                   doubled for each further failure
#   BACKOFF_MAX     the longest wait before a start, default 300
#   BACKOFF_RESET   an enclave that ran this many seconds before it ended
#                   counts as a first failure again, default 600
#   START_WAIT      whole seconds to wait for each parent tool after
#                   parent-run.sh returns, default 10
# The failure count is in RUNTIME_DIRECTORY (systemd keeps it across
# restarts, not across a stop or a reboot).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="${STATE_DIR:-/var/lib/signer-runner}"
WATCH_INTERVAL="${WATCH_INTERVAL:-10}"
BACKOFF_BASE="${BACKOFF_BASE:-10}"
BACKOFF_MAX="${BACKOFF_MAX:-300}"
BACKOFF_RESET="${BACKOFF_RESET:-600}"
START_WAIT="${START_WAIT:-10}"
RUN_DIR="${RUNTIME_DIRECTORY:-/run/signer-runner}"
TOOLS=(hostagent forwarder udprelay vsock-proxy)
# parent-run.sh writes the PIDs of the optional routes' proxies here.
OPTIONAL_PIDS="$RUN_DIR/optional-pids"
export STATE_DIR OPTIONAL_PIDS

say() { echo "parent-service: $*"; }

# The JSON of describe-enclaves: one object per enclave.
enclave_count() { grep -o '"EnclaveID"' <<<"$1" | wc -l; }
running_count() { grep -o '"State": *"RUNNING"' <<<"$1" | wc -l; }

# Terminates the enclave if this service started it: "owned" is written
# only after the start found no enclave, and one enclave fits a parent.
# cleanup removes "owned", after systemd has killed what was left.
terminate_owned() {
  [ -f "$RUN_DIR/owned" ] || return 0
  local out
  out="$(nitro-cli describe-enclaves 2>/dev/null || true)"
  if [ "$(enclave_count "$out")" -gt 0 ]; then
    say "terminating the enclave"
    nitro-cli terminate-enclave --all >/dev/null || say "nitro-cli terminate-enclave failed"
  fi
}

PIDS=()
WATCH=()
stop_tools() {
  local p n
  for p in "${PIDS[@]}"; do kill "${p%% *}" 2>/dev/null || true; done
  for ((n = 0; n < 50; n++)); do
    local alive=0
    for p in "${PIDS[@]}"; do ! kill -0 "${p%% *}" 2>/dev/null || alive=1; done
    [ "$alive" = 1 ] || return 0
    sleep 0.1
  done
  for p in "${PIDS[@]}"; do kill -9 "${p%% *}" 2>/dev/null || true; done
}

stopping=0
PR=""
on_term() { stopping=1; }
stop_now() {
  [ -z "$PR" ] || kill "$PR" 2>/dev/null || true
  # Tools that parent-run.sh had started before the stop came.
  [ "${#PIDS[@]}" -gt 0 ] || collect_pids || true
  terminate_owned
  stop_tools
  say "stopped"
  exit 0
}
# Waits SECONDS, or less on SIGTERM.
pause() { sleep "$1" & wait $! || true; }

# PIDS: "PID NAME" of each parent tool of this user, which a stop ends.
# WATCH: those the watch loop needs running, all but the proxies of optional
# routes that parent-run.sh listed in OPTIONAL_PIDS: one of those may end
# (its host did not resolve) without a restart. Fails if a tool is missing.
collect_pids() {
  local t p found=0
  PIDS=()
  WATCH=()
  for t in "${TOOLS[@]}"; do
    found=0
    for p in $(pgrep -x -u "$(id -u)" "$t" || true); do
      PIDS+=("$p $t")
      if [ -f "$OPTIONAL_PIDS" ] && grep -q -x -F -- "$p" "$OPTIONAL_PIDS"; then continue; fi
      WATCH+=("$p $t")
      found=1
    done
    [ "$found" = 1 ] || { say "$t is not running after parent-run.sh"; return 1; }
  done
}

# parent-run.sh starts the tools in the background, so one may not run yet
# when it returns. Waits up to START_WAIT seconds for each, checking every
# 0.2 s; collect_pids then reports one that is still missing.
wait_tools() {
  local t n
  for t in "${TOOLS[@]}"; do
    for ((n = START_WAIT * 5; n > 0; n--)); do
      ! pgrep -x -u "$(id -u)" "$t" >/dev/null || break
      [ "$stopping" = 0 ] || stop_now
      sleep 0.2
    done
  done
}

failed() {
  local reason="$1" now n=0
  [ "$stopping" = 0 ] || stop_now
  now="$(date +%s)"
  [ ! -f "$RUN_DIR/failures" ] || n="$(cat "$RUN_DIR/failures")"
  if [ -f "$RUN_DIR/started" ] && [ $((now - $(cat "$RUN_DIR/started"))) -ge "$BACKOFF_RESET" ]; then n=0; fi
  echo $((n + 1)) >"$RUN_DIR/failures"
  say "$reason (failure $((n + 1)))"
  if [ -f "$STATE_DIR/last-exit.txt" ] && [ "$STATE_DIR/last-exit.txt" -nt "$RUN_DIR/started" ]; then
    say "last-exit.txt: $(head -c 2100 "$STATE_DIR/last-exit.txt")"
  fi
  terminate_owned
  stop_tools
  exit 1
}

cmd_run() {
  mkdir -p "$RUN_DIR"
  trap on_term TERM INT
  local n=0 delay out misses=0 t
  [ ! -f "$RUN_DIR/failures" ] || n="$(cat "$RUN_DIR/failures")"
  if [ "$n" -gt 0 ]; then
    delay="$BACKOFF_BASE"
    for ((t = 1; t < n && delay < BACKOFF_MAX; t++)); do delay=$((delay * 2)); done
    [ "$delay" -le "$BACKOFF_MAX" ] || delay="$BACKOFF_MAX"
    say "start after failure $n: waiting ${delay}s"
    pause "$delay"
    [ "$stopping" = 0 ] || { say "stopped"; exit 0; }
  fi

  # One enclave and one set of parent tools: refuse to start next to any.
  out="$(nitro-cli describe-enclaves)" || { say "nitro-cli describe-enclaves failed"; exit 1; }
  if [ "$(enclave_count "$out")" -gt 0 ]; then
    say "an enclave is already running that this service did not start; terminate it (nitro-cli terminate-enclave) and start the service again"
    exit 3
  fi
  for t in "${TOOLS[@]}"; do
    if pgrep -x "$t" >/dev/null; then
      say "$t is already running; stop it, or reboot, and start the service again"
      exit 3
    fi
  done
  : >"$RUN_DIR/owned"
  rm -f "$OPTIONAL_PIDS"
  date +%s >"$RUN_DIR/started"

  bash "$HERE/parent-run.sh" &
  PR=$!
  wait "$PR" || {
    local rc=$?
    PR=""
    [ "$stopping" = 0 ] || stop_now
    collect_pids || true
    failed "parent-run.sh failed (exit $rc)"
  }
  PR=""
  [ "$stopping" = 0 ] || stop_now
  wait_tools
  collect_pids || failed "a parent tool did not start"
  say "running: ${WATCH[*]}"

  while :; do
    pause "$WATCH_INTERVAL"
    [ "$stopping" = 0 ] || stop_now
    local reason=""
    if ! out="$(nitro-cli describe-enclaves 2>&1)"; then
      misses=$((misses + 1))
      [ "$misses" -ge 3 ] && reason="nitro-cli describe-enclaves failed 3 times: $out"
    else
      misses=0
      [ "$(running_count "$out")" -gt 0 ] || reason="the enclave ended"
    fi
    if [ -z "$reason" ]; then
      for t in "${WATCH[@]}"; do
        kill -0 "${t%% *}" 2>/dev/null || { reason="${t#* } (pid ${t%% *}) ended"; break; }
      done
    fi
    [ -z "$reason" ] || failed "$reason"
  done
}

case "${1:-}" in
  run) cmd_run ;;
  cleanup) mkdir -p "$RUN_DIR" && terminate_owned && rm -f "$RUN_DIR/owned" ;;
  *) echo "usage: parent-service.sh run|cleanup" >&2; exit 2 ;;
esac
