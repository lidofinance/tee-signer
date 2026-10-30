#!/usr/bin/env bash
# Builds the fuzz targets (make fuzz) and runs them. See fuzz/README.md.
#   fuzz.sh ci       regression inputs, then FUZZ_SECONDS (default 5) per target
#   fuzz.sh long     FUZZ_SECONDS (default 1800) per target, keeps going after a crash
#   fuzz.sh replay   regression inputs and seeds only
# Settings:
#   FUZZ_TARGETS="signer bls"   a subset (default: every target)
#   FUZZ_JOBS=N                 targets run at once (default: nproc, at most 8)
#   FUZZ_ENGINE=libfuzzer|driver|auto   passed to make (default auto)
# Outputs under build/<arch>/fuzz/: corpus/<target>/ (grows across runs),
# artifacts-<mode>/<target>/ (crash inputs; ci clears its own), logs/<target>.log, summary.txt.
# Exits non-zero if any target crashed or a regression input fails.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

MODE="${1:-ci}"
case "$MODE" in
  ci) SECONDS_PER="${FUZZ_SECONDS:-5}" ;;
  long) SECONDS_PER="${FUZZ_SECONDS:-1800}" ;;
  replay) SECONDS_PER=0 ;;
  *) echo "usage: $0 [ci|long|replay]" >&2; exit 2 ;;
esac
FB="$CORE_DIR/build/$HOST_ARCH/fuzz"
REGRESS="$CORE_DIR/fuzz/regress"
ART="$FB/artifacts-$MODE"
JOBS="${FUZZ_JOBS:-$(nproc)}"
[ "$JOBS" -le 8 ] || JOBS=8

mkdir -p "$FB/logs"
make -C "$CORE_DIR" -j"$JOBS" FUZZ_ENGINE="${FUZZ_ENGINE:-auto}" fuzz >"$FB/logs/build.log" 2>&1 || {
  tail -20 "$FB/logs/build.log" >&2
  exit 1
}
ENGINE="$(cat "$FB/engine")"
TARGETS="${FUZZ_TARGETS:-$(make -s -C "$CORE_DIR" fuzz-targets | tr '\n' ' ')}"
for d in "$CST_SSZ_DIR" "$CST_BLS_DIR"; do
  [ -d "$d" ] || { echo "missing $d; run scripts/fetch.sh" >&2; exit 1; }
done
rm -rf "$FB/seeds"
"$FB/mkseeds" "$FB/seeds" "$CORE_DIR/tests/data" "$CST_SSZ_DIR" "$CST_BLS_DIR" >/dev/null

# Inputs longer than this are cut; aggregates and builder auth data are long.
max_len() {
  case "$1" in
    aggregate_and_proof) echo 17100 ;;
    builder_request_auth) echo 4200 ;;
    signer) echo 8192 ;;
    ssz_*|payload_envelope|repeat_roots|contribution_and_proof|bls) echo 1024 ;;
    *) echo 4096 ;;
  esac
}

# replay <target>: every regression input and seed once, in one process.
replay() {
  local t="$1" files=()
  shopt -s nullglob
  files=("$REGRESS/$t"/* "$FB/seeds/$t"/*)
  shopt -u nullglob
  [ ${#files[@]} -gt 0 ] || return 0
  "$FB/fuzz_$t" "${files[@]}" >"$FB/logs/$t.replay.log" 2>&1
}

# fuzz <target>: SECONDS_PER seconds from the corpus, seeds and regression inputs.
fuzz() {
  local t="$1" extra=() dirs=()
  dirs=("$FB/corpus/$t" "$FB/seeds/$t")
  # libFuzzer stops on a missing directory; regress/<target> exists only after a crash.
  [ -d "$REGRESS/$t" ] && dirs+=("$REGRESS/$t")
  mkdir -p "$FB/corpus/$t" "$ART/$t"
  if [ "$ENGINE" = driver ]; then
    [ "$MODE" = long ] && extra+=(-keep_going=1)
  else
    extra+=(-use_value_profile=1)
  fi
  "$FB/fuzz_$t" -max_total_time="$SECONDS_PER" -max_len="$(max_len "$t")" -timeout=60 \
    -print_final_stats=1 -artifact_prefix="$ART/$t/" "${extra[@]}" \
    "${dirs[@]}" >"$FB/logs/$t.log" 2>&1
}

status=0
for t in $TARGETS; do
  if ! replay "$t"; then
    echo "FAIL fuzz replay $t (log: ${FB#"$REPO_ROOT"/}/logs/$t.replay.log)"
    status=1
  fi
done
if [ "$MODE" = replay ]; then
  [ $status = 0 ] && echo "PASS fuzz replay ($(echo "$TARGETS" | wc -w) targets, engine $ENGINE)"
  exit $status
fi

: >"$FB/summary.txt"
[ "$MODE" = ci ] && rm -rf "$ART"
running=0
for t in $TARGETS; do
  (
    start=$(date +%s)
    if fuzz "$t"; then res=PASS; else res=FAIL; fi
    end=$(date +%s)
    log="$FB/logs/$t.log"
    stats="$(grep -E '^stat::(number_of_executed_units|edges|value_profile|corpus|average_exec_per_sec)' "$log" 2>/dev/null |
      sed 's/^stat:://' | tr '\n' ' ' || true)"
    # libFuzzer reports coverage only on its DONE line (cov, ft, corp).
    stats="$stats$(grep -E '^#[0-9]+[[:space:]]+DONE' "$log" | tail -1 |
      grep -oE '(cov|ft|corp): [^ ]+' | tr '\n' ' ' || true)"
    crashes="$(find "$ART/$t" -type f \( -name 'crash-*' -o -name 'timeout-*' -o -name 'leak-*' -o -name 'oom-*' \) | wc -l)"
    echo "$res $t $((end - start))s crashes=$crashes $stats" >>"$FB/summary.txt"
  ) &
  running=$((running + 1))
  if [ "$running" -ge "$JOBS" ]; then
    wait -n || true
    running=$((running - 1))
  fi
done
wait
sort -o "$FB/summary.txt" "$FB/summary.txt"
sed 's/^/  /' "$FB/summary.txt"
if grep -q '^FAIL' "$FB/summary.txt"; then
  status=1
fi
n="$(wc -l <"$FB/summary.txt")"
if [ $status = 0 ]; then
  echo "PASS fuzz $MODE ($n targets x ${SECONDS_PER}s, engine $ENGINE)"
else
  echo "FAIL fuzz $MODE (artifacts in ${ART#"$REPO_ROOT"/}/)"
fi
exit $status
