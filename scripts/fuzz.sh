#!/usr/bin/env bash
# Runs every Go fuzz target of the modules for a time budget each: the
# decoders of untrusted bytes must not panic, allocate more than their
# input justifies, or take longer than FUZZ_INPUT_LIMIT on one input
# (devkit/fuzzcheck). go test alone runs only the seed corpus (f.Add and
# testdata/fuzz); this script mutates.
#
#   FUZZ_TIME   budget per target (go test -fuzztime), default 10s
#   FUZZ_MATCH  run only the targets whose name matches this regexp
#   FUZZ_MINIMIZE_TIME  budget to minimize each new input (go test
#               -fuzzminimizetime), default 1s. Go's default of 60s let the
#               first new input of a target use up a 60 s budget with no
#               mutation (FuzzDecodeShare: 4734 executions in 30 s, against
#               about a million at 1s).
#   FUZZ_INPUT_LIMIT  time one input may take (fuzzcheck.Watch), default 2s
#   FUZZ_MODULES  the modules to fuzz, separated by spaces: unset or ALL for
#               every module, none for no module. On a pull request CI sets
#               it from scripts/affected.sh: the changed modules and those
#               that depend on them, nothing for a docs-only change.
#
# Every target calls fuzzcheck.Watch(t) first; this script refuses one
# that does not. Watch ends the fuzzing process when an input runs longer
# than FUZZ_INPUT_LIMIT, and go test reports "fuzzing process hung or
# terminated unexpectedly" and saves the input. Without it go test passes
# when an input loops forever.
#
# A failure leaves the input in the package's testdata/fuzz/<target>/;
# commit it with the fix as a regression seed. One failure is retried
# once: go test reported only "context deadline exceeded", with no other
# failure line, no panic and no new file in testdata/fuzz/<target>/. That
# error comes from go test stopping its fuzzing processes at the end of
# the budget, not from an input. A failed retry fails the run.
# Logs: logs/fuzz.log.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
mkdir -p "$LOGS"
budget="${FUZZ_TIME:-10s}"
match="${FUZZ_MATCH:-.}"
minimize="${FUZZ_MINIMIZE_TIME:-1s}"
one="$LOGS/fuzz-one.log"
if fuzz_everything; then
  mods=("${GO_MODULES[@]}")
else
  mods=()
  for m in $FUZZ_MODULES; do
    [ "$m" != none ] || continue
    [[ " ${GO_MODULES[*]} " == *" $m "* ]] || { echo "FUZZ_MODULES: $m is not a Go module of this repo" >&2; exit 1; }
    mods+=("$m")
  done
  if [ ${#mods[@]} -eq 0 ]; then
    log "fuzz: FUZZ_MODULES=$FUZZ_MODULES names no module, nothing to fuzz"
    exit 0
  fi
  log "fuzz: only ${mods[*]} (FUZZ_MODULES)"
fi
: >"$LOGS/fuzz.log"
n=0
# The runner's targets build with the dev release build's tags (the files
# behind !debugimport, FuzzSlashingModel in tee-signer/server, exist).
tags_of() {
  case "$1" in
    tee-signer) runner_tags runner-dev ;;
    platform-aws) echo platform_aws ;;
    platform-azure) echo platform_azure ;;
    platform-gcp) echo platform_gcp ;;
  esac
}

# watched <file> <target>: the target's body calls fuzzcheck.Watch(t).
watched() {
  awk -v f="func $2(" 'index($0, f) == 1 { in_f = 1 } in_f && /fuzzcheck\.Watch\(t\)/ { found = 1 } in_f && /^}/ { exit } END { exit !found }' "$1"
}

# saved <mod> <dir> <target>: the files of the target's testdata/fuzz.
saved() { ls -1 "$ROOT/$1/$2/testdata/fuzz/$3" 2>/dev/null || true; }

# fuzz_one <mod> <dir> <target>: go test -fuzz into $one.
fuzz_one() {
  (cd "$ROOT/$1" && go test -tags "$(tags_of "$1")" -run '^$' -fuzz "^$3\$" -fuzztime "$budget" \
    -fuzzminimizetime "$minimize" -parallel 4 "$2") >"$one" 2>&1
}

# bare_deadline <saved before>: the failure in $one is "context deadline
# exceeded" alone. After the one "--- FAIL" line, that is the only
# indented line; nothing panicked or raced, and no input was saved.
bare_deadline() {
  [ "$(grep -c -- '--- FAIL' "$one")" = 1 ] || return 1
  [ "$(sed -n '/--- FAIL/,$p' "$one" | grep '^[[:space:]]')" = "    context deadline exceeded" ] || return 1
  ! grep -qE 'panic:|DATA RACE|Failing input|hung or terminated|fuzzcheck:' "$one" || return 1
  [ "$(saved "$mod" "$dir" "$name")" = "$1" ]
}

# failed: shows the log of a failed target and exits.
failed() {
  cat "$one" >>"$LOGS/fuzz.log"
  tail -30 "$one"
  if grep -q 'hung or terminated unexpectedly' "$one"; then
    local id
    id="$(sed -n "s#.*Failing input written to testdata/fuzz/$name/##p" "$one" | head -n 1)"
    echo "an input crashed the fuzzing process or ran longer than FUZZ_INPUT_LIMIT (${FUZZ_INPUT_LIMIT:-2s}); go test does not show that process's output." >&2
    echo "to see the stacks: cd $mod && FUZZ_INPUT_LIMIT=${FUZZ_INPUT_LIMIT:-2s} go test -tags '$(tags_of "$mod")' -run '^$name/${id:-<file>}\$' $dir" >&2
  fi
  echo "fuzz target $name in $mod/${dir#./} failed" >&2
  exit 1
}

for mod in "${mods[@]}"; do
  [ -f "$ROOT/$mod/go.mod" ] || continue
  # package directory, file, then target name, for each func FuzzX in a _test.go
  while read -r dir file name; do
    [[ "$name" =~ $match ]] || continue
    watched "$ROOT/$mod/$file" "$name" ||
      { echo "fuzz target $name in $mod/$file: call fuzzcheck.Watch(t) first in its f.Fuzz function" >&2; exit 1; }
    log "fuzz $mod/${dir#./} $name ($budget)"
    before="$(saved "$mod" "$dir" "$name")"
    if ! fuzz_one "$mod" "$dir" "$name"; then
      bare_deadline "$before" || failed
      cat "$one" >>"$LOGS/fuzz.log"
      log "fuzz $mod/${dir#./} $name: RETRY: go test failed with only 'context deadline exceeded' and saved no input; running it once more"
      fuzz_one "$mod" "$dir" "$name" || failed
      log "fuzz $mod/${dir#./} $name: the retry passed"
    fi
    cat "$one" >>"$LOGS/fuzz.log"
    # go test passes when the tags leave the target out; that is a failure here.
    if grep -q 'no fuzz tests to fuzz' "$one"; then
      echo "fuzz target $name in $mod/${dir#./} did not build (build tags?)" >&2
      exit 1
    fi
    n=$((n + 1))
  done < <(cd "$ROOT/$mod" && grep -rl --include='*_test.go' '^func Fuzz' . |
    while read -r f; do
      d="./$(dirname "${f#./}")"
      grep -o '^func Fuzz[A-Za-z0-9_]*' "$f" | sed "s#^func #$d ${f#./} #"
    done | sort)
done
log "fuzz: $n targets in ${#mods[@]} modules, $budget each, no failure"
