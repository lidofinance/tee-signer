#!/usr/bin/env bash
# Runs every Go fuzz target of the modules for a time budget each: the
# decoders of untrusted bytes must not panic or allocate more than their
# input justifies (devkit/fuzzcheck). go test alone runs only the seed
# corpus (f.Add and testdata/fuzz); this script mutates.
#
#   FUZZ_TIME   budget per target (go test -fuzztime), default 10s
#   FUZZ_MATCH  run only the targets whose name matches this regexp
#   FUZZ_MINIMIZE_TIME  budget to minimize each new input (go test
#               -fuzzminimizetime), default 1s. Go's default of 60s let the
#               first new input of a target use up a 60 s budget with no
#               mutation (FuzzDecodeShare: 4734 executions in 30 s, against
#               about a million at 1s).
#
# A failure leaves the input in the package's testdata/fuzz/<target>/;
# commit it with the fix as a regression seed. Logs: logs/fuzz.log.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
mkdir -p "$LOGS"
budget="${FUZZ_TIME:-10s}"
match="${FUZZ_MATCH:-.}"
minimize="${FUZZ_MINIMIZE_TIME:-1s}"
: >"$LOGS/fuzz.log"
n=0
# The runner's targets build with the key generation build's tags, so the
# ones in files for the peer builds (FuzzSlashingModel in tee-signer/server)
# exist; the files without a constraint build as well.
tags_of() {
  case "$1" in
    tee-signer) runner_tags runner-dev-dkg-dev ;;
    platform-aws) echo platform_aws ;;
    platform-azure) echo platform_azure ;;
    platform-gcp) echo platform_gcp ;;
  esac
}
for mod in "${GO_MODULES[@]}"; do
  [ -f "$ROOT/$mod/go.mod" ] || continue
  # package directory, then target name, for each func FuzzX in a _test.go
  while read -r dir name; do
    [[ "$name" =~ $match ]] || continue
    log "fuzz $mod/${dir#./} $name ($budget)"
    if ! (cd "$ROOT/$mod" && go test -tags "$(tags_of "$mod")" -run '^$' -fuzz "^$name\$" -fuzztime "$budget" -fuzzminimizetime "$minimize" -parallel 4 "$dir") >"$LOGS/fuzz-one.log" 2>&1; then
      cat "$LOGS/fuzz-one.log" >>"$LOGS/fuzz.log"
      tail -30 "$LOGS/fuzz-one.log"
      echo "fuzz target $name in $mod/$dir failed" >&2
      exit 1
    fi
    cat "$LOGS/fuzz-one.log" >>"$LOGS/fuzz.log"
    # go test passes when the tags leave the target out; that is a failure here.
    if grep -q 'no fuzz tests to fuzz' "$LOGS/fuzz-one.log"; then
      echo "fuzz target $name in $mod/$dir did not build (build tags?)" >&2
      exit 1
    fi
    n=$((n + 1))
  done < <(cd "$ROOT/$mod" && grep -rl --include='*_test.go' '^func Fuzz' . |
    while read -r f; do
      d="./$(dirname "${f#./}")"
      grep -o '^func Fuzz[A-Za-z0-9_]*' "$f" | sed "s#^func #$d #"
    done | sort)
done
log "fuzz: $n targets, $budget each, no failure"
