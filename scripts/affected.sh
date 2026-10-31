#!/usr/bin/env bash
# Prints the Go modules that a change needs fuzzed, for scripts/fuzz.sh
# (FUZZ_MODULES). The change is git diff BASE...HEAD, the commits of HEAD
# since it left BASE.
#
#   scripts/affected.sh [BASE]   default origin/$GITHUB_BASE_REF, else origin/main
#
# Prints one line:
#   nothing    only docs changed: *.md, docs/, LICENSE, CODEOWNERS
#   modules    the modules with a changed file and every module that depends
#              on one of them, in GO_MODULES order. A module depends on the
#              modules of this repo that its go.mod names in a require or
#              replace line, and on theirs in turn.
#   ALL        a shared input changed: Makefile, scripts/, devkit/,
#              .github/, go.work*, signer-core/, markformat/, the Rust code
#              of trusted-time, any C or Rust file, or a file in no module.
#              Also when the diff cannot be made, and when FUZZ_ALL=1.
# The reason goes to stderr. The C fuzz targets run only on ALL.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

all() {
  log "affected: $*: ALL"
  echo ALL
  exit 0
}

[ "${FUZZ_ALL:-0}" != 1 ] || all "FUZZ_ALL=1"
if [ -n "${1:-}" ]; then
  base="$1"
elif [ -n "${GITHUB_BASE_REF:-}" ]; then
  base="origin/$GITHUB_BASE_REF"
else
  base=origin/main
fi
git -C "$ROOT" merge-base "$base" HEAD >/dev/null 2>&1 || all "no merge base of $base and HEAD (fetch the base, or the full history)"
files="$(git -C "$ROOT" diff --name-only --no-renames "$base...HEAD")" || all "git diff $base...HEAD failed"

# is_module <name>: <name> is one of GO_MODULES.
is_module() { [[ " ${GO_MODULES[*]} " == *" $1 "* ]]; }

changed=()
while IFS= read -r f; do
  [ -n "$f" ] || continue
  case "$f" in
    *.md | docs/* | LICENSE | CODEOWNERS | .github/CODEOWNERS) continue ;;
    Makefile | scripts/* | devkit/* | .github/* | go.work*) all "$f is a shared input" ;;
    signer-core/* | markformat/* | trusted-time/rust/* | trusted-time/toolchain/*) all "$f is a shared input" ;;
    *.c | *.h | *.S | *.rs | Cargo.* | */Cargo.*) all "$f is C or Rust code" ;;
  esac
  mod="${f%%/*}"
  if [ "$mod" = "$f" ] || ! is_module "$mod" || [ ! -f "$ROOT/$mod/go.mod" ]; then
    all "$f is in no Go module"
  fi
  [[ " ${changed[*]} " == *" $mod "* ]] || changed+=("$mod")
done <<<"$files"

if [ ${#changed[@]} -eq 0 ]; then
  log "affected: only docs changed since $base: no module"
  exit 0
fi

# deps <module>: the modules of this repo that its go.mod names.
deps() {
  sed -n 's#.*github\.com/lidofinance/tee-signer/\([A-Za-z0-9_.-]*\)[ /].*#\1#p; s#.*github\.com/lidofinance/tee-signer/\([A-Za-z0-9_.-]*\)$#\1#p' "$ROOT/$1/go.mod" |
    sort -u | grep -vx "$1" || true
}

# Add every module that names a module of the set, until none is left.
set=" ${changed[*]} "
grew=1
while [ "$grew" = 1 ]; do
  grew=0
  for m in "${GO_MODULES[@]}"; do
    [[ "$set" != *" $m "* ]] && [ -f "$ROOT/$m/go.mod" ] || continue
    for d in $(deps "$m"); do
      if [[ "$set" == *" $d "* ]]; then
        set+="$m "
        grew=1
        break
      fi
    done
  done
done
out=()
for m in "${GO_MODULES[@]}"; do [[ "$set" != *" $m "* ]] || out+=("$m"); done
log "affected: changed since $base: ${changed[*]}; with the modules that depend on them: ${out[*]}"
echo "${out[*]}"
