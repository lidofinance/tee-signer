#!/usr/bin/env bash
# Code lines per module, counted on demand (the numbers change with every
# commit, so no file of the repo records them). cloc counts code only, no
# comments or blank lines. Left out: tests (_test.go, the tests module, the
# C tests, fuzz harness and simulator), test fakes and test
# helper packages, testdata, vendored code (third_party) and docs.
#
#   scripts/loc.sh              per module and language
#   scripts/loc.sh builds       the lines each runner build links: the Go
#                               files of this repo that go list -deps picks for
#                               its tags, plus the C core
#   scripts/loc.sh files MOD    the counted files of one module
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
command -v cloc >/dev/null || { echo "loc: cloc is not installed (apt install cloc)" >&2; exit 1; }
cd "$ROOT"

# A package directory is test code when a path element names a fake, a mock,
# a test helper or a test-only devkit package.
TEST_DIRS='(^|/)(tests|testdata|third_party|fuzz|sim|tools|docs|deploy|[a-z]*fake[a-z]*|[a-z]*test|fakeagent|fakerunner|fuzzcheck|leakcheck)(/|$)'

# files <module>: the counted source files of a module, one per line.
files() {
  local m="$1"
  case "$m" in
    signer-core)
      find signer-core/src signer-core/include -type f \( -name '*.c' -o -name '*.h' \)
      find signer-core -name '*.go' -not -name '*_test.go' | grep -vE "^signer-core/.*$TEST_DIRS" | grep -v '^signer-core/tools/' ;;
    trusted-time)
      find trusted-time -name '*.go' -not -name '*_test.go' | grep -vE "^trusted-time/.*$TEST_DIRS" ;;
    tests) ;;
    *)
      find "$m" -name '*.go' -not -name '*_test.go' | grep -vE "^$m/.*$TEST_DIRS" || true ;;
  esac
}

count() { # count <file list>: code lines per language, then the total
  [ -s "$1" ] || { echo "  (no files)"; return; }
  cloc --quiet --list-file="$1" --csv 2>/dev/null | awk -F, 'NR > 1 && $2 != "" && $2 != "SUM" { printf "  %-16s %7d\n", $2, $5; t += $5 } END { printf "  %-16s %7d\n", "total", t }'
}

mods=()
for m in */go.mod; do mods+=("${m%/go.mod}"); done
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

case "${1:-modules}" in
  modules)
    printf '%-20s %8s\n' module code
    for m in "${mods[@]}"; do
      files "$m" >"$tmp/$m.list"
      n=0
      [ ! -s "$tmp/$m.list" ] || n="$(cloc --quiet --list-file="$tmp/$m.list" --csv 2>/dev/null | awk -F, '$2 == "SUM" { print $5 }')"
      printf '%-20s %8s\n' "$m" "${n:-0}"
      cat "$tmp/$m.list" >>"$tmp/all.list"
    done
    echo "all modules, by language:"
    count "$tmp/all.list" ;;
  files) files "${2:?module}" ;;
  builds)
    files signer-core | grep -E '\.(c|h)$' >"$tmp/core.list"
    for name in "${RUNNER_BINS[@]}"; do
      tags="netgo,osusergo,$(runner_tags "$name")"
      (cd tee-signer && GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go list -deps -tags "$tags" \
        -f '{{if .Module}}{{range .GoFiles}}{{println $.Module.Path $.Dir .}}{{end}}{{range .CgoFiles}}{{println $.Module.Path $.Dir .}}{{end}}{{range .CFiles}}{{println $.Module.Path $.Dir .}}{{end}}{{end}}' .) |
        awk '$1 ~ /^github.com[/]lidofinance[/]tee-signer[/]/ { print $2 "/" $3 }' | sed "s#^$ROOT/##" >"$tmp/go.list"
      cat "$tmp/go.list" "$tmp/core.list" >"$tmp/b.list"
      go="$(cloc --quiet --list-file="$tmp/go.list" --csv 2>/dev/null | awk -F, '$2 == "SUM" { print $5 }')"
      all="$(cloc --quiet --list-file="$tmp/b.list" --csv 2>/dev/null | awk -F, '$2 == "SUM" { print $5 }')"
      printf '%-34s Go %6s, with the C core %6s\n' "$name" "$go" "$all"
    done ;;
  *) echo "usage: loc.sh [modules|builds|files MODULE]" >&2; exit 2 ;;
esac
