#!/usr/bin/env bash
# Code lines per module, counted on demand (the numbers change with every
# commit, so no file of the repo records them). cloc counts code only, no
# comments or blank lines. Left out: tests (_test.go, the tests module, the
# C tests, fuzz harness and simulator, the Rust tests), test fakes and test
# helper packages, testdata, vendored code (third_party) and docs.
#
#   scripts/loc.sh              per module and language
#   scripts/loc.sh builds       the lines each runner build links: the Go
#                               files of this repo that go list -deps picks for
#                               its tags, plus the C core, plus the Rust NTS
#                               crate for the builds with the tag nts
#   scripts/loc.sh scope        the rows of SECURITY-SCOPE.md: the files the
#                               AWS release runner links, per row, and the
#                               share-import tool with its verifier, then any linked file no
#                               row covers
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
      find trusted-time/rust/src trusted-time/rust/core/src trusted-time/rust/nostd-check/src trusted-time/rust/include -type f \
        \( -name '*.rs' -o -name '*.h' \) -not -name 'tests.rs'
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
    files trusted-time | grep -E '\.(rs|h)$' >"$tmp/rust.list"
    for name in "${RUNNER_BINS[@]}"; do
      tags="netgo,osusergo,$(runner_tags "$name")"
      (cd tee-signer && GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go list -deps -tags "$tags" \
        -f '{{if .Module}}{{range .GoFiles}}{{println $.Module.Path $.Dir .}}{{end}}{{range .CgoFiles}}{{println $.Module.Path $.Dir .}}{{end}}{{range .CFiles}}{{println $.Module.Path $.Dir .}}{{end}}{{end}}' .) |
        awk '$1 ~ /^github.com[/]lidofinance[/]tee-signer[/]/ { print $2 "/" $3 }' | sed "s#^$ROOT/##" >"$tmp/go.list"
      cat "$tmp/go.list" "$tmp/core.list" >"$tmp/b.list"
      has_nts "$name" && cat "$tmp/rust.list" >>"$tmp/b.list"
      go="$(cloc --quiet --list-file="$tmp/go.list" --csv 2>/dev/null | awk -F, '$2 == "SUM" { print $5 }')"
      all="$(cloc --quiet --list-file="$tmp/b.list" --csv 2>/dev/null | awk -F, '$2 == "SUM" { print $5 }')"
      printf '%-34s Go %6s, with the C core%s %6s\n' "$name" "$go" "$(has_nts "$name" && echo ' and NTS' || echo '        ')" "$all"
    done ;;
  scope)
    # The rows of SECURITY-SCOPE.md, in its order: a label, then the Go
    # package directories (dir/... takes the packages under it too). @core is
    # the C signer core, @rust the Rust NTS core, @shareimport the share-import
    # tool and the attestation-verify code it checks the runner with (without
    # the GCP and dev verifiers), which the runner does not link.
    rows=(
      "1  signer-core|signer-core/core signer-core/threshold @core"
      "2  markformat|markformat"
      "3  tee-signer/attls|tee-signer/attls"
      "4  slashing-log, tee-signer/state|slashing-log tee-signer/state"
      "5  slashing-log/statestore, platform-aws/s3log|slashing-log/statestore platform-aws/s3log"
      "6  platform-aws/nitro|platform-aws/nitro"
      "7  tee-signer/server|tee-signer/server"
      "8  trusted-time: clock, nts, Rust NTS core|trusted-time/clock trusted-time/nts @rust"
      "9  setupwire, importorder, runnerchain|governance/setupwire governance/importorder governance/runnerchain"
      "10 tee-signer root package|tee-signer"
      "11 signer-protocol|signer-protocol/..."
      "12 platform, platform/setup|platform platform/setup"
      "13 enclave side of the parent links|platform-aws/hostagent/agentclient platform-aws/hostagent/agentwire platform-aws/udprelay/relayclient"
      "14 share-import, attestation-verify|@shareimport"
    )
    files signer-core | grep -E '\.(c|h)$' >"$tmp/core.list"
    files trusted-time | grep -E '\.(rs|h)$' >"$tmp/rust.list"
    tags="netgo,osusergo,$(runner_tags runner-aws)"
    (cd tee-signer && GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go list -deps -tags "$tags"       -f '{{if .Module}}{{range .GoFiles}}{{println $.Module.Path $.Dir .}}{{end}}{{range .CgoFiles}}{{println $.Module.Path $.Dir .}}{{end}}{{range .CFiles}}{{println $.Module.Path $.Dir .}}{{end}}{{range .HFiles}}{{println $.Module.Path $.Dir .}}{{end}}{{end}}' .) |
      awk '$1 ~ /^github.com[/]lidofinance[/]tee-signer[/]/ { print $2 "/" $3 }' | sed "s#^$ROOT/##" >"$tmp/go.list"
    : >"$tmp/seen.list"
    for row in "${rows[@]}"; do
      for p in ${row#*|}; do
        case "$p" in
          @core) cat "$tmp/core.list" ;;
          @rust) cat "$tmp/rust.list" ;;
          @shareimport)
            for d in signer-admin/cmd/share-import signer-admin/remote/admin signer-protocol/remote attestation-verify attestation-verify/azureid attestation-verify/runnerclient \
              attestation-verify/runnerclient/verify attestation-verify/runnerclient/internal/optset; do
              find "$d" -maxdepth 1 -name '*.go' -not -name '*_test.go'
            done | grep -vxE 'attestation-verify/gcp\.go|attestation-verify/runnerclient/verify/(gcp_cs|dev)\.go' ;;
          */...) awk -v b="${p%/...}" '{ d = $0; sub(/[/][^/]*$/, "", d) } d == b || index(d, b "/") == 1' "$tmp/go.list" ;;
          *) awk -v b="$p" '{ d = $0; sub(/[/][^/]*$/, "", d) } d == b' "$tmp/go.list" ;;
        esac
      done >"$tmp/row.list"
      cat "$tmp/row.list" >>"$tmp/seen.list"
      n=0
      [ ! -s "$tmp/row.list" ] || n="$(cloc --quiet --list-file="$tmp/row.list" --csv 2>/dev/null | awk -F, '$2 == "SUM" { print $5 }')"
      printf '%-48s %7s\n' "${row%%|*}" "${n:-0}"
    done
    echo "in scope, by language:"
    count "$tmp/seen.list"
    left="$(grep -vxF -f "$tmp/seen.list" "$tmp/go.list" || true)"
    [ -z "$left" ] || { echo "linked, but in no row of SECURITY-SCOPE.md:"; echo "$left" | sed 's/^/  /'; } ;;
  *) echo "usage: loc.sh [modules|builds|scope|files MODULE]" >&2; exit 2 ;;
esac
