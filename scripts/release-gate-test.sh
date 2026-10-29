#!/usr/bin/env bash
# Self-test of scripts/release-gate.sh: each forbidden string in a small Go
# binary makes the binary check fail, a clean binary passes, a test-only
# package in the dependencies fails the deps check, and a forbidden commit
# in the history fails the tree check. Offline, stdlib only.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
GATE="$ROOT/scripts/release-gate.sh"
# The checks below expect no build overlay; one case sets it.
unset SIGNER_BUILD_OVERLAY_DIR
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fails=0
expect() { # expect <pass|fail> <what> <command...>
  local want="$1" what="$2"
  shift 2
  if "$@" >"$tmp/out" 2>&1; then got=pass; else got=fail; fi
  if [ "$got" != "$want" ]; then
    echo "release gate self-test: $what: got $got, want $want" >&2
    sed 's/^/  /' "$tmp/out" >&2
    fails=$((fails + 1))
  fi
}

# build_with <name> <string>: a static Go binary that holds the string
# (no quotes or backslashes in it).
build_with() {
  mkdir -p "$tmp/src/$1"
  printf 'module gatetest\n\ngo 1.22\n' >"$tmp/src/$1/go.mod"
  printf 'package main\n\nimport "os"\n\nvar s = "%s"\n\nfunc main() { os.Stdout.WriteString(s[:len(os.Args)-1]) }\n' "$2" >"$tmp/src/$1/main.go"
  (cd "$tmp/src/$1" && CGO_ENABLED=0 GOFLAGS=-mod=mod go build -trimpath -o "$tmp/$1" .)
}

build_with clean "nothing to see"
for kind in release debug; do
  expect pass "clean $kind binary" bash "$GATE" binary "$tmp/clean" "$kind"
  expect fail "clean $kind binary with the build overlay set" env SIGNER_BUILD_OVERLAY_DIR=/x bash "$GATE" binary "$tmp/clean" "$kind"
done

# Every string of the default list fails every default-flavour binary;
# every string of the release list fails a release binary only.
i=0
while IFS= read -r s; do
  i=$((i + 1))
  build_with "d$i" "x${s}x"
  expect fail "default list: $s in a release binary" bash "$GATE" binary "$tmp/d$i" release
  expect fail "default list: $s in a debug binary" bash "$GATE" binary "$tmp/d$i" debug
done < <(bash "$GATE" list default)
i=0
while IFS= read -r s; do
  i=$((i + 1))
  build_with "r$i" "x${s}x"
  expect fail "release list: $s in a release binary" bash "$GATE" binary "$tmp/r$i" release
  expect pass "release list: $s in a debug binary" bash "$GATE" binary "$tmp/r$i" debug
done < <(bash "$GATE" list release)
[ "$(bash "$GATE" list default | wc -l)" -ge 5 ] || { echo "release gate self-test: default list too short" >&2; fails=$((fails + 1)); }
[ "$(bash "$GATE" list release | wc -l)" -ge 4 ] || { echo "release gate self-test: release list too short" >&2; fails=$((fails + 1)); }

# deps: a main package that imports a test-only package, and one that
# imports testing, fail; the stdlib alone passes.
mkdir -p "$tmp/mod/wormfake" "$tmp/mod/okcmd" "$tmp/mod/fakecmd" "$tmp/mod/testingcmd" \
  "$tmp/mod/fuzzcheck" "$tmp/mod/leakcheck" "$tmp/mod/fuzzcmd" "$tmp/mod/leakcmd" \
  "$tmp/mod/devkit/helper" "$tmp/mod/devkitcmd"
printf 'module gatemod\n\ngo 1.22\n' >"$tmp/mod/go.mod"
printf 'package wormfake\n\nfunc F() int { return 1 }\n' >"$tmp/mod/wormfake/f.go"
printf 'package main\n\nimport "fmt"\n\nfunc main() { fmt.Println(1) }\n' >"$tmp/mod/okcmd/main.go"
printf 'package main\n\nimport "gatemod/wormfake"\n\nfunc main() { println(wormfake.F()) }\n' >"$tmp/mod/fakecmd/main.go"
printf 'package main\n\nimport "testing"\n\nfunc main() { println(testing.Short()) }\n' >"$tmp/mod/testingcmd/main.go"
expect pass "deps: stdlib only" bash "$GATE" deps "$tmp/mod" "" ./okcmd
expect fail "deps: a fake package" bash "$GATE" deps "$tmp/mod" "" ./fakecmd
expect fail "deps: package testing" bash "$GATE" deps "$tmp/mod" "" ./testingcmd
# The fuzz oracles and the goroutine leak check are test-only packages.
printf 'package fuzzcheck\n\nfunc F() int { return 2 }\n' >"$tmp/mod/fuzzcheck/f.go"
printf 'package leakcheck\n\nfunc F() int { return 3 }\n' >"$tmp/mod/leakcheck/f.go"
printf 'package main\n\nimport "gatemod/fuzzcheck"\n\nfunc main() { println(fuzzcheck.F()) }\n' >"$tmp/mod/fuzzcmd/main.go"
printf 'package main\n\nimport "gatemod/leakcheck"\n\nfunc main() { println(leakcheck.F()) }\n' >"$tmp/mod/leakcmd/main.go"
expect fail "deps: package fuzzcheck" bash "$GATE" deps "$tmp/mod" "" ./fuzzcmd
expect fail "deps: package leakcheck" bash "$GATE" deps "$tmp/mod" "" ./leakcmd
expect pass "deps: other tags" bash "$GATE" deps "$tmp/mod" "netgo,osusergo" ./okcmd

# No devkit package belongs in release builds.
printf 'package helper\n\nfunc F() int { return 4 }\n' >"$tmp/mod/devkit/helper/f.go"
printf 'package main\n\nimport "gatemod/devkit/helper"\n\nfunc main() { println(helper.F()) }\n' >"$tmp/mod/devkitcmd/main.go"
expect fail "deps: devkit helper" bash "$GATE" deps "$tmp/mod" "" ./devkitcmd

# tree: a history with a forbidden commit fails, one without passes.
git -c init.defaultBranch=main init -q "$tmp/repo"
g() { git -C "$tmp/repo" -c user.name=t -c user.email=t@t -c commit.gpgsign=false "$@"; }
g commit -q --allow-empty -m base
g checkout -q -b bad
g commit -q --allow-empty -m forbidden
bad="$(g rev-parse HEAD)"
g checkout -q main
g commit -q --allow-empty -m good
expect pass "tree: forbidden commit not an ancestor" env RELEASE_GATE_FORBIDDEN_COMMITS="$bad" RELEASE_GATE_FORBIDDEN_BRANCHES=bad bash "$GATE" tree "$tmp/repo"
g merge -q --no-edit bad
expect fail "tree: forbidden commit merged" env RELEASE_GATE_FORBIDDEN_COMMITS="$bad" RELEASE_GATE_FORBIDDEN_BRANCHES= bash "$GATE" tree "$tmp/repo"
expect fail "tree: forbidden branch tip merged" env RELEASE_GATE_FORBIDDEN_COMMITS= RELEASE_GATE_FORBIDDEN_BRANCHES=bad bash "$GATE" tree "$tmp/repo"
expect fail "tree: not a git tree" bash "$GATE" tree "$tmp/src"
# The real list against this tree.
expect pass "tree: this tree" bash "$GATE" tree "$ROOT"

[ "$fails" = 0 ] || { echo "release gate self-test: $fails failures" >&2; exit 1; }
log "release gate self-test passed"
