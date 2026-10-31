#!/usr/bin/env bash
# Self-test of scripts/affected.sh. Builds a throwaway git repo with this
# repo's go.mod files and scripts, commits a change on a branch for each
# case, and checks the modules affected.sh prints. Needs git only.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

git -C "$tmp" init -q -b main
git -C "$tmp" config user.name test
git -C "$tmp" config user.email test@example.invalid
git -C "$tmp" config commit.gpgsign false
mkdir -p "$tmp/scripts"
cp "$ROOT/scripts/common.sh" "$ROOT/scripts/affected.sh" "$tmp/scripts/"
for m in "${GO_MODULES[@]}"; do
  [ -f "$ROOT/$m/go.mod" ] || continue
  mkdir -p "$tmp/$m"
  cp "$ROOT/$m/go.mod" "$tmp/$m/"
done
echo base >"$tmp/README.md"
git -C "$tmp" add -A
git -C "$tmp" commit -q -m base

fails=0
n=0
# affected <case> <file>...: on a new branch off main, change each file and
# print what affected.sh prints for the branch.
affected() {
  local name="$1" f
  shift
  git -C "$tmp" checkout -q -b "$name" main
  for f in "$@"; do
    mkdir -p "$tmp/$(dirname "$f")"
    echo "$name" >>"$tmp/$f"
  done
  git -C "$tmp" add -A
  git -C "$tmp" commit -q -m "$name"
  (cd "$tmp" && FUZZ_ALL="${FUZZ_ALL:-0}" bash scripts/affected.sh main 2>/dev/null)
  git -C "$tmp" checkout -q main
}

# expect <case> <want> <got>: affected.sh printed exactly <want>.
expect() {
  local name="$1" want="$2" got="$3"
  n=$((n + 1))
  if [ "$got" = "$want" ]; then
    echo "  ok   $name: '${got}'"
  else
    echo "  FAIL $name: got '$got', want '$want'"
    fails=$((fails + 1))
  fi
}

# check <case> <want> <file>...: affected.sh prints exactly <want> for a
# change to the files.
check() {
  local name="$1" want="$2"
  shift 2
  expect "$name" "$want" "$(affected "$name" "$@")"
}

# has <case> <got> <want words> <not words>: <got> holds each of <want
# words> and none of <not words>.
has() {
  local name="$1" got=" $2 " w
  n=$((n + 1))
  for w in $3; do [[ "$got" == *" $w "* ]] || { echo "  FAIL $name: '$2' lacks $w"; fails=$((fails + 1)); return; }; done
  for w in $4; do [[ "$got" != *" $w "* ]] || { echo "  FAIL $name: '$2' has $w"; fails=$((fails + 1)); return; }; done
  echo "  ok   $name: '$2'"
}

check docs-only "" README.md slashing-log/docs/marklog.md docs/new.md LICENSE
check leaf-module web3signer-api web3signer-api/api.go
check leaf-module-and-docs web3signer-api web3signer-api/api.go tee-signer/README.md
check tests-module tests tests/e2e/x_test.go
check makefile ALL Makefile
check signer-core ALL signer-core/go/core.go
check markformat ALL markformat/markformat.go
check scripts ALL scripts/fuzz.sh
check devkit ALL devkit/fuzzcheck/fuzzcheck.go
check workflow ALL .github/workflows/ci.yml
check nts-rust ALL trusted-time/rust/src/lib.rs
check c-file ALL platform/x.c
check no-module ALL .gitignore
# A base that does not exist, and FUZZ_ALL=1 on a docs-only change.
expect unknown-base ALL "$(cd "$tmp" && bash scripts/affected.sh no-such-ref 2>/dev/null)"
expect fuzz-all ALL "$(FUZZ_ALL=1 affected fuzz-all README.md)"

# slashing-log: itself and the modules that use it, not those it uses.
has slashing-log "$(affected slashing-log slashing-log/record.go)" \
  "slashing-log tee-signer platform-aws attestation-verify signer-admin tests" \
  "devkit governance signer-protocol platform trusted-time markformat web3signer-api"
# governance: markformat names only signer-protocol, which names governance.
has governance-transitive "$(affected governance governance/x.go)" \
  "governance signer-protocol markformat tee-signer" "devkit trusted-time web3signer-api"

if [ "$fails" -ne 0 ]; then
  echo "affected-test: $fails of $n cases failed" >&2
  exit 1
fi
echo "affected-test: $n cases passed"
