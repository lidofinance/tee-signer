#!/usr/bin/env bash
# Release gate (T-127): a default build carries no bypass code.
#
#   release-gate.sh list <default|release>
#       print the forbid list, one string per line
#   release-gate.sh binary <file> <release|debug>
#       fail if SIGNER_BUILD_OVERLAY_DIR (the build overlay) is
#       set, or if the binary holds a string of the default list (any
#       default-flavour build, debug builds too) or, for a release build,
#       of the release list. scripts/build-runner.sh runs it on every
#       default-flavour runner it builds.
#   release-gate.sh deps <module dir> <tags> <package>
#       fail if the package links "testing", net/http/httptest or a
#       test-only package (fakes, test helpers, fuzz oracles, the goroutine
#       leak check), or if the tags hold lockcheck
#   release-gate.sh tree [dir]
#       fail unless dir (default: this repo) is a git tree whose HEAD has
#       no commit of the testnet approver reset branch in its history
#
# The strings are flag, option, role and file names that only the code
# behind them holds. Go keeps source file names in the binary's line
# table even with -s -w, so a file name marks its code. Each string of the
# lists is one that no default build needs; scripts/release-gate-test.sh
# checks that each one fails the gate.
set -euo pipefail

# unhex <hex>: the string. Two strings of the testnet approver reset are
# kept as hex here, so that the tree guard (scripts/check-forbidden.sh) finds
# no reset marker in this file.
unhex() { printf '%b' "$(sed 's/../\\x&/g' <<<"$1")"; }

# Strings no default-flavour runner may hold, debug builds included.
default_list() {
  cat <<'L'
approver reset
approverReset
admin-root-direct
allow-unlisted-image
imageoverride_testnet.go
signer-runner testnet
0.1.0+testnet
signer-build-overlay
net-state-dir
runner/netstate
L
  unhex 415050524f5645525f52455345545f484153484553
  echo
}

# Strings no release runner may hold: the plaintext import and the fake
# hardware of the debug builds, and the test-only packages.
# lockorder/check.go is the lock order check that -tags lockcheck
# builds in place of lockorder/off.go; it panics on an inversion.
release_list() {
  cat <<'L'
allow-import
tee-signer/debugimport.go
server/plainimport.go
hooks_debug.go
nts_servers_debug.go
RUNNER_NTS_TEST_SERVERS
slashing-log/wormfake
slashing-log/logtest
nts/ntstest
lockorder/check.go
devkit/leakcheck
devkit/fuzzcheck
L
}

# The commits of the testnet approver reset branch of the dev repo. None may be in a release tree, and neither
# may the branch's tip, wherever it moves.
FORBIDDEN_COMMITS="${RELEASE_GATE_FORBIDDEN_COMMITS-053ba4352da2811d56ce118b76c1e3d8e263c0d3 1013b7b9d2e00e80987b6316d6ea3a90751cf10e 55ff587896060b0c85c10227dbfcf587a0d96e33 ae7e38cb2a243876ff443910fc5c237ba6f76445}"
FORBIDDEN_BRANCHES="${RELEASE_GATE_FORBIDDEN_BRANCHES-$(unhex 6e65787433722d617070726f7665722d7265736574)}"

check_binary() {
  local file="$1" kind="$2" s bad=0
  case "$kind" in release|debug) ;; *) echo "release gate: kind $kind, want release or debug" >&2; return 2 ;; esac
  # The build overlay is for testnet builds only.
  if [ -n "${SIGNER_BUILD_OVERLAY_DIR:-}" ]; then
    echo "release gate: SIGNER_BUILD_OVERLAY_DIR is set; a default build takes no build overlay" >&2
    return 1
  fi
  [ -f "$file" ] || { echo "release gate: no file $file" >&2; return 2; }
  while IFS= read -r s; do
    if grep -qaF -- "$s" "$file"; then echo "release gate: $file holds \"$s\" (a default build carries no bypass code)" >&2; bad=1; fi
  done < <(default_list)
  if [ "$kind" = release ]; then
    while IFS= read -r s; do
      if grep -qaF -- "$s" "$file"; then echo "release gate: $file holds \"$s\" (a release build carries no debug or test code)" >&2; bad=1; fi
    done < <(release_list)
  fi
  return "$bad"
}

check_deps() {
  local dir="$1" tags="$2" pkg="$3" deps bad
  # The lock order check (devkit/lockorder) panics on an inversion; it is
  # for tests only.
  case ",$tags," in
    *,lockcheck,*) echo "release gate: $pkg is built with tag lockcheck (tests only)" >&2; return 1 ;;
  esac
  # Standard packages as "std <path>", the others as "mod <path>".
  deps="$(cd "$dir" && go list -deps -tags "$tags" -f '{{if .Standard}}std{{else}}mod{{end}} {{.ImportPath}}' "$pkg")"
  # A module package is test-only when one of its path elements names a
  # fake, a mock, a test helper (xtest, testx), a fuzz oracle (fuzzcheck)
  # or the goroutine leak check (leakcheck); "attest" is the attestation
  # code, not a test.
  bad="$(awk '
    $1 == "std" && ($2 == "testing" || $2 ~ /^testing\// || $2 == "net/http/httptest") { print; next }
    $1 == "mod" {
      n = split($2, e, "/")
      # devkit/lockorder is linked in every build: without the tag lockcheck
      # it is a plain mutex (lockorder/off.go); the binary check forbids its
      # check.go and the tag check above forbids lockcheck.
      if (index($2, "/devkit/lockorder") && $2 ~ /lockorder$/) next
      for (i = 1; i <= n; i++)
        if (e[i] != "attest" && e[i] ~ /(^test|test$|fake|mock|^lockrank$|^leakcheck$|^fuzzcheck$|^devkit$)/) { print; next }
    }' <<<"$deps")"
  if [ -n "$bad" ]; then
    echo "release gate: $pkg (tags $tags) links test-only packages:" >&2
    sed 's/^/  /' <<<"$bad" >&2
    return 1
  fi
}

check_tree() {
  local dir="$1" c b tip bad=0
  git -C "$dir" rev-parse --is-inside-work-tree >/dev/null 2>&1 ||
    { echo "release gate: $dir is not a git tree; its history cannot be checked" >&2; return 1; }
  for c in $FORBIDDEN_COMMITS; do
    # A commit this repo does not have cannot be in its history.
    git -C "$dir" cat-file -e "$c^{commit}" 2>/dev/null || continue
    if git -C "$dir" merge-base --is-ancestor "$c" HEAD; then
      echo "release gate: HEAD of $dir has commit $c of the approver reset branch" >&2; bad=1
    fi
  done
  for b in $FORBIDDEN_BRANCHES; do
    tip="$(git -C "$dir" rev-parse -q --verify "refs/heads/$b^{commit}" || true)"
    [ -n "$tip" ] || continue
    if git -C "$dir" merge-base --is-ancestor "$tip" HEAD; then
      echo "release gate: HEAD of $dir has branch $b ($tip)" >&2; bad=1
    fi
  done
  return "$bad"
}

case "${1:-}" in
  list)
    case "${2:-}" in default) default_list ;; release) release_list ;; *) echo "usage: $0 list <default|release>" >&2; exit 2 ;; esac ;;
  binary) [ $# = 3 ] || { echo "usage: $0 binary <file> <release|debug>" >&2; exit 2; }; check_binary "$2" "$3" ;;
  deps) [ $# = 4 ] || { echo "usage: $0 deps <module dir> <tags> <package>" >&2; exit 2; }; check_deps "$2" "$3" "$4" ;;
  tree) check_tree "${2:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}" ;;
  *) echo "usage: $0 list|binary|deps|tree ..." >&2; exit 2 ;;
esac
