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
#       leak check)
#   release-gate.sh tree [dir]
#       fail unless dir (default: this repo) is a git tree whose HEAD has
#       none of the forbidden commits or branch tips in its history
#
# RELEASE_GATE_FORBID_FILE=<file> adds entries from a list kept outside the
# tree, one per line: default:<string>, release:<string>, commit:<sha>,
# branch:<name>, or b64: and one of those lines base64-encoded. Blank lines
# and lines that start with # are skipped. RELEASE_GATE_FORBIDDEN_COMMITS
# and RELEASE_GATE_FORBIDDEN_BRANCHES (space-separated) add more.
#
# The strings are flag, option, role and file names that only the code
# behind them holds. Go keeps source file names in the binary's line
# table even with -s -w, so a file name marks its code. Each string of the
# lists is one that no default build needs; scripts/release-gate-test.sh
# checks that each one fails the gate.
set -euo pipefail

# extra <kind>: the entries of that kind in RELEASE_GATE_FORBID_FILE.
extra() {
  local f="${RELEASE_GATE_FORBID_FILE:-}" line
  [ -n "$f" ] || return 0
  [ -r "$f" ] || { echo "release gate: cannot read RELEASE_GATE_FORBID_FILE=$f" >&2; exit 2; }
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in '' | '#'*) continue ;; esac
    [ "${line#b64:}" = "$line" ] || line="$(base64 -d <<<"${line#b64:}")"
    [ "${line#"$1":}" = "$line" ] || printf '%s\n' "${line#"$1":}"
  done <"$f"
}

# Strings no default-flavour runner may hold, debug builds included.
default_list() {
  cat <<'L'
admin-root-direct
allow-unlisted-image
imageoverride_testnet.go
signer-runner testnet
0.1.0+testnet
signer-build-overlay
net-state-dir
L
  extra default
}

# Strings no release runner may hold: the plaintext import and the fake
# hardware of the debug builds, and the test-only packages.
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
github.com/lidofinance/tee-signer/devkit
platform/dev/dev.go
signer-core/software/software.go
L
  extra release
}

if [ -n "${RELEASE_GATE_FORBID_FILE:-}" ] && [ ! -r "$RELEASE_GATE_FORBID_FILE" ]; then
  echo "release gate: cannot read RELEASE_GATE_FORBID_FILE=$RELEASE_GATE_FORBID_FILE" >&2
  exit 2
fi

# Commits and branches that may not be in a release tree's history; a
# branch's tip counts wherever it moves.
FORBIDDEN_COMMITS="${RELEASE_GATE_FORBIDDEN_COMMITS-} $(extra commit)"
FORBIDDEN_BRANCHES="${RELEASE_GATE_FORBIDDEN_BRANCHES-} $(extra branch)"

check_binary() {
  local file="$1" kind="$2" s tags bad=0
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
    tags="$(go version -m "$file" 2>/dev/null | awk '$1 == "build" && $2 ~ /^-tags=/ { sub(/^-tags=/, "", $2); print $2 }' || true)"
    while IFS= read -r s; do
      # The local dev runner intentionally links platform/dev.
      if [ "$s" = platform/dev/dev.go ]; then
        case ",$tags," in *,platform_dev,*) continue ;; esac
      fi
      if grep -qaF -- "$s" "$file"; then echo "release gate: $file holds \"$s\" (a release build carries no debug or test code)" >&2; bad=1; fi
    done < <(release_list)
  fi
  return "$bad"
}

check_deps() {
  local dir="$1" tags="$2" pkg="$3" deps bad
  case ",${tags// /,}," in
    *,lockcheck,*) echo "release gate: lockcheck is for tests only" >&2; return 1 ;;
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
      echo "release gate: HEAD of $dir has forbidden commit $c" >&2; bad=1
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
