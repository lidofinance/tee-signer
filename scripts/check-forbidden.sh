#!/usr/bin/env bash
# Tree guard: fails if any file of the tree (text or binary) holds
#   - a private key block (PEM, OpenSSH or PGP),
#   - an AWS access key ID, a GitHub token or a VPN auth key (tskey-),
#   - a real AWS account ID in an ARN,
# or, with TEE_SIGNER_SCRUB_FILE set, an entry of that list. Key blocks and
# tokens in test files and third_party/ folders pass, and so do the AWS
# documentation examples.
#
#   scripts/check-forbidden.sh [dir]        default: this repo
#   TEE_SIGNER_SCRUB_FILE=<file>            also refuse each entry of a list
#                                           kept outside the tree
#
# Each line of the list is one entry:
#   i:<text>     any case
#   c:<text>     exact case
#   r:<regex>    an extended regular expression, any case
#   x:<text>     any case, in files outside third_party/ folders
#   b64:<line>   one of the lines above or below, base64-encoded
#   <text>       exact case; anything after a TAB is ignored
# Blank lines and lines that start with # are skipped. A failure names the
# entry's line number in the list, never the entry.
set -euo pipefail
ROOT="$(cd "${1:-$(dirname "${BASH_SOURCE[0]}")/..}" && pwd)"
# Account IDs that may appear: AWS documentation examples and all zeros.
ALLOWED_ACCOUNTS="111122223333 123456789012 000000000000"
# Files where key blocks and tokens may be fixtures.
FIXTURES='(^|/)(third_party|testdata|tests?)/|_test\.(go|rs|c|py|sh)$|(^|/)test_[^/]*$'
cd "$ROOT"
list="$(mktemp)" own="$(mktemp)" code="$(mktemp)"
trap 'rm -f "$list" "$own" "$code"' EXIT
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git ls-files -z -co --exclude-standard
else
  find . -type f -not -path './.git/*' -not -path './build/*' -not -path './logs/*' -print0
fi >"$list"
# The same files without third_party/ folders, and without fixtures.
tr '\0' '\n' <"$list" | grep -v -E '(^|/)third_party/' | tr '\n' '\0' >"$own" || true
tr '\0' '\n' <"$list" | grep -v -E "$FIXTURES" | tr '\n' '\0' >"$code" || true
fail=0

# scan <what> <regex> <allowed match regex or ""> : the regex in non-fixture
# files. Prints the file names only, not the match.
scan() {
  local what="$1" re="$2" allow="$3" hits
  hits="$(xargs -0 -r grep -aHoE -e "$re" -- <"$code" |
    { if [ -n "$allow" ]; then grep -vE -e ":($allow)\$"; else cat; fi; } |
    cut -d: -f1 | sort -u || true)"
  if [ -n "$hits" ]; then
    echo "check-forbidden: $what in:" >&2
    sed 's/^/  /' <<<"$hits" >&2
    fail=1
  fi
}
scan "a private key block" '-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY( BLOCK)?-----' ""
scan "an AWS access key ID" '\b(AKIA|ASIA)[0-9A-Z]{16}\b' '(AKIA|ASIA)[0-9A-Z]{9}EXAMPLE'
scan "a GitHub token" '\b(gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})' ""
scan "a VPN auth key" 'tskey-[a-z]+-[A-Za-z0-9]{6,}' ""

# AWS account IDs in ARNs.
ids="$(xargs -0 -r grep -ahoE 'arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:[0-9]{12}' -- <"$list" | grep -oE '[0-9]{12}$' | sort -u || true)"
for id in $ids; do
  case " $ALLOWED_ACCOUNTS " in *" $id "*) continue ;; esac
  echo "check-forbidden: an AWS account ID that is not a documentation example in: $(xargs -0 -r grep -alF -e "$id" -- <"$list" | tr '\n' ' ')" >&2
  fail=1
done

scrub=""
if [ -n "${TEE_SIGNER_SCRUB_FILE:-}" ]; then
  [ -f "$TEE_SIGNER_SCRUB_FILE" ] && [ -r "$TEE_SIGNER_SCRUB_FILE" ] ||
    { echo "check-forbidden: cannot read TEE_SIGNER_SCRUB_FILE=$TEE_SIGNER_SCRUB_FILE" >&2; exit 2; }
  abs="$(cd "$(dirname "$TEE_SIGNER_SCRUB_FILE")" && pwd)/$(basename "$TEE_SIGNER_SCRUB_FILE")"
  case "$abs" in "$ROOT"/*) echo "check-forbidden: TEE_SIGNER_SCRUB_FILE is inside the tree; keep it outside" >&2; exit 2 ;; esac
  n=0 entries=0
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    case "$line" in '' | '#'*) continue ;; esac
    if [ "${line#b64:}" != "$line" ]; then
      line="$(base64 -d <<<"${line#b64:}" 2>/dev/null)" ||
        { echo "check-forbidden: line $n of TEE_SIGNER_SCRUB_FILE is not base64" >&2; fail=1; continue; }
    fi
    case "$line" in
      [icrx]:*) mode="${line%%:*}" text="${line#?:}" ;;
      *) mode=c text="${line%%$'\t'*}" ;;
    esac
    [ -n "$text" ] || continue
    entries=$((entries + 1))
    case "$mode" in
      i | x) flags=(-l -a -F -i) ;;
      r) flags=(-l -a -E -i) ;;
      *) flags=(-l -a -F) ;;
    esac
    files="$list"
    [ "$mode" != x ] || files="$own"
    hits="$(xargs -0 -r grep "${flags[@]}" -e "$text" -- <"$files" || true)"
    if [ -n "$hits" ]; then
      echo "check-forbidden: entry on line $n of TEE_SIGNER_SCRUB_FILE in:" >&2
      sed 's/^/  /' <<<"$hits" >&2
      fail=1
    fi
  done <"$TEE_SIGNER_SCRUB_FILE"
  scrub=", none of the $entries entries of TEE_SIGNER_SCRUB_FILE"
fi

if [ "$fail" != 0 ]; then
  echo "check-forbidden: FAILED" >&2
  exit 1
fi
echo "check-forbidden: $(tr -cd '\0' <"$list" | wc -c) files, no key block, token or account ID$scrub"
