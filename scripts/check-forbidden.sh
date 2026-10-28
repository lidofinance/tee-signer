#!/usr/bin/env bash
# Tree guard: fails if any file of the tree (text or binary) holds a name or
# marker that must never be in this repo:
#   - names of private projects and personal or private infrastructure,
#   - the markers of the testnet approver reset (a devnet-only image),
#   - a real cloud account ID.
# The name and marker list is base64 below, so that this file does not
# match itself. Decode it with: base64 -d <<<"$PATTERNS"
# Each line is "i:<text>" (any case), "c:<text>" (exact case), "r:<regex>"
# (an extended regular expression, any case) or "x:<text>" (any case, in
# files outside third_party/ folders, whose upstream code may use the word).
#
#   scripts/check-forbidden.sh [dir]        default: this repo
#   TEE_SIGNER_SCRUB_FILE=<file>            also refuse each value of a private
#                                           list (value TAB placeholder per line)
set -euo pipefail
ROOT="$(cd "${1:-$(dirname "${BASH_SOURCE[0]}")/..}" && pwd)"
PATTERNS=aTplcGxpeAppOmZzaGFycC12YwppOmYjIHZhbGlkYXRvcgppOnZjLWRldgppOmlwZXRrb3YKaTpjbG91ZGZsYXJlZAppOmNsb3VkZmxhcmVhY2Nlc3MKaTpjZi1hY2Nlc3MKaTphY2Nlc3NnYXRlCmk6aXZhbnAKaTpuZXh0M3IKYzphcHByb3ZlclJlc2V0SGFzaGVzCmM6YXBwcm92ZXIgcmVzZXQgYXJtZWQKYzpBUFBST1ZFUl9SRVNFVF9IQVNIRVMKYzpWZXJpZnlOZXdTZXQKYzp0cnVzdGVkX3Jlc2V0X2hhc2hlcwpjOmFwcHJvdmVyLXJlc2V0CmM6YXBwcm92ZXJyZXNldAppOnNpZ25lci1zcGlrZS1wcml2YXRlCmk6L2hvbWUvaXZhbgppOm5leHQzCnI6XC50c1wubmV0KFteYS16MC05LV18JCkKcjppdmFuJz9zIGRlY2lzaW9uCng6dGFpbHNjYWxlCng6c2lnbmVyLXNwaWtlCng6c3Bpa2UK
# Account IDs that may appear: AWS documentation examples and all zeros.
ALLOWED_ACCOUNTS="111122223333 123456789012 000000000000"
cd "$ROOT"
list="$(mktemp)" own="$(mktemp)"
trap 'rm -f "$list" "$own"' EXIT
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git ls-files -z -co --exclude-standard
else
  find . -type f -not -path './.git/*' -not -path './build/*' -not -path './logs/*' -print0
fi >"$list"
# The same files without third_party/ folders.
tr '\0' '\n' <"$list" | grep -v -E '(^|/)third_party/' | tr '\n' '\0' >"$own" || true
fail=0
while IFS= read -r line; do
  [ -n "$line" ] || continue
  mode="${line%%:*}" text="${line#*:}"
  case "$mode" in
    i) flags=(-l -a -F -i) ;;
    r) flags=(-l -a -E -i) ;;
    x) flags=(-l -a -F -i) ;;
    *) flags=(-l -a -F) ;;
  esac
  files="$list"
  [ "$mode" != x ] || files="$own"
  hits="$(xargs -0 -r grep "${flags[@]}" -e "$text" -- <"$files" || true)"
  if [ -n "$hits" ]; then
    echo "check-forbidden: forbidden name or marker (base64 line $(base64 -w0 <<<"$line")) in:" >&2
    sed 's/^/  /' <<<"$hits" >&2
    fail=1
  fi
done < <(base64 -d <<<"$PATTERNS")
# AWS account IDs in ARNs.
ids="$(xargs -0 -r grep -ahoE 'arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:[0-9]{12}' -- <"$list" | grep -oE '[0-9]{12}$' | sort -u || true)"
for id in $ids; do
  case " $ALLOWED_ACCOUNTS " in *" $id "*) continue ;; esac
  echo "check-forbidden: an AWS account ID that is not a documentation example in: $(xargs -0 -r grep -alF -e "$id" -- <"$list" | tr '\n' ' ')" >&2
  fail=1
done
if [ -n "${TEE_SIGNER_SCRUB_FILE:-}" ]; then
  while IFS=$'\t' read -r val _; do
    [ -n "$val" ] || continue
    hits="$(xargs -0 -r grep -alF -e "$val" -- <"$list" || true)"
    [ -z "$hits" ] || { echo "check-forbidden: a value of TEE_SIGNER_SCRUB_FILE in: $(tr '\n' ' ' <<<"$hits")" >&2; fail=1; }
  done <"$TEE_SIGNER_SCRUB_FILE"
fi
if [ "$fail" != 0 ]; then
  echo "check-forbidden: FAILED" >&2
  exit 1
fi
echo "check-forbidden: $(tr -cd '\0' <"$list" | wc -c) files, no forbidden name, marker or account ID"
