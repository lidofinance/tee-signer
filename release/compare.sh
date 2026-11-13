#!/usr/bin/env bash
# Compares two release lanes (release/release-build.sh outputs) of one chain:
#
#   release/compare.sh DIST_A DIST_B
#
# Every file must be byte-identical, except the EIF: nitro-cli writes the
# build time into its metadata, so the EIF file differs on every build while
# PCR0 to PCR2 do not. For the EIF the PCRs of build-enclave.json are
# compared instead (they are in fingerprints-*.txt too). The comment lines of
# fingerprints-*.txt (build time, host) are skipped, and so is the id of the
# local nitro-cli image in the Nitro inputs record.
#
# First, in each folder, every file must be listed in SHA256SUMS and match
# it, and each PCR must be 96 hex digits.
set -euo pipefail
shopt -s nullglob
a="${1:?usage: compare.sh DIST_A DIST_B}" b="${2:?}"
die() { echo "compare: $*" >&2; exit 1; }
for d in "$a" "$b"; do
  [ -s "$d/SHA256SUMS" ] || die "no $d/SHA256SUMS"
  (cd "$d" && sha256sum --quiet --strict -c SHA256SUMS) || die "$d does not match its SHA256SUMS"
  [ "$(cd "$d" && find . -mindepth 1 -maxdepth 1 ! -name SHA256SUMS -printf '%f\n' | LC_ALL=C sort)" = \
    "$(awk '{print $2}' "$d/SHA256SUMS" | LC_ALL=C sort)" ] || die "the files in $d are not the ones its SHA256SUMS lists"
done
fps=("$a"/fingerprints-*.txt) eifs=("$a"/*.build-enclave.json)
[ ${#fps[@]} -gt 0 ] || die "no fingerprints-*.txt in $a"
[ ${#eifs[@]} -gt 0 ] || die "no *.build-enclave.json in $a"
fail=0
strip() { grep -v '^#' "$1"; }
for f in "${fps[@]}"; do
  n="${f##*/}"
  if diff <(strip "$f") <(strip "$b/$n"); then echo "same  $n"; else echo "DIFF  $n"; fail=1; fi
done
while read -r sum name; do
  case "$name" in
    *.eif) echo "skip  $name (build time in the EIF metadata; PCRs compared above)"; continue ;;
    fingerprints-*) continue ;;
    runner-aws-*.inputs.txt)
      # The local nitro-cli image's id differs per build (its PCR1 kernel
      # does not); the rest of the record must match.
      if diff <(sed 's/ image sha256:[0-9a-f]*$//' "$a/$name") <(sed 's/ image sha256:[0-9a-f]*$//' "$b/$name") >/dev/null; then
        echo "same  $name (nitro-cli image id aside)"
      else
        echo "DIFF  $name"; fail=1
      fi
      continue ;;
  esac
  other="$(awk -v n="$name" '$2 == n { print $1 }' "$b/SHA256SUMS")"
  if [ "$sum" = "$other" ]; then echo "same  $name"; else echo "DIFF  $name ${sum:0:16} vs ${other:0:16}"; fail=1; fi
done <"$a/SHA256SUMS"
[ "$(awk '{print $2}' "$a/SHA256SUMS")" = "$(awk '{print $2}' "$b/SHA256SUMS")" ] || { echo "DIFF  the file lists differ"; fail=1; }
for j in "${eifs[@]}"; do
  n="${j##*/}"
  for p in PCR0 PCR1 PCR2; do
    x="$(jq -r ".Measurements.$p" "$j" || true)" y="$(jq -r ".Measurements.$p" "$b/$n" || true)"
    if ! [[ "$x" =~ ^[0-9a-f]{96}$ && "$y" =~ ^[0-9a-f]{96}$ ]]; then
      echo "BAD   $n $p is not 96 hex digits: '$x', '$y'"; fail=1
    elif [ "$x" != "$y" ]; then
      echo "DIFF  $n $p"; fail=1
    fi
  done
done
[ "$fail" = 0 ] || { echo "compare: the two lanes differ" >&2; exit 1; }
echo "compare: the two lanes are identical (EIF: same PCRs)"
