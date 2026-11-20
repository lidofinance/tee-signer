#!/usr/bin/env bash
# Offline test of scripts/generic-images.sh check FILE: the recorded values
# of a build pass, a differing value fails, and the lines of FILE are data:
# a name in FILE never becomes part of a sed program. FILE can come from another party (a release's published
# fingerprints-<chain>.txt, release/release-build.sh), so a hostile line
# must not run a command or write a file before the check reports FAIL.
#
# The script runs from a copy of itself and the two common.sh files it
# sources, in a temporary folder whose build/ holds fake build outputs; no
# image is built, nothing outside that folder is written. The case with
# sed's e command needs GNU sed and is skipped, with a line saying so,
# without it; the case with the w flag runs with any sed.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
pass=0
fail=0
ok() { pass=$((pass + 1)); echo "PASS  $*"; }
bad() { fail=$((fail + 1)); echo "FAIL  $*"; }

R="$T/repo"
mkdir -p "$R/scripts" "$R/platform-azure/deploy"
cp "$ROOT/scripts/generic-images.sh" "$ROOT/scripts/common.sh" "$R/scripts/"
cp "$ROOT/platform-azure/deploy/common.sh" "$R/platform-azure/deploy/"

# Fake outputs of a mainnet build of the default variant.
B="$R/build"
mkdir -p "$B/nitro" "$B/aarch64/bin" "$B/x86_64/bin" "$B/azure" "$B/gcp"
printf '{"Measurements": {"HashAlgorithm": "Sha384 { ... }", "PCR0": "%s", "PCR1": "%s", "PCR2": "%s"}}\n' \
  "$(printf 'a%.0s' {1..96})" "$(printf 'b%.0s' {1..96})" "$(printf 'c%.0s' {1..96})" >"$B/nitro/build-enclave-aarch64.json"
for f in aarch64/bin/runner-aws aarch64/bin/hostagent aarch64/bin/forwarder aarch64/bin/udprelay x86_64/bin/runner-azure x86_64/bin/runner-gcp; do
  echo "fake $f" >"$B/$f"
done
echo "sha256:$(printf '1%.0s' {1..64})" >"$B/azure/runner.digest"
printf '2%.0s' {1..64} >"$B/azure/policy.sha256"
echo "sha256:$(printf '3%.0s' {1..64})" >"$B/gcp/runner.digest"
sha() { sha256sum <"$1" | cut -d' ' -f1; }
{
  echo "# generic images, as generic-images.sh build writes them"
  echo "nitro.PCR0 $(printf 'a%.0s' {1..96})"
  echo "nitro.PCR1 $(printf 'b%.0s' {1..96})"
  echo "nitro.PCR2 $(printf 'c%.0s' {1..96})"
  echo "nitro.runner $(sha "$B/aarch64/bin/runner-aws")"
  echo "parent.hostagent $(sha "$B/aarch64/bin/hostagent")"
  echo "parent.forwarder $(sha "$B/aarch64/bin/forwarder")"
  echo "parent.udprelay $(sha "$B/aarch64/bin/udprelay")"
  echo "azure.image sha256:$(printf '1%.0s' {1..64})"
  echo "azure.cce_policy $(printf '2%.0s' {1..64})"
  echo "azure.runner $(sha "$B/x86_64/bin/runner-azure")"
  echo "gcp.image sha256:$(printf '3%.0s' {1..64})"
  echo "gcp.runner $(sha "$B/x86_64/bin/runner-gcp")"
} >"$T/fp.txt"

# check FILE: generic-images.sh check FILE on the fake build; output in $T/out.
check() { env -u CHAIN -u CHAIN_JSON -u DVT -u SIGNER_BUILD_OVERLAY_DIR bash "$R/scripts/generic-images.sh" check "$1" >"$T/out" 2>&1; }
show() { sed 's/^/      /' "$T/out"; }

if check "$T/fp.txt" && [ "$(grep -c '^ok ' "$T/out")" = 12 ]; then
  ok "check: the recorded values of the build, ok for each of the 12"
else
  bad "check: the recorded values of the build do not pass"; show
fi
sed 's/^parent.forwarder .*/parent.forwarder 00/' "$T/fp.txt" >"$T/fp-diff.txt"
if ! check "$T/fp-diff.txt" && grep -q "^FAIL  parent.forwarder '" "$T/out" && [ "$(grep -c '^ok ' "$T/out")" = 11 ]; then
  ok "check: one differing value fails, with its name"
else
  bad "check: a differing value of parent.forwarder"; show
fi

# A name in FILE went unescaped into
# "sed -n s/^NAME //p". sed's w flag takes the rest of the program line as
# a file name, so the name x//w<dir>/w writes the file "<dir>/w /p", here
# in a folder "w " made for it.
mkdir "$T/w "
{ cat "$T/fp.txt"; echo "x//w$T/w 00"; } >"$T/fp-w.txt"
rc=0
check "$T/fp-w.txt" || rc=$?
if [ ! -e "$T/w /p" ] && [ "$rc" != 0 ]; then
  ok "check: a name with sed's w flag writes no file and fails"
else
  bad "check: a name in FILE is run as sed code: the w flag wrote $T/w /p (exit $rc)"; show
fi
# The same with GNU sed's e command: the name runs a shell command.
if sed --version 2>/dev/null | grep -q GNU; then
  # shellcheck disable=SC2016 # ${IFS} is for the shell that sed's e starts
  { cat "$T/fp.txt"; echo 'x//;etouch${IFS}'"$T"'/e-ran;# 00'; } >"$T/fp-e.txt"
  rc=0
  check "$T/fp-e.txt" || rc=$?
  if [ ! -e "$T/e-ran" ] && [ "$rc" != 0 ]; then
    ok "check: a name with sed's e command runs nothing and fails"
  else
    bad "check: a name in FILE is run as sed code: the e command ran touch (exit $rc)"; show
  fi
else
  echo "skip  check: sed's e command (sed is not GNU sed)"
fi

echo "generic-images-test: $pass passed, $fail failed"
[ "$fail" = 0 ]
