#!/usr/bin/env bash
# Dependency check: each runner binary links the code of its own cloud and
# none of the others' (tee-signer/platforms.go). It exits non-zero on a leak, so
# a build that breaks the split fails.
#
#   scripts/check-deps.sh            from the sources: go list -deps, no build needed
#   scripts/check-deps.sh ARCH...    also the binaries in build/ARCH/bin (go version -m)
#
# For each runner build (the list is in common.sh):
#
#   1. Every package that is not the standard library is ours (github.com/lidofinance/tee-signer/...)
#      or in a module the build's clouds may use. The AWS SDK, smithy-go,
#      hf/nsm, mdlayher/vsock and socket and golang.org/x/{net,sync,sys} are
#      for the AWS build only, fxamacker/cbor and x448/float16 too (the
#      Nitro verifier's CBOR parser). The cloud builds (tag nts) also hold
#      the NTS library (beevik/nts, beevik/ntp, secure-io/siv-go, aead/cmac)
#      and, through it, golang.org/x/net and x/sys. The dev builds hold
#      nothing third-party but the embedded root certificates
#      (x509roots/fallback).
#   2b. The attestation verifier of the build's own platform only (tag
#      verifierselect): attestation-verify/azureid with platform_azure,
#      github.com/lidofinance/tee-signer/attestation-verify with any cloud
#      platform, none in the dev build.
#   2. No package of another cloud: the nitro platform and the host agent
#      only in AWS builds, azure and gcp only in theirs.
#   3. The build's own platform package is there, so a tag that stopped
#      working does not pass as a clean build.
#   4. The NTS clock (github.com/lidofinance/tee-signer/trusted-time/nts, tag nts) is in the cloud builds
#      and not in the dev builds; the UDP relay's package only in AWS builds.
#
# With a binary, also: its -tags setting is the expected one, and the modules
# it links (go version -m) are on the same lists as in 1.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

fail=0
bad() { echo "check-deps: $*" >&2; fail=1; }

# clouds_of <tags>: the platforms in a tag list, for example "aws dev".
clouds_of() {
  local t out=()
  for t in ${1//,/ }; do
    case "$t" in platform_*) out+=("${t#platform_}") ;; esac
  done
  echo "${out[*]}"
}

# cloud_in <clouds> <a|b>: true if one of the alternatives is among the clouds.
cloud_in() {
  local c alt
  for alt in ${2//|/ }; do
    for c in $1; do [ "$c" = "$alt" ] && return 0; done
  done
  return 1
}

# module_ok <clouds> <module path> <nts: 1 for a build with the tag nts>
module_ok() {
  case "$2" in
    github.com/lidofinance/tee-signer/*|golang.org/x/crypto/x509roots/fallback) return 0 ;;
    # The NTS clock's library (trusted-time/nts): every cloud build.
    github.com/beevik/nts|github.com/beevik/ntp|github.com/secure-io/siv-go|github.com/aead/cmac)
      [ "${3:-0}" = 1 ] && return 0 ;;
    # x/net and x/sys: the AWS SDK, and the NTP library's socket options.
    golang.org/x/net|golang.org/x/sys)
      { cloud_in "$1" aws || [ "${3:-0}" = 1 ]; } && return 0 ;;
    # The Nitro verifier's CBOR parser: the AWS platform.
    github.com/fxamacker/cbor/*|github.com/x448/float16)
      cloud_in "$1" aws && return 0 ;;
    github.com/aws/*|github.com/hf/nsm|github.com/mdlayher/*|golang.org/x/sync)
      cloud_in "$1" aws && return 0 ;;
  esac
  return 1
}

# verifier_package_ok <clouds> <import path>: verifier code only in the
# builds whose platform needs it.
verifier_package_ok() {
  case "$2" in
    github.com/lidofinance/tee-signer/attestation-verify/azureid) cloud_in "$1" azure ;;
    github.com/lidofinance/tee-signer/attestation-verify) cloud_in "$1" "azure|aws|gcp" ;;
    *) return 0 ;;
  esac
}

# package_cloud <import path>: the cloud a package of ours belongs to, or
# nothing. jwtclaims is shared by azure and gcp.
package_cloud() {
  case "$1" in
    # The UDP relay: its client is the Nitro enclave's NTP path.
    github.com/lidofinance/tee-signer/platform-aws/nitro|github.com/lidofinance/tee-signer/platform-aws/nitro/*|github.com/lidofinance/tee-signer/platform-aws/hostagent|github.com/lidofinance/tee-signer/platform-aws/hostagent/*|github.com/lidofinance/tee-signer/platform-aws/udprelay) echo aws ;;
    # NTS test servers never belong in a binary.
    github.com/lidofinance/tee-signer/trusted-time/nts/ntstest) echo none ;;
    github.com/lidofinance/tee-signer/platform-azure/azure|github.com/lidofinance/tee-signer/platform-azure/azure/*) echo azure ;;
    github.com/lidofinance/tee-signer/platform-gcp/gcp|github.com/lidofinance/tee-signer/platform-gcp/gcp/*) echo gcp ;;
    github.com/lidofinance/tee-signer/platform/jwtclaims) echo "azure|gcp" ;;
    # The mark log clients: each cloud's object store only in its own build.
    github.com/lidofinance/tee-signer/platform-aws/s3log) echo aws ;;
    github.com/lidofinance/tee-signer/platform-gcp/gcslog) echo gcp ;;
    github.com/lidofinance/tee-signer/platform-azure/azlog) echo azure ;;
    # Test fakes and the shared test suite never belong in a binary.
    github.com/lidofinance/tee-signer/slashing-log/wormfake|github.com/lidofinance/tee-signer/slashing-log/logtest) echo none ;;
  esac
}

# linked <file of "package module imports..." lines> <package>
linked() { awk -v w="$2" '$1 == w { found = 1 } END { exit !found }' "$1"; }

# check_source <name> <goarch>
check_source() {
  local name="$1" goarch="$2" tags clouds nts list viol pkg mod cloud c want n
  tags="netgo,osusergo,$(runner_tags "$name")"
  clouds="$(clouds_of "$tags")"
  nts=0; has_nts "$name" && nts=1
  list="$(mktemp)"
  viol="$(mktemp)"
  # Lines of: import path, module path, imports. The standard library is left out.
  (cd "$ROOT/tee-signer" && GOOS=linux GOARCH="$goarch" CGO_ENABLED=1 \
    go list -deps -tags "$tags" -f '{{if not .Standard}}{{.ImportPath}} {{with .Module}}{{.Path}}{{else}}-{{end}} {{join .Imports " "}}{{end}}' .) >"$list"
  # viol: the packages this build must not link, with the reason.
  while read -r pkg mod _; do
    [ -n "$pkg" ] || continue
    cloud="$(package_cloud "$pkg")"
    if ! module_ok "$clouds" "$mod" "$nts"; then
      echo "$pkg $mod" >>"$viol"
    elif ! verifier_package_ok "$clouds" "$pkg"; then
      echo "$pkg verifier-of-another-cloud" >>"$viol"
    elif [ -n "$cloud" ] && ! cloud_in "$clouds" "$cloud"; then
      echo "$pkg code-of-$cloud" >>"$viol"
    fi
  done <"$list"
  # The CBOR modules off the AWS platform: only github.com/lidofinance/tee-signer/attestation-verify (and
  # those modules' own packages) may import them.
  if ! cloud_in "$clouds" aws; then
    awk 'NR == FNR { if ($2 ~ /^github.com\/fxamacker\/cbor\// || $2 == "github.com/x448/float16") v[$1] = 1; next }
         $1 == "github.com/lidofinance/tee-signer/attestation-verify" || ($1 in v) { next }
         { for (i = 3; i <= NF; i++) if ($i in v) print $1 " CBOR-outside-github.com/lidofinance/tee-signer/attestation-verify" }' "$list" "$list" >>"$viol"
  fi
  if [ -s "$viol" ]; then
    n="$(wc -l <"$viol")"
    bad "$name ($goarch): $n packages that a build for ($clouds) must not link, from: $(awk '{ print $2 }' "$viol" | sort -u | tr '\n' ' ')"
    # The way in: a package of the build that imports one of them.
    awk 'NR == FNR { v[$1] = 1; next }
         !($1 in v) { for (i = 3; i <= NF; i++) if ($i in v) print "    " $1 " imports " $i }' "$viol" "$list" >&2
  fi
  for c in $clouds; do
    case "$c" in
      aws) want=github.com/lidofinance/tee-signer/platform-aws/nitro ;;
      azure) want=github.com/lidofinance/tee-signer/platform-azure/azure ;;
      gcp) want=github.com/lidofinance/tee-signer/platform-gcp/gcp ;;
      dev) want=github.com/lidofinance/tee-signer/platform/dev ;;
      *) bad "$name: unknown platform tag platform_$c"; continue ;;
    esac
    linked "$list" "$want" || bad "$name ($goarch): $want is not linked, so the tag platform_$c did nothing"
  done
  # The NTS library (tag nts) in the cloud builds, not in the dev ones.
  if has_nts "$name"; then
    linked "$list" github.com/lidofinance/tee-signer/trusted-time/nts || bad "$name ($goarch): built with the tag nts but github.com/lidofinance/tee-signer/trusted-time/nts is not linked"
  elif linked "$list" github.com/lidofinance/tee-signer/trusted-time/nts; then
    bad "$name ($goarch): links github.com/lidofinance/tee-signer/trusted-time/nts without the tag nts"
  fi
  if cloud_in "$clouds" aws; then
    for want in github.com/aws/aws-sdk-go-v2/service/kms github.com/hf/nsm github.com/mdlayher/vsock github.com/fxamacker/cbor/v2; do
      linked "$list" "$want" || bad "$name ($goarch): $want is not linked"
    done
  fi
  rm -f "$list" "$viol"
}

# check_binary <file> <name>
check_binary() {
  local file="$1" name="$2" want got clouds nts mod
  want="netgo,osusergo,$(runner_tags "$name")"
  clouds="$(clouds_of "$want")"
  nts=0; has_nts "$name" && nts=1
  got="$(go version -m "$file" | awk '$1 == "build" && $2 ~ /^-tags=/ { sub(/^-tags=/, "", $2); print $2 }')"
  [ "$got" = "$want" ] || bad "$file: built with -tags=$got, expected -tags=$want"
  while read -r mod; do
    module_ok "$clouds" "$mod" "$nts" || bad "$file links the module $mod, and a build for: $clouds must not"
  done < <(go version -m "$file" | awk '$1 == "dep" { print $2 }')
}

for goarch in amd64 arm64; do
  for name in "${RUNNER_BINS[@]}"; do
    check_source "$name" "$goarch"
  done
done
for arch in "$@"; do
  for name in "${RUNNER_BINS[@]}"; do
    file="$BUILD/$arch/bin/$name"
    if [ -f "$file" ]; then check_binary "$file" "$name"; else bad "$file: no such binary (scripts/build-runner.sh builds it)"; fi
  done
done

if [ "$fail" != 0 ]; then
  echo "check-deps: FAILED: a runner build holds code of a cloud it does not run on" >&2
  exit 1
fi
log "check-deps: the ${#RUNNER_BINS[@]} runner builds hold only the code of their own cloud"
