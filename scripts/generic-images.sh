#!/usr/bin/env bash
# The generic images of the setup phase: one image per cloud for
# every signer and every chain. They hold the runner and the flags the
# design keeps fixed; no chain config, no client CA, no key-release name, no
# store, no signer or network name. Each signer's values come in its setup
# at start, through the platform's channel (governance/docs/setup-phase-cloud-test.md).
# Local only: nothing is pushed or pulled and no cloud is called.
#
#   scripts/generic-images.sh build [DIR]   build the three images and write
#                                           their fingerprints to DIR/fingerprints.txt
#                                           (default build/generic)
#   scripts/generic-images.sh check FILE    compare the current build outputs
#                                           with FILE, the recorded values; FILE
#                                           must hold each name once, in the
#                                           format build writes; a release's
#                                           lane lines chain and
#                                           build_variant must match CHAIN
#                                           and DVT, and variant the images
#
# Check a release with the generic-images.sh of this version or later:
# check refuses a file that lacks any of the names this version writes.
# Files from v0.1.0-rc.1 and rc.2 pass this check; their own tag's check
# does not read the lane lines.
#
# DVT=1 (scripts/common.sh) builds the dvt images: runners with the tag dvt
# and the DVT core, with "-dvt" after the chain's suffix in every name
# (runner-aws-dvt, build/nitro-dvt, build/generic-dvt). Unset, the images
# are the default variant. The fingerprints header names the variant.
#
# CHAIN (scripts/common.sh) picks the build: mainnet when unset. With
# CHAIN=hoodi, devnet or ci-test both work on that chain's non-prod images
# (signer-protocol/buildchain): the same code built with -tags
# nonprod,chain_<chain>, whose governance times run in minutes and which
# start on that chain only. For research and tests, never for real keys.
# Their runners, folders, local names, registry tags and records carry
# "-<chain>": runner-<cloud>-hoodi, build/nitro-hoodi,
# signer-cloud/azure-runner-hoodi, tags generic-hoodi (GCP) and
# generic-hoodi-ts (Azure). CHAIN=devnet
# needs CHAIN_JSON, the devnet's chain config (scripts/build-runner.sh).
#
# What build runs, with the settings fixed here:
#   Nitro  scripts/nitro-eif.sh aarch64 (the EIF for Graviton, built twice by
#          the script), and the parent's hostagent, forwarder and udprelay
#          for arm64
#   Azure  platform-azure/deploy/build-image.sh, then deploy.sh policy
#          in a network namespace with only lo (unshare -rn): az confcom
#          reads the local images and cannot reach a registry. The group
#          is the runner alone (aci-template.json). STDIO=enable: a test
#          image (the group's logs are readable); production uses
#          STDIO=disable, another policy
#   GCP    platform-gcp/deploy/build-image.sh with NETWORK_ENTRY=public;
#          log_redirect is "always" in this image, a test image
# With SIGNER_BUILD_OVERLAY_DIR (non-prod images only) the overlay sets the
# network entries of the devnet images (devnet_generic_images_env).
# The EIF file's own sha256 changes with every build (its
# metadata has the build time); PCR0 to PCR2, which KMS checks, do not. It is
# printed, not compared.
#
# Environment: for the policy, ACR_NAME and VAULT (any names: az confcom runs with --omit-id,
# so the policy does not depend on them; default signeracr and
# signer-vault). Go runs with GOPROXY=off and GOTOOLCHAIN=local, and the
# EIF build uses the local nitro-cli image (NITRO_CLI_REUSE=1): nothing here
# downloads. The pinned sources in third_party/ and the docker images
# (nitro-cli, the NTS toolchain, and what the overlay needs) must be there.
set -euo pipefail
# shellcheck source=common.sh
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

die() { echo "generic-images: $*" >&2; exit 1; }

export GOPROXY=off GOTOOLCHAIN=local NITRO_CLI_REUSE=1
# The chain's suffix: -<chain> for a non-prod chain, nothing for mainnet.
SUFFIX="$(image_suffix)"
# IMAGE_VARIANT=test (default): the test images (Azure STDIO=enable, GCP
# log_redirect always). IMAGE_VARIANT=prod: the production images (STDIO=disable,
# log_redirect never), with their own measurements.
IMAGE_VARIANT="${IMAGE_VARIANT:-test}"
case "$IMAGE_VARIANT" in
  test) export STDIO=enable LOG_REDIRECT=always ;;
  prod) export STDIO=disable LOG_REDIRECT=never ;;
  *) die "IMAGE_VARIANT must be test or prod" ;;
esac
export IMAGE_TAG=generic
unset CLIENT_CA REGION KMS_KEY_ARN MARK_BUCKET MARK_SIGNER MARK_STORE STATE_STORE

# The network settings of the Azure and GCP builds: the overlay's, or none
# (Azure) and public (GCP).
AZ_ENV=() GCP_ENV=(NETWORK_ENTRY=public)
if devnet_has generic_images_env; then
  mapfile -t AZ_ENV < <(devnet_generic_images_env azure)
  mapfile -t GCP_ENV < <(devnet_generic_images_env gcp)
fi
AZ_OUT="$(env ${AZ_ENV[@]+"${AZ_ENV[@]}"} bash -c '. "$1/platform-azure/deploy/common.sh" && echo "$OUT"' _ "$ROOT")"
GCP_OUT="$BUILD/gcp$SUFFIX"
NITRO_OUT="$BUILD/nitro$SUFFIX"

sha() { sha256sum <"$1" | cut -d' ' -f1; }
pcr() { python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["Measurements"][sys.argv[2]])' "$NITRO_OUT/build-enclave-aarch64.json" "$1"; }

# fingerprints: "name value" lines of the current build outputs.
fingerprints() {
  local p
  for p in PCR0 PCR1 PCR2; do echo "nitro.$p $(pcr "$p")"; done
  echo "nitro.runner $(sha "$BUILD/aarch64/bin/runner-aws$SUFFIX")"
  echo "parent.hostagent $(sha "$BUILD/aarch64/bin/hostagent")"
  echo "parent.forwarder $(sha "$BUILD/aarch64/bin/forwarder")"
  echo "parent.udprelay $(sha "$BUILD/aarch64/bin/udprelay")"
  echo "azure.image $(cat "$AZ_OUT/runner.digest")"
  echo "azure.cce_policy $(cat "$AZ_OUT/policy.sha256" 2>/dev/null || echo none)"
  echo "azure.runner $(sha "$BUILD/x86_64/bin/runner-azure$SUFFIX")"
  echo "gcp.image $(cat "$GCP_OUT/runner.digest")"
  echo "gcp.runner $(sha "$BUILD/x86_64/bin/runner-gcp$SUFFIX")"
}

cmd_build() {
  local dir="${1:-$BUILD/generic$SUFFIX}" start
  start=$(date +%s)
  mkdir -p "$dir"
  log "Nitro EIF, arm64 (log $dir/nitro.log)"
  bash "$ROOT/scripts/nitro-eif.sh" aarch64 >"$dir/nitro.log" 2>&1 || { tail -n 30 "$dir/nitro.log"; die "nitro-eif.sh failed"; }
  local p
  for p in PCR0 PCR1 PCR2; do
    grep -q "$p repeats" "$dir/nitro.log" || die "the two EIF builds differ in $p (see $dir/nitro.log)"
  done
  log "Azure image, ${AZ_ENV[*]:-the runner alone} (log $dir/azure.log)"
  env ${AZ_ENV[@]+"${AZ_ENV[@]}"} bash "$ROOT/platform-azure/deploy/build-image.sh" >"$dir/azure.log" 2>&1 || { tail -n 30 "$dir/azure.log"; die "azure build-image.sh failed"; }
  rm -f "$AZ_OUT/policy.sha256"
  log "Azure CCE policy, in a network namespace with only lo (log $dir/azure-policy.log)"
  # shellcheck disable=SC2016 # the inner script's $1, expanded by the inner bash
  env ${AZ_ENV[@]+"${AZ_ENV[@]}"} ACR_NAME="${ACR_NAME:-signeracr}" VAULT="${VAULT:-signer-vault}" \
    unshare -rn bash -c 'ip -o link | grep -qv "lo:" && { echo "the namespace has a link besides lo" >&2; exit 1; }; exec bash "$1" policy' _ \
    "$ROOT/platform-azure/deploy/deploy.sh" >"$dir/azure-policy.log" 2>&1 || { tail -n 30 "$dir/azure-policy.log"; die "deploy.sh policy failed"; }
  [ -s "$AZ_OUT/policy.sha256" ] || die "no $AZ_OUT/policy.sha256"
  log "GCP image, ${GCP_ENV[*]} (log $dir/gcp.log)"
  env "${GCP_ENV[@]}" bash "$ROOT/platform-gcp/deploy/build-image.sh" >"$dir/gcp.log" 2>&1 || { tail -n 30 "$dir/gcp.log"; die "gcp build-image.sh failed"; }
  {
    echo "# generic $(chain_is_prod "$CHAIN" || echo "$CHAIN ")images, built $(date -u +%Y-%m-%dT%H:%M:%SZ) from $(git -C "$ROOT" rev-parse --short HEAD)$([ -z "$(git -C "$ROOT" status --porcelain -- . ':!build' ':!logs')" ] || echo ' with local changes')"
    echo "# $(head -n 1 "$BUILD/core-src/SOURCE.txt")"
    echo "# variant $IMAGE_VARIANT, build variant $(variant), builder ${SIGNER_BUILDER_IMAGE:-none (host toolchain)}"
    echo "# go $(go env GOVERSION), nitro-cli $NITRO_CLI_TAG image $(docker image inspect "signer-cloud/nitro-cli:$NITRO_CLI_TAG-$HOST_ARCH" --format '{{.Id}}')$(devnet_hook generic_images_note)"
    fingerprints
  } >"$dir/fingerprints.txt"
  echo "nitro EIF file sha256 $(sha "$NITRO_OUT/runner-aarch64.eif") (changes with every build)" >"$dir/eif-file.txt"
  cat "$dir/fingerprints.txt"
  log "done in $(( $(date +%s) - start )) s: $dir/fingerprints.txt"
}

# The names fingerprints writes, in its order.
FINGERPRINT_NAMES=(nitro.PCR0 nitro.PCR1 nitro.PCR2 nitro.runner parent.hostagent parent.forwarder
  parent.udprelay azure.image azure.cce_policy azure.runner gcp.image gcp.runner)

# fingerprint_format NAME: the regex a value of NAME must match, as
# fingerprints writes it; fails for a name it does not write.
fingerprint_format() {
  case "$1" in
    nitro.PCR0 | nitro.PCR1 | nitro.PCR2) echo '^[0-9a-f]{96}$' ;;
    nitro.runner | parent.hostagent | parent.forwarder | parent.udprelay | azure.runner | gcp.runner) echo '^[0-9a-f]{64}$' ;;
    azure.image | gcp.image) echo '^sha256:[0-9a-f]{64}$' ;;
    azure.cce_policy) echo '^([0-9a-f]{64}|none)$' ;;
    *) return 1 ;;
  esac
}

# check FILE: FILE holds each name of fingerprints once, as "name value"
# with the value in the format fingerprints writes, and each value equals
# the current build's. The lane lines variant, build_variant, commit and
# chain, which release/release-build.sh adds to a release's
# fingerprints-<chain>.txt, may each appear once, with a value
# release-build.sh writes. chain and build_variant, when there, must
# equal this run's CHAIN and variant (from DVT), and variant the one
# release/image-variant.py reads from the GCP image and the Azure
# policies of this build (IMAGE_VARIANT plays no part); a
# commit other than the checked-out one only gets a note. A release file
# without build_variant is compared as default; any other lane line that
# is not there is not asked for. Blank lines and
# lines that start with # are skipped; any other line refuses the whole
# file before anything is compared. FILE is data: it is read with read and
# compared in the shell, and no part of it goes into a sed program or a
# command.
# output_variant: the variant of this build's GCP image and Azure
# policies, read by release/image-variant.py as release-build.sh checks
# it, or "unknown (reason)".
output_variant() {
  local fp out policies
  fp="$(mktemp)"
  fingerprints >"$fp"
  shopt -s nullglob
  policies=("$AZ_OUT"/signer-*/policy.rego)
  shopt -u nullglob
  if out="$(python3 -I "$ROOT/release/image-variant.py" detect "$fp" "$GCP_OUT/runner.oci.tar" ${policies[@]+"${policies[@]}"} 2>&1)"; then
    echo "$out"
  else
    echo "unknown ($(printf '%s' "$out" | tail -n 1))"
  fi
  rm -f "$fp"
}

cmd_check() {
  # The format checks use [0-9], [a-f] and [a-z]; in another locale these
  # match more than ASCII. Only check runs in C: build keeps the caller's
  # locale for its tools.
  export LC_ALL=C
  local file="${1:-}" ok=1 line name want got format n=0
  [ -n "$file" ] || die "check needs FILE, the recorded fingerprints"
  [ -s "$file" ] || die "no $file"
  local -A rec=() cur=() lane=()
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    case "$line" in "" | \#*) continue ;; esac
    if [[ "$line" =~ ^(variant|build_variant|commit|chain)\ ([^[:space:]]+)$ ]]; then
      name="${BASH_REMATCH[1]}" want="${BASH_REMATCH[2]}"
      case "$name" in
        variant) [[ "$want" =~ ^(test|prod)$ ]] ;;
        build_variant) [[ "$want" =~ ^(default|dvt)$ ]] ;;
        commit) [[ "$want" =~ ^[0-9a-f]{40}$ ]] ;;
        chain) [[ " $CHAINS " == *" $want "* ]] ;;
      esac || die "$file line $n: $name value is not one release-build.sh writes"
      [ -z "${lane[$name]+x}" ] || die "$file line $n: $name given twice"
      lane[$name]="$want"
      continue
    fi
    [[ "$line" =~ ^([a-z]+\.[A-Za-z0-9_]+)\ ([^[:space:]]+)$ ]] || die "$file line $n: not a \"name value\" line"
    name="${BASH_REMATCH[1]}" want="${BASH_REMATCH[2]}"
    format="$(fingerprint_format "$name")" || die "$file line $n: unknown name $name"
    [[ "$want" =~ $format ]] || die "$file line $n: $name value is not in the format build writes"
    [ -z "${rec[$name]+x}" ] || die "$file line $n: $name given twice"
    rec[$name]="$want"
  done <"$file"
  for name in "${FINGERPRINT_NAMES[@]}"; do
    [ -n "${rec[$name]+x}" ] || die "$file has no $name"
  done
  while read -r name got; do cur[$name]="$got"; done < <(fingerprints)
  for name in "${FINGERPRINT_NAMES[@]}"; do
    want="${rec[$name]}" got="${cur[$name]:-}"
    if [ "$got" = "$want" ]; then echo "ok    $name ${want:0:24}..."; else echo "FAIL  $name '$got', want $want"; ok=0; fi
  done
  # A release file without build_variant (v0.1.0-rc.2) is of a default
  # lane, as release/measurements.py reads it. A file without lane lines
  # is not a release file and gets none.
  [ "${#lane[@]}" = 0 ] || [ -n "${lane[build_variant]+x}" ] || lane[build_variant]=default
  local -A run=([chain]="$CHAIN" [build_variant]="$(variant)")
  [ -z "${lane[variant]+x}" ] || run[variant]="$(output_variant)"
  local -A from=([chain]=CHAIN [variant]="the GCP image and Azure policies" [build_variant]=DVT)
  for name in chain variant build_variant; do
    [ -n "${lane[$name]+x}" ] || continue
    want="${lane[$name]}" got="${run[$name]}"
    if [ "$got" = "$want" ]; then echo "ok    $name $want"; else echo "FAIL  $name '$got' (from ${from[$name]}), want $want"; ok=0; fi
  done
  if [ -n "${lane[commit]+x}" ]; then
    want="${lane[commit]}"
    # HEAD only of the repo whose top is ROOT: without .git, git would
    # walk up to an outer repo and give its HEAD.
    got=unknown
    if [ "$(realpath -e -- "$(git -C "$ROOT" rev-parse --show-toplevel 2>/dev/null)" 2>/dev/null)" = "$(realpath -e -- "$ROOT")" ]; then
      got="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null)" || got=unknown
    fi
    if [ "$got" = "$want" ]; then echo "ok    commit $want"; else echo "note  commit $want, not the checked-out commit $got (not compared)"; fi
  fi
  [ "$ok" = 1 ] || die "the build differs from $file"
}

case "${1:-}" in
  build) shift; cmd_build "$@" ;;
  check) shift; cmd_check "$@" ;;
  *) sed -n '2,/^set -euo/p' "$0" | sed '$d;s/^# \{0,1\}//' >&2; exit 2 ;;
esac
