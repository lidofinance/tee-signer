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
#   scripts/generic-images.sh check [FILE]  compare the current build outputs
#                                           with FILE (default cloud/generic-images.txt,
#                                           the recorded values)
#
# With IMAGE_FLAVOR=testnet both work on the
# testnet images (signer-protocol/buildflavor): the same code built with -tags
# testnet, whose governance times run in minutes and which start on devnets,
# Hoodi, Sepolia and Chiado only. For research, never for real keys. Their
# runners, folders, local names, registry tags and records carry "-testnet":
# runner-<cloud>-testnet, build/nitro-testnet, signer-cloud/azure-runner-testnet,
# tags generic-testnet (GCP) and generic-testnet-ts (Azure),
# cloud/generic-images-testnet.txt.
#
# What build runs, with the settings fixed here:
#   Nitro  scripts/nitro-eif.sh aarch64 (the EIF for Graviton, built twice by
#          the script), and the parent's hostagent, forwarder and udprelay
#          for arm64
#   Azure  platform-azure/deploy/build-image.sh, then, when a network entry exists,
#          deploy.sh policy in a network namespace with only lo (unshare
#          -rn): az confcom reads the local images and cannot reach a
#          registry. STDIO=enable: a test image (the group's logs are
#          readable); production uses STDIO=disable, another policy
#   GCP    platform-gcp/deploy/build-image.sh with NETWORK_ENTRY=public;
#          log_redirect is "always" in this image, a test image
# This tree has no Azure network entry, so without a build
# overlay there is no Azure CCE policy (azure.cce_policy none). With
# SIGNER_BUILD_OVERLAY_DIR (testnet images only) the overlay sets the
# network entries of the devnet images (devnet_generic_images_env).
# Every image build needs a passed handover gate (scripts/handover-gate.sh;
# common.sh require_handover_gate). The EIF file's own sha256 changes with every build (its
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
# The flavour: -testnet or nothing.
export IMAGE_FLAVOR
SUFFIX="$(image_suffix)"
export IMAGE_TAG=generic STDIO=enable
unset CHAIN CHAIN_JSON CLIENT_CA REGION KMS_KEY_ARN MARK_BUCKET MARK_SIGNER MARK_STORE STATE_STORE

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
RECORD="$ROOT/cloud/generic-images$SUFFIX.txt"

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
  log "Azure image, ${AZ_ENV[*]:-no network entry} (log $dir/azure.log)"
  env ${AZ_ENV[@]+"${AZ_ENV[@]}"} bash "$ROOT/platform-azure/deploy/build-image.sh" >"$dir/azure.log" 2>&1 || { tail -n 30 "$dir/azure.log"; die "azure build-image.sh failed"; }
  rm -f "$AZ_OUT/policy.sha256"
  if [ ${#AZ_ENV[@]} = 0 ]; then
    log "no Azure CCE policy: this tree has no Azure network entry (the build overlay has its own)"
  else
  log "Azure CCE policy, in a network namespace with only lo (log $dir/azure-policy.log)"
  # shellcheck disable=SC2016 # the inner script's $1, expanded by the inner bash
  env "${AZ_ENV[@]}" ACR_NAME="${ACR_NAME:-signeracr}" VAULT="${VAULT:-signer-vault}" \
    unshare -rn bash -c 'ip -o link | grep -qv "lo:" && { echo "the namespace has a link besides lo" >&2; exit 1; }; exec bash "$1" policy' _ \
    "$ROOT/platform-azure/deploy/deploy.sh" >"$dir/azure-policy.log" 2>&1 || { tail -n 30 "$dir/azure-policy.log"; die "deploy.sh policy failed"; }
  [ -s "$AZ_OUT/policy.sha256" ] || die "no $AZ_OUT/policy.sha256"
  fi
  log "GCP image, ${GCP_ENV[*]} (log $dir/gcp.log)"
  env "${GCP_ENV[@]}" bash "$ROOT/platform-gcp/deploy/build-image.sh" >"$dir/gcp.log" 2>&1 || { tail -n 30 "$dir/gcp.log"; die "gcp build-image.sh failed"; }
  {
    echo "# generic $([ "$IMAGE_FLAVOR" = default ] || echo "$IMAGE_FLAVOR ")images, built $(date -u +%Y-%m-%dT%H:%M:%SZ) from $(git -C "$ROOT" rev-parse --short HEAD)$([ -z "$(git -C "$ROOT" status --porcelain -- . ':!build' ':!logs')" ] || echo ' with local changes')"
    echo "# $(head -n 1 "$BUILD/core-src/SOURCE.txt")"
    echo "# go $(go env GOVERSION), nitro-cli $NITRO_CLI_TAG image $(docker image inspect "signer-cloud/nitro-cli:$NITRO_CLI_TAG-$HOST_ARCH" --format '{{.Id}}')$(devnet_hook generic_images_note)"
    fingerprints
  } >"$dir/fingerprints.txt"
  echo "nitro EIF file sha256 $(sha "$NITRO_OUT/runner-aarch64.eif") (changes with every build)" >"$dir/eif-file.txt"
  cat "$dir/fingerprints.txt"
  log "done in $(( $(date +%s) - start )) s: $dir/fingerprints.txt"
}

# check [FILE]: every "name value" line of FILE equals the current build's.
cmd_check() {
  local file="${1:-$RECORD}" ok=1 name want got
  [ -s "$file" ] || die "no $file"
  while read -r name want; do
    case "$name" in "" | \#*) continue ;; esac
    got="$(fingerprints | sed -n "s/^$name //p")"
    if [ "$got" = "$want" ]; then echo "ok    $name ${want:0:24}..."; else echo "FAIL  $name '$got', want $want"; ok=0; fi
  done <"$file"
  [ "$ok" = 1 ] || die "the build differs from $file"
}

case "${1:-}" in
  build) shift; cmd_build "$@" ;;
  check) shift; cmd_check "$@" ;;
  *) sed -n '2,/^set -euo/p' "$0" | sed '$d;s/^# \{0,1\}//' >&2; exit 2 ;;
esac
