#!/usr/bin/env bash
# Builds the docker image "signer-cloud/nitro-cli:<tag>-<blobs arch>" with
# nitro-cli compiled from the pinned source (Rust inside docker, nothing
# installed on the host) and the kernel/init blobs of one arch baked in.
# The source gets platform-aws/deploy/nitro-cli/target-arch.patch (a named build
# context), so nitro-cli can build an EIF for the other arch: nitro-eif.sh
# mounts that arch's blob set over the baked one and sets
# NITRO_CLI_TARGET_ARCH. Idempotent: docker reuses cached layers.
#
# Usage: nitro-cli-image.sh [x86_64|aarch64]   default: host arch. Keep the
# default. The image is the host arch's nitro-cli with the host arch's blobs,
# and builds EIFs for both arches. Another value only changes the baked
# blobs and the tag, and makes docker rebuild the apt layer (network).
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

blobs="${1:-$HOST_ARCH}"
bash "$ROOT/scripts/fetch.sh" --nitro
IMAGE="signer-cloud/nitro-cli:$NITRO_CLI_TAG-$blobs"
log "building $IMAGE (nitro-cli for $HOST_ARCH, enclave blobs for $blobs)"
docker build -q \
  -f "$ROOT/platform-aws/deploy/nitro-cli/Dockerfile" \
  --build-arg "BLOBS_ARCH=$blobs" \
  --build-context "patches=$ROOT/platform-aws/deploy/nitro-cli" \
  -t "$IMAGE" "$NITRO_CLI_DIR"
docker run --rm "$IMAGE" --version
