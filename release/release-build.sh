#!/usr/bin/env bash
# One build lane of a release, and the command an approver runs to rebuild a release on their own machine:
#
#   CHAIN=mainnet IMAGE_VARIANT=prod release/release-build.sh DIST
#
# At the root of a clean checkout of the tagged commit. Steps:
#   1. build the release builder image (release/builder.Dockerfile), no cache,
#   2. fetch the Go modules into build/gomod (network: the Go proxy, go.sum),
#      the pinned nitro-cli source and its image (network: GitHub, crates.io,
#      Debian), the NTS crates (network: crates.io, Cargo.lock),
#   3. scripts/generic-images.sh build with SIGNER_BUILDER_IMAGE set: the
#      runners and parent tools in the builder, offline, then the three
#      images, each built twice,
#   4. copy what a release ships into DIST, with DIST/SHA256SUMS.
#
# Needs Docker with the containerd image store and buildx, qemu-user-static
# (binfmt_misc, F flag) for the arm64 linuxkit, az with the confcom
# extension at the version of AZ_CONFCOM_VERSION, python3, jq, and a Go of
# any version on PATH (it only reads build info; the build uses the builder's).
set -euo pipefail
umask 022
DIST="${1:?usage: release-build.sh DIST}"
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"
# shellcheck source=../scripts/common.sh
. "$ROOT/scripts/common.sh"
die() { echo "release-build: $*" >&2; exit 1; }

AZ_CONFCOM_VERSION=2.3.0
IMAGE_VARIANT="${IMAGE_VARIANT:-prod}"
export IMAGE_VARIANT

[ -z "$(git status --porcelain --untracked-files=all)" ] || die "the tree has local changes or untracked files"
[ -z "${SIGNER_BUILD_OVERLAY_DIR:-}" ] || die "a release never uses the build overlay"
got="$(az extension show --name confcom --query version -o tsv 2>/dev/null || true)"
[ "$got" = "$AZ_CONFCOM_VERSION" ] || die "az confcom is '$got', want $AZ_CONFCOM_VERSION (az extension add --name confcom --version $AZ_CONFCOM_VERSION)"

# The time stamp of the licence archives and SBOMs: the commit time of HEAD,
# or SOURCE_DATE_EPOCH when set (the tagged commit's time, when the release
# tooling sits on top of the tag as local commits).
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"
export SOURCE_DATE_EPOCH
commit="$(git rev-parse HEAD)"
start=$(date +%s)

# RELEASE_BUILDER_IMAGE names a builder image of release/builder.Dockerfile
# that is already loaded (a pinned one, or one built earlier). Unset, the
# lane builds the builder from the Dockerfile without cache.
if [ -n "${RELEASE_BUILDER_IMAGE:-}" ]; then
  export SIGNER_BUILDER_IMAGE="$RELEASE_BUILDER_IMAGE"
else
  export SIGNER_BUILDER_IMAGE="signer-release-builder:$commit"
  docker buildx build -q --no-cache --load -f release/builder.Dockerfile -t "$SIGNER_BUILDER_IMAGE" release >/dev/null
fi
log "builder image $SIGNER_BUILDER_IMAGE ($(docker image inspect "$SIGNER_BUILDER_IMAGE" --format '{{.Id}}'))"

export SIGNER_GOMODCACHE="$BUILD/gomod"
mkdir -p "$SIGNER_GOMODCACHE"
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -e GOMODCACHE=/gomod \
  -v "$SIGNER_GOMODCACHE:/gomod" -v "$ROOT:$ROOT" -w "$ROOT" \
  "$SIGNER_BUILDER_IMAGE" bash release/build.sh fetch
bash scripts/nitro-cli-image.sh >/dev/null
bash scripts/fetch-nts.sh
# The C core for both arches, in the builder: scripts/build-runner.sh also
# links a host-arch runner (the no-platform-tag check) when it builds for
# aarch64 only, and a fresh checkout has no host-arch core yet.
docker run --rm --pull=never --network none --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$ROOT:$ROOT" -w "$ROOT" "$SIGNER_BUILDER_IMAGE" bash scripts/build-core.sh x86_64 aarch64

bash scripts/generic-images.sh build "$BUILD/generic$(image_suffix)"

# What a release ships, under names that carry the chain.
sfx="$(image_suffix)"
c="$CHAIN"
rm -rf "$DIST"
mkdir -p "$DIST"
cp "$BUILD/generic$sfx/fingerprints.txt" "$DIST/fingerprints-$c.txt"
for spec in "aarch64:runner-aws$sfx" "x86_64:runner-azure$sfx" "x86_64:runner-gcp$sfx" \
  aarch64:hostagent aarch64:forwarder aarch64:udprelay x86_64:setup-tool aarch64:setup-tool; do
  a="${spec%%:*}" n="${spec#*:}"
  base="$n-$c-linux-$(goarch_of "$a")"
  install -m 0555 "$BUILD/$a/bin/$n" "$DIST/$base"
  tar -C "$BUILD/$a/bin" --sort=name --owner=0 --group=0 --numeric-owner \
    --mtime="@$SOURCE_DATE_EPOCH" -czf "$DIST/$base.licenses.tar.gz" "$n.licenses"
  docker run --rm --network none --user "$(id -u):$(id -g)" -e HOME=/tmp -e GOMODCACHE=/gomod \
    -e SOURCE_DATE_EPOCH -v "$SIGNER_GOMODCACHE:/gomod:ro" -v "$ROOT:$ROOT" -v "$DIST:/dist" -w "$ROOT" \
    "$SIGNER_BUILDER_IMAGE" sh -c 'python3 -I release/sbom.py --name "$1" --builder-packages /builder-packages.txt "$2" >"/dist/$1.spdx.json"' \
    _ "$base" "$BUILD/$a/bin/$n"
done
cp "$BUILD/nitro$sfx/runner-aarch64.eif" "$DIST/runner-aws-$c-aarch64.eif"
cp "$BUILD/nitro$sfx/build-enclave-aarch64.json" "$DIST/runner-aws-$c-aarch64.build-enclave.json"
cp "$BUILD/nitro$sfx/inputs-aarch64.txt" "$DIST/runner-aws-$c-aarch64.inputs.txt"
az_out="$(bash -c '. "$1/platform-azure/deploy/common.sh" && echo "$OUT"' _ "$ROOT")"
cp "$az_out/runner.oci.tar" "$DIST/runner-azure-$c.oci.tar"
cp "$az_out/runner.inputs" "$DIST/runner-azure-$c.inputs.txt"
cp "$BUILD/gcp$sfx/runner.oci.tar" "$DIST/runner-gcp-$c.oci.tar"
cp "$BUILD/gcp$sfx/runner.inputs" "$DIST/runner-gcp-$c.inputs.txt"
docker run --rm "$SIGNER_BUILDER_IMAGE" cat /builder-packages.txt >"$DIST/builder-packages.txt"
# Into a temporary name first: the redirect of the pipe can create
# SHA256SUMS before the glob runs, which would list the empty file.
(cd "$DIST" && sha256sum -- * | LC_ALL=C sort -k2 >../.SHA256SUMS.$$ && mv ../.SHA256SUMS.$$ SHA256SUMS)
log "release lane done in $(( $(date +%s) - start )) s: $DIST"
