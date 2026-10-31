#!/usr/bin/env bash
# Builds the runner enclave image from the AWS release runner (runner-aws,
# which holds the Nitro platform and no other cloud's code, and the NTS clock:
# tags platform_aws,nts; the image runs -nts-clock) and turns it into
# a Nitro EIF with nitro-cli build-enclave, without running it (no Nitro
# hardware needed).
#
#   build/nitro/runner-<arch>.eif
#   build/nitro/build-enclave-<arch>.json   nitro-cli output with PCR0/1/2
#   build/nitro/describe-eif-<arch>.json
#   build/nitro/kms-key-policy-<arch>.json  platform-aws/deploy/kms-key-policy.json.tmpl with PCR0/1/2/3
#                                           (scripts/kms-policy.sh render)
#   build/nitro/inputs-<arch>.txt           hashes of what went into the image, and the PCRs
#
# The image is generic: the runner and the flags of
# platform-aws/deploy/enclave/Dockerfile, nothing of an operator. The chain config,
# the client CA, the KMS key and region, the mark bucket and the signer name
# are in the signer's setup, which the parent's host agent hands to the
# enclave at every start (platform-aws/deploy/parent-run.sh SETUP). So one EIF, one
# set of PCRs and one KMS key policy serve every signer and every chain:
#
#   [ARCH=aarch64] scripts/nitro-eif.sh [arch]
#
#   ARCH       x86_64 or aarch64 (also as the first argument). Default: the
#              host arch. The other arch is built through qemu-user, see below.
#   NITRO_CLI_REUSE=1
#              use the local nitro-cli image when it exists instead of
#              running scripts/nitro-cli-image.sh. That script's docker build
#              relies on docker's layer cache; on a miss (a fresh copy of the
#              pinned source is enough) it runs cargo and apt, which download.
#              An offline build sets this and stops if the image is missing.
#
# The CHAIN, CHAIN_JSON, CLIENT_CA, REGION, KMS_KEY_ARN and MARK_BUCKET
# settings of the per-operator images are gone. The build stops if one is
# set: the value belongs in the setup. Make the setup with
# signer-admin/cmd/setup-tool (encode, then check -platform nitro -chain
# governance/chains/CHAIN.json).
#
# Other arch than the host (for example an arm64 EIF for Graviton on an
# x86_64 machine): nitro-cli 1.5.2 picks the kernel blob name from the arch
# it runs on (src/lib.rs: "bzImage" on x86_64, "Image" on aarch64).
# platform-aws/deploy/nitro-cli/target-arch.patch makes it follow NITRO_CLI_TARGET_ARCH,
# and this script mounts the target arch's blob set from the pinned source
# over the image's own. That set has its own linuxkit binary (aarch64 ELF),
# which runs through qemu-user via binfmt_misc with the F flag (apt: qemu-user-static,
# scripts/deps.sh). The script checks that it runs before it builds. The
# enclave image is built for the target arch with buildx (FROM scratch,
# nothing to emulate). A build on an arm64 host would use the same blobs
# and the same image, so it should give the same PCRs. That was not
# checked (no arm64 host here), and neither was a launch: the first launch
# on Graviton is the check, with the PCRs of nitro-cli describe-enclaves.
#
# The EIF is built twice from scratch to check that the PCRs repeat. Then
# scripts/eif-check.sh reads the EIF itself: kernel header, the runner in
# the ramdisk, and PCR0/1/2 recomputed without nitro-cli.
# nitro-cli runs in the docker image from scripts/nitro-cli-image.sh, as
# the calling user, with the host docker socket mounted (it reads the
# image through the docker daemon).
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

die() { echo "nitro-eif: $*" >&2; exit 1; }

for v in CHAIN CHAIN_JSON CLIENT_CA REGION KMS_KEY_ARN MARK_BUCKET MARK_SIGNER; do
  [ -z "${!v:-}" ] || die "$v is set, but the image is generic now: it goes into the signer's setup (signer-admin/cmd/setup-tool), not into the image"
done

arch="${1:-${ARCH:-$HOST_ARCH}}"
case "$arch" in
  x86_64|amd64) arch=x86_64 ;;
  aarch64|arm64) arch=aarch64 ;;
  *) die "unknown arch $arch (x86_64 or aarch64)" ;;
esac
# One nitro-cli image per host arch. It builds EIFs for both arches.
NITRO_IMAGE="signer-cloud/nitro-cli:$NITRO_CLI_TAG-$HOST_ARCH"
# IMAGE_FLAVOR=testnet takes the testnet build (runner-aws-testnet,
# build/nitro-testnet).
SUFFIX="$(image_suffix)"
TAGS="netgo,osusergo,$(runner_tags "runner-aws$SUFFIX")"
# The handover release gate (common.sh require_handover_gate).
require_handover_gate "runner-aws$SUFFIX" || die "no image without the handover gate"
ENCLAVE_IMAGE="signer-cloud/runner-enclave$SUFFIX:$arch"
OUT="$BUILD/nitro$SUFFIX"
CTX="$OUT/ctx-$arch"
mkdir -p "$OUT" "$CTX"
# The chain record of the per-chain images: a generic image has none.
rm -f "$OUT/runner-$arch.chain"

if [ "${NITRO_CLI_REUSE:-}" = 1 ]; then
  docker image inspect "$NITRO_IMAGE" >/dev/null 2>&1 ||
    die "NITRO_CLI_REUSE=1 but there is no local $NITRO_IMAGE (scripts/nitro-cli-image.sh builds it, with network)"
  bash "$ROOT/scripts/fetch.sh" --nitro >/dev/null
  log "nitro-cli: the local image $NITRO_IMAGE ($(docker image inspect "$NITRO_IMAGE" --format '{{.Id}}'))"
else
  bash "$ROOT/scripts/nitro-cli-image.sh" >/dev/null
fi
IMAGE_FLAVOR="$IMAGE_FLAVOR" bash "$ROOT/scripts/build-runner.sh" "$arch" >/dev/null 2>&1
RUNNER="$BUILD/$arch/bin/runner-aws$SUFFIX"
[ -x "$RUNNER" ] || die "$RUNNER was not built"
if grep -qa -- "allow-import" "$RUNNER"; then
  die "$RUNNER has the plaintext import flag; this is not the release build"
fi
# The Nitro platform and nothing else: the build tags are in the binary.
[ "$(go version -m "$RUNNER" | awk '$1 == "build" && $2 ~ /^-tags=/ { print $2 }')" = "-tags=$TAGS" ] ||
  die "$RUNNER was not built with exactly the tags $TAGS"

# Other arch than the host: this arch's blob set and its target arch for nitro-cli.
cross_opts=()
if [ "$arch" != "$HOST_ARCH" ]; then
  BLOBS="$NITRO_CLI_DIR/blobs/$arch"
  [ -f "$BLOBS/linuxkit" ] || die "$BLOBS/linuxkit: no such file (the pinned nitro-cli source has the blob sets)"
  cross_opts=(-v "$BLOBS:/blobs:ro" -e NITRO_CLI_BLOBS=/blobs -e "NITRO_CLI_TARGET_ARCH=$arch")
  if ! docker run --rm --entrypoint /blobs/linuxkit -v "$BLOBS:/blobs:ro" "$NITRO_IMAGE" version >/dev/null 2>&1; then
    die "the $arch linuxkit does not run on this $HOST_ARCH host. Needs qemu-user-static: binfmt_misc entry qemu-$arch with the F flag (sudo apt-get install qemu-user-static)"
  fi
  log "$arch linuxkit runs through qemu-user (binfmt_misc)"
fi

rm -rf "$CTX"
mkdir -p "$CTX"
# Explicit modes, the same as the Dockerfile's COPY --chmod: the image, and
# so PCR0 and PCR2, must not depend on the builder's umask.
install -m 0555 "$RUNNER" "$CTX/runner"
mkdir -m 0755 "$CTX/licenses"
install -m 0644 "$RUNNER.licenses/"* "$CTX/licenses/"
install -m 0644 "$ROOT/platform-aws/deploy/enclave/Dockerfile" "$CTX/Dockerfile"
# Do not reset mtimes here: BuildKit skips re-sending context files whose
# size and mtime look unchanged, which once put a stale runner in the
# image. rewrite-timestamp below clamps layer timestamps instead.

DOCKER_GID="$(stat -c %g /var/run/docker.sock)"

build_eif() { # build_eif <tag>
  local tag="$1"
  # Drop the image of the last build first. Moving the tag to a new image
  # that shares layers with it (same runner, other region) once made
  # `docker create` fail with "parent snapshot ... does not exist" (docker
  # 29, containerd image store).
  docker rmi "$ENCLAVE_IMAGE" >/dev/null 2>&1 || true
  # SOURCE_DATE_EPOCH + rewrite-timestamp pin file and image timestamps,
  # and no provenance/SBOM attestations: a plain `docker build` gives a new
  # image (and new PCR0/PCR2) on every --no-cache build.
  SOURCE_DATE_EPOCH=0 docker buildx build -q --no-cache --provenance=false --sbom=false \
    --platform "linux/$(goarch_of "$arch")" --build-arg SOURCE_DATE_EPOCH=0 \
    --output "type=docker,name=$ENCLAVE_IMAGE,rewrite-timestamp=true" "$CTX" >/dev/null
  # The image must hold exactly the runner we passed in, with the mode the
  # Dockerfile sets, and nothing of an operator.
  local cid got gotmode
  cid="$(docker create --platform "linux/$(goarch_of "$arch")" "$ENCLAVE_IMAGE")"
  if docker cp "$cid:/etc/signer" - >/dev/null 2>&1; then
    docker rm -f "$cid" >/dev/null
    die "the image has /etc/signer: a generic image holds no chain config and no client CA"
  fi
  got="$(docker cp "$cid:/runner" - | tar -xO | sha256sum | cut -d' ' -f1)"
  [ "$got" = "$(sha256sum <"$CTX/runner" | cut -d" " -f1)" ] || { docker rm -f "$cid" >/dev/null; die "/runner in the image differs from $CTX/runner"; }
  gotmode="$(docker cp "$cid:/runner" - | tar -tv | cut -c1-10)"
  [ "$gotmode" = "-r-xr-xr-x" ] || { docker rm -f "$cid" >/dev/null; die "/runner has mode $gotmode in the image, want -r-xr-xr-x"; }
  local notice
  for notice in "$CTX/licenses/"*; do
    got="$(docker cp "$cid:/licenses/${notice##*/}" - | tar -xO | sha256sum | cut -d' ' -f1)"
    [ "$got" = "$(sha256sum <"$notice" | cut -d' ' -f1)" ] || { docker rm -f "$cid" >/dev/null; die "/licenses/${notice##*/} differs from $notice"; }
    gotmode="$(docker cp "$cid:/licenses/${notice##*/}" - | tar -tv | cut -c1-10)"
    [ "$gotmode" = "-rw-r--r--" ] || { docker rm -f "$cid" >/dev/null; die "/licenses/${notice##*/} has mode $gotmode, want -rw-r--r--"; }
  done
  docker rm -f "$cid" >/dev/null
  # The command: the setup from the platform, the NTS clock, the mark log
  # of the setup as the clone protection. No operator value, no option the
  # setup sets (the routes and the KMS key come from the setup), no
  # DynamoDB, no recovery flag, no -record (the runner has no such flag).
  local ep
  ep="$(docker inspect --format '{{json .Config.Entrypoint}}' "$ENCLAVE_IMAGE")"
  for want in '"-setup","platform"' '"-nts-clock"' 'https://kms.{region}.amazonaws.com/'; do
    grep -qF -- "$want" <<<"$ep" || die "the image's command lacks $want"
  done
  for not in '"-config"' '"-tls-client-ca"' '"-platform-opt"' '"-mark-store"' '"-mark-signer"' '"-record' \
    'dynamodb' ':8003' '"-mark-create"' '"-state-create"' '"https-date"'; do
    ! grep -qF -- "$not" <<<"$ep" || die "the image's command has $not"
  done
  log "image holds runner-aws $(sha256sum <"$RUNNER" | cut -c1-16)... as built here, with the Dockerfile's mode, and no operator value"
  # HOME: linuxkit keeps a cache in ~/.moby.
  docker run --rm --user "$(id -u):$(id -g)" --group-add "$DOCKER_GID" -e HOME=/tmp \
    ${cross_opts[@]+"${cross_opts[@]}"} \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$OUT:/out" \
    "$NITRO_IMAGE" build-enclave --docker-uri "$ENCLAVE_IMAGE" \
    --output-file "/out/runner-$arch$tag.eif" >"$OUT/build-enclave-$arch$tag.json"
}

log "nitro-cli build-enclave ($arch), run 1"
build_eif ""
log "nitro-cli build-enclave ($arch), run 2 (reproducibility check)"
build_eif "-rebuild"

docker run --rm --user "$(id -u):$(id -g)" -v "$OUT:/out" "$NITRO_IMAGE" \
  describe-eif --eif-path "/out/runner-$arch.eif" >"$OUT/describe-eif-$arch.json"

pcr() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["Measurements"][sys.argv[2]])' "$1" "$2"; }
for p in PCR0 PCR1 PCR2; do
  a="$(pcr "$OUT/build-enclave-$arch.json" "$p")"
  b="$(pcr "$OUT/build-enclave-$arch-rebuild.json" "$p")"
  if [ "$a" = "$b" ]; then log "$p repeats: $a"; else log "$p DIFFERS between builds: $a vs $b"; fi
done
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("[cloud] describe-eif: EifVersion=%s Arch=%s Kernel=%s IsSigned=%s" % (d.get("EifVersion"), d["Metadata"]["DockerInfo"]["Architecture"], d["Metadata"]["KernelVersion"], d.get("IsSigned")))' "$OUT/describe-eif-$arch.json"

# PCR0/1/2 from this build, PCR3 from the parent role ARN (placeholder
# account unless PARENT_ROLE_ARN or ACCOUNT_ID is set). The policy is the
# same for every signer of this image.
bash "$ROOT/scripts/kms-policy.sh" render "$OUT/build-enclave-$arch.json" "$OUT/kms-key-policy-$arch.json"

# What went into the image, next to the PCRs it gave.
{
  printf 'runner      %s (runner-aws%s)\n' "$(sha256sum <"$RUNNER" | cut -d' ' -f1)" "$SUFFIX"
  printf 'Dockerfile  %s\n' "$(sha256sum <"$CTX/Dockerfile" | cut -d' ' -f1)"
  (cd "$CTX" && sha256sum licenses/*)
  printf 'setup       from the host agent at every start (chain, client CA, KMS key, region, mark bucket, signer)\n'
  printf 'clock       nts: NTS-KE via vsock 8005-8008, NTP via udprelay on vsock 7102\n'
  printf 'nitro-cli  %s, target-arch.patch %s, built on %s, image %s\n' "$NITRO_CLI_TAG" \
    "$(sha256sum <"$ROOT/platform-aws/deploy/nitro-cli/target-arch.patch" | cut -c1-16)" "$HOST_ARCH" \
    "$(docker image inspect "$NITRO_IMAGE" --format '{{.Id}}')"
  for p in PCR0 PCR1 PCR2; do printf '%s        %s\n' "$p" "$(pcr "$OUT/build-enclave-$arch.json" "$p")"; done
} >"$OUT/inputs-$arch.txt"
log "inputs and PCRs in $OUT/inputs-$arch.txt; the setup goes to the parent (platform-aws/deploy/parent-run.sh SETUP)"

# The EIF itself: kernel, the runner in the ramdisk, nothing of an operator,
# PCRs recomputed without nitro-cli.
bash "$ROOT/scripts/eif-check.sh" "$OUT/runner-$arch.eif" "$arch" --runner "$RUNNER" --licenses "$CTX/licenses" --generic \
  --build-json "$OUT/build-enclave-$arch.json" --blobs "$NITRO_CLI_DIR/blobs/$arch"

ls -l "$OUT"/runner-"$arch"*.eif
cat "$OUT/build-enclave-$arch.json"
