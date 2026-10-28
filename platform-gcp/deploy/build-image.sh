#!/usr/bin/env bash
# Builds the GCP workload image from the GCP release runner (runner-gcp, which
# holds the GCP platform and no other cloud's code), twice, and checks that
# both builds give the same image digest. Needs Docker only. It pushes
# nothing and touches no cloud account.
#
#   platform-gcp/deploy/build-image.sh
#
# The image is generic: the runner (and what the build overlay
# adds), nothing of an operator or a project. The chain config, the client
# CA and the names of the WIF provider, KMS key and buckets are in the
# signer's setup (deploy.sh vm-create SETUP_FILE).
# The build stops if CHAIN, CHAIN_JSON or CLIENT_CA of the per-chain images
# is set: those values belong in the setup.
#
# Output in build/gcp/:
#   runner.oci.tar   OCI archive, one image for linux/amd64
#   runner.digest    its manifest digest: the value for the WIF condition and
#                    for the image reference in the VM metadata
#   runner.inputs    sha256 of the runner and the rendered Dockerfile, and
#                    the network entry
#   ctx/             the build context (rendered Dockerfile included)
# and the image is loaded into the local Docker as $LOCAL_RUNNER_IMAGE.
#
# The image holds build/x86_64/bin/runner-gcp, never a debug build and never
# another cloud's runner. BuildKit builds the same bytes each time because of
# SOURCE_DATE_EPOCH=0, rewrite-timestamp and no provenance or SBOM
# attestations, as in platform-azure/deploy/build-image.sh. The file modes are explicit
# (the Dockerfile's COPY --chmod, and install -m on the context files), so the
# digest is the same whatever the builder's umask.
set -euo pipefail
# shellcheck source=common.sh
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

for v in CHAIN CHAIN_JSON CLIENT_CA; do
  [ -z "${!v:-}" ] || die "$v is set, but the image is generic: it goes into the signer's setup (signer-admin/cmd/setup-tool), not into the image"
done

mkdir -p "$OUT"
# The chain record of the per-chain images: a generic image has none.
rm -f "$OUT/runner.chain"
# The handover release gate: scripts/handover-gate.sh must have passed on
# these sources (common.sh require_handover_gate).
require_handover_gate "runner-gcp$IMAGE_SUFFIX" || die "no image without the handover gate"
log "building the runners (scripts/build-runner.sh)"
if ! IMAGE_FLAVOR="$IMAGE_FLAVOR" bash "$ROOT/scripts/build-runner.sh" x86_64 >"$OUT/build-runner.log" 2>&1; then
  tail -n 20 "$OUT/build-runner.log" >&2
  die "scripts/build-runner.sh failed (log: $OUT/build-runner.log)"
fi
RUNNER="$BUILD/x86_64/bin/runner-gcp$IMAGE_SUFFIX"
TAGS="netgo,osusergo,$(runner_tags "runner-gcp$IMAGE_SUFFIX")"
[ -x "$RUNNER" ] || die "$RUNNER was not built"
if grep -qa -- "allow-import" "$RUNNER"; then
  die "$RUNNER has the plaintext import flag; this is not the release build"
fi
# The GCP platform and nothing else: the build tags are in the binary.
[ "$(go version -m "$RUNNER" | awk '$1 == "build" && $2 ~ /^-tags=/ { print $2 }')" = "-tags=$TAGS" ] ||
  die "$RUNNER was not built with exactly the tags $TAGS"
case "$(file -b "$RUNNER")" in
  *"x86-64"*"statically linked"*) ;;
  *) die "$RUNNER is not a static x86-64 binary" ;;
esac

CTX="$OUT/ctx"
rm -rf "$CTX"
mkdir -p "$CTX"
# Explicit modes, the same as the Dockerfile's COPY --chmod: the image must
# not depend on the umask of the builder or on the mode of the input files.
install -m 0555 "$RUNNER" "$CTX/runner"
render_dockerfile "$DOCKERFILE" >"$CTX/Dockerfile"
chmod 0644 "$CTX/Dockerfile"
if grep -Eq '@[A-Z_]+@' "$CTX/Dockerfile"; then
  die "unfilled token left in the Dockerfile"
fi

# More files of the image, "file|source|mode in the image" each, checked in
# the image below like the runner. Only the build overlay adds any.
extra=()
devnet_hook gcp_image_ctx "$CTX"

build_once() { # build_once <n>: archive in $OUT/runner-<n>.oci.tar, prints the manifest digest
  SOURCE_DATE_EPOCH=0 docker buildx build -q --no-cache --provenance=false --sbom=false \
    --platform linux/amd64 --build-arg SOURCE_DATE_EPOCH=0 \
    --metadata-file "$OUT/build-$1.json" \
    --output "type=oci,dest=$OUT/runner-$1.oci.tar,name=$LOCAL_RUNNER_IMAGE,rewrite-timestamp=true" \
    "$CTX" >/dev/null
  jq -r '."containerimage.digest"' "$OUT/build-$1.json"
}

log "build 1"
d1="$(build_once 1)"
log "build 2 (reproducibility check)"
d2="$(build_once 2)"
if [ "$d1" != "$d2" ]; then
  echo "the two builds differ: $d1 and $d2" >&2
  exit 1
fi

mv "$OUT/runner-2.oci.tar" "$OUT/runner.oci.tar"
rm -f "$OUT/runner-1.oci.tar" "$OUT/build-1.json" "$OUT/build-2.json"
echo "$d1" >"$OUT/runner.digest"

# The image must hold exactly the runner (and the extra files) we passed
# in, with the modes the Dockerfile sets, and nothing of an operator.
docker load -i "$OUT/runner.oci.tar" >/dev/null
cid="$(docker create "$LOCAL_RUNNER_IMAGE")"
trap 'docker rm -f "$cid" >/dev/null 2>&1 || true' EXIT
if docker cp "$cid:/etc/signer" - >/dev/null 2>&1; then
  die "the image has /etc/signer: a generic image holds no chain config and no client CA"
fi
for entry in "runner|$CTX/runner|-r-xr-xr-x" ${extra[@]+"${extra[@]}"}; do
  IFS='|' read -r inimg want mode <<<"$entry"
  got="$(docker cp "$cid:/$inimg" - | tar -xO | sha256sum | cut -d' ' -f1)"
  [ "$got" = "$(sha256sum <"$want" | cut -d' ' -f1)" ] || die "/$inimg in the image differs from $want"
  gotmode="$(docker cp "$cid:/$inimg" - | tar -tv | cut -c1-10)"
  [ "$gotmode" = "$mode" ] || die "/$inimg has mode $gotmode in the image, want $mode"
done
devnet_hook gcp_image_check "$cid"
# With Docker's containerd image store the local image id is the manifest digest.
loaded="$(docker image inspect "$LOCAL_RUNNER_IMAGE" --format '{{.Id}}')"
[ "$loaded" = "$d1" ] || die "local image id $loaded is not the manifest digest $d1 (needs the containerd image store)"

# What the image bakes in, written next to the digest: the entrypoint and the
# launch policy labels, read back from the loaded image.
docker image inspect "$LOCAL_RUNNER_IMAGE" --format '{{json .Config.Entrypoint}}' | jq -r 'join(" ")' >"$OUT/runner.entrypoint"
docker image inspect "$LOCAL_RUNNER_IMAGE" --format '{{json .Config.Labels}}' | jq -S . >"$OUT/runner.labels.json"
# The runner takes its values from the setup: the command names none of
# them, and no recovery flag.
grep -q -F -- "/runner -platform gcp -setup platform " "$OUT/runner.entrypoint" || die "the image entrypoint lacks -setup platform"
for not in " -config " " -tls-client-ca " " -platform-opt " " -mark-store " " -state-store " " -mark-signer " \
  " -mark-create" " -state-create" " -record-create" "service_account="; do
  ! grep -q -F -- "$not" "$OUT/runner.entrypoint" || die "the image entrypoint has$not"
done
# The NTS clock, and no -clock flag that would replace it.
grep -q -F -- " -nts-clock -nts-coarse-urls " "$OUT/runner.entrypoint" || die "the image entrypoint lacks -nts-clock"
! grep -q -F -- " -clock " "$OUT/runner.entrypoint" || die "the image entrypoint has -clock, which would replace the NTS clock"
devnet_hook gcp_image_check_entrypoint

{
  printf 'runner      %s\n' "$(sha256sum <"$RUNNER" | cut -d' ' -f1)"
  printf 'Dockerfile  %s (rendered)\n' "$(sha256sum <"$CTX/Dockerfile" | cut -d' ' -f1)"
  printf 'image       %s\n' "$d1"
  printf 'network     %s\n' "$NETWORK_ENTRY"
  devnet_hook gcp_image_inputs "$CTX"
  printf 'setup       per signer, in the metadata attribute signer-setup (deploy.sh vm-create)\n'
} >"$OUT/runner.inputs"
log "image digest $d1 (two identical builds), loaded as $LOCAL_RUNNER_IMAGE"
log "inputs recorded in $OUT/runner.inputs"
