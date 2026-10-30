# shellcheck shell=bash disable=SC2034
# Shared settings for the GCP scripts (build-image.sh, deploy.sh). Source it,
# do not run it. Every name that the image bakes in or that deploy.sh creates
# is chosen here, so the image digest and the cloud resources agree.

GCP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../scripts/common.sh
. "$GCP_DIR/../../scripts/common.sh"

die() { echo "gcp: $*" >&2; exit 1; }

# The image is the same for every signer and every chain (Dockerfile); its
# build folder is build/gcp. CHAIN names the chain of the setup (vm-create
# checks it) and of the verifier settings file.
if [ -n "${CHAIN:-}" ]; then check_chain_name "$CHAIN" || exit 1; fi
CHAIN_SUFFIX="$(chain_suffix "${CHAIN:-devnet}")"
OUT="$BUILD/gcp"

# SETUP_FILE: the signer's binary setup (signer-admin/cmd/setup-tool encode). It holds the chain
# config, the client CA, the WIF provider, KMS key and identity audience,
# the mark and state buckets and the signer name.
# vm-create puts it, base64, into the instance metadata attribute
# signer-setup, where the runner reads it.
SETUP_FILE="${SETUP_FILE:-}"

# need_setup: SETUP_FILE is a setup the GCP runner accepts, of chain $CHAIN,
# whose key release names this project's WIF provider, KMS key and identity
# audience (the names the resources below get), and whose mark bucket is
# MARK_STORE's when that is set. Prints setup_sha256.
need_setup() {
  local out
  [ -n "$SETUP_FILE" ] || die "set SETUP_FILE to the signer's binary setup (signer-admin/cmd/setup-tool encode)"
  out="$(check_setup "$SETUP_FILE" gcp)" || die "SETUP_FILE=$SETUP_FILE refused"
  [ "$(setup_value "$SETUP_FILE" sealing_key_release.wif_provider)" = "$WIF_PROVIDER_RESOURCE" ] ||
    die "SETUP_FILE names WIF provider $(setup_value "$SETUP_FILE" sealing_key_release.wif_provider), this project $WIF_PROVIDER_RESOURCE"
  [ "$(setup_value "$SETUP_FILE" sealing_key_release.kms_key)" = "$KMS_KEY_RESOURCE" ] ||
    die "SETUP_FILE names KMS key $(setup_value "$SETUP_FILE" sealing_key_release.kms_key), this project $KMS_KEY_RESOURCE"
  [ "$(setup_value "$SETUP_FILE" sealing_key_release.attest_audience)" = "$IDENTITY_AUDIENCE" ] ||
    die "SETUP_FILE names identity audience $(setup_value "$SETUP_FILE" sealing_key_release.attest_audience), this deploy $IDENTITY_AUDIENCE"
  if [ -n "$MARK_STORE" ]; then
    [ "gcs:bucket=$(setup_value "$SETUP_FILE" slashing_log_store.bucket)" = "$MARK_STORE" ] ||
      die "SETUP_FILE names mark bucket $(setup_value "$SETUP_FILE" slashing_log_store.bucket), MARK_STORE is $MARK_STORE"
  fi
  sed -n 's/^setup_sha256 //p' <<<"$out"
}

# ---- project and names ------------------------------------------------------
# The operator's project. `deploy.sh preflight` checks the number against
# `gcloud projects describe`.
PROJECT_ID="${PROJECT_ID:-<gcp-project>}"
PROJECT_NUMBER="${PROJECT_NUMBER:-<gcp-project-number>}"
REGION="${REGION:-europe-west4}"
ZONE="${ZONE:-europe-west4-a}"

AR_REPO=signer
IMAGE_NAME=runner
# Another IMAGE_TAG keeps the deployed image's tag in the registry, for a
# rollback (the mark log test pushes :marklog). IMAGE_FLAVOR=testnet
# (scripts/common.sh) adds "-testnet" (generic-testnet).
IMAGE_TAG="${IMAGE_TAG:-poc}"
if [ "$IMAGE_FLAVOR" = testnet ]; then
  case "$IMAGE_TAG" in *-testnet) ;; *) IMAGE_TAG="$IMAGE_TAG-testnet" ;; esac
fi
KMS_RING=signer
SA_NAME=signer-workload
VPC=signer-net
SUBNET=signer-subnet
SUBNET_RANGE=10.10.0.0/24
FW_RULE=signer-allow-7100
NET_TAG=signer-node
SIGNER_PORT=7100
# A signer of its own next to a running one (a handover target) takes
# its own VM, address, KMS key and WIF pool and provider by these
# overrides, and shares the project, network, firewall rules, registry, key
# ring and service account with the running one. Its own pool, because the
# KMS key grants its role to a pool's principal set: every identity that
# passes any provider of the pool would get the key. With the target's pool
# and a provider pinned to the target's digest alone, the new key releases
# to the target image only and the running signer's key stays its own.
KMS_KEY="${KMS_KEY:-sealing}"
WIF_POOL="${WIF_POOL:-signer-pool}"
WIF_PROVIDER="${WIF_PROVIDER:-signer-attestation}"
VM="${VM:-signer-node-1}"
ADDRESS_NAME="${ADDRESS_NAME:-signer-node-1-ip}"
[[ "$KMS_KEY" =~ ^[a-zA-Z0-9_-]{1,63}$ ]] || die "KMS_KEY=$KMS_KEY: letters, digits, dashes and underscores, at most 63"
[[ "$WIF_POOL" =~ ^[a-z0-9-]{4,32}$ ]] || die "WIF_POOL=$WIF_POOL: 4 to 32 lowercase letters, digits and dashes"
[[ "$WIF_PROVIDER" =~ ^[a-z0-9-]{4,32}$ ]] || die "WIF_PROVIDER=$WIF_PROVIDER: 4 to 32 lowercase letters, digits and dashes"
[[ "$VM" =~ ^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$ ]] || die "VM=$VM is not a Compute Engine name"
[[ "$ADDRESS_NAME" =~ ^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$ ]] || die "ADDRESS_NAME=$ADDRESS_NAME is not a Compute Engine name"
# side_by_side: the names are another signer's than the defaults, so the
# shared resources belong to a running signer too.
side_by_side() {
  [ "$VM" != signer-node-1 ] || [ "$ADDRESS_NAME" != signer-node-1-ip ] || [ "$KMS_KEY" != sealing ] ||
    [ "$WIF_POOL" != signer-pool ] || [ "$WIF_PROVIDER" != signer-attestation ]
}


# ---- network entry and mark log ---------------------------------------------
# NETWORK_ENTRY: how the signing clients reach port 7100 (README, "Network entry").
#   public     the VM's external address, firewall TCP 7100 from OPERATOR_IP
#              (Dockerfile)
# The build overlay (SIGNER_BUILD_OVERLAY_DIR) adds its own
# entries (devnet_gcp_network_entry sets DOCKERFILE and their settings).
NETWORK_ENTRY="${NETWORK_ENTRY:-public}"
if [ "$NETWORK_ENTRY" = public ]; then
  DOCKERFILE="$GCP_DIR/Dockerfile"
elif devnet_has gcp_network_entry; then
  devnet_gcp_network_entry
else
  die "NETWORK_ENTRY must be public, got '$NETWORK_ENTRY' (other entries come from the build overlay)"
fi

# MARK_STORE: the bucket of the runner's mark log (slashing-log/docs/marklog.md), for
# example gcs:bucket=<mark-bucket>: bucket-bind grants the
# pool on it, and vm-create checks that the setup names it. The runner takes
# its mark log and state copy (STATE_STORE before the setup) from the setup.
MARK_STORE="${MARK_STORE:-}"

# The audience of the identity tokens that the runner hands to clients. It must
# differ from the one the WIF provider accepts (https://sts.googleapis.com).
IDENTITY_AUDIENCE="${IDENTITY_AUDIENCE:-signer-runner-identity}"
STS_AUDIENCE="https://sts.googleapis.com"
[ "$IDENTITY_AUDIENCE" != "$STS_AUDIENCE" ] ||
  die "IDENTITY_AUDIENCE must differ from the provider's audience $STS_AUDIENCE: a token with it would be a credential for the KMS key"
# Google's issuer. The discovery document and the iss claim have no trailing slash.
CS_ISSUER="https://confidentialcomputing.googleapis.com"

# ---- hardware ---------------------------------------------------------------
# HARDWARE=amd-sev is the setting of THIS TEST ONLY: the operator chose
# n2d-highcpu-2 with AMD SEV. The three-cloud layout (Azure on AMD SEV-SNP,
# AWS Nitro, GCP) needs HARDWARE=intel-tdx in production, so that no chip
# family holds two of the three shares.
HARDWARE="${HARDWARE:-amd-sev}"
case "$HARDWARE" in
  amd-sev)
    CC_TYPE=SEV
    MACHINE="${MACHINE:-n2d-highcpu-2}"
    MIN_CPU_PLATFORM="AMD Milan"
    MAINTENANCE=MIGRATE # live migration works for N2D with SEV only
    GCP_HWMODELS=GCP_AMD_SEV
    ;;
  intel-tdx)
    CC_TYPE=TDX
    # Google's supported-configurations page names c3-standard-* for TDX and does
    # not name c3-highcpu-*. Check before the production run.
    MACHINE="${MACHINE:-c3-highcpu-4}"
    MIN_CPU_PLATFORM=""
    MAINTENANCE=TERMINATE
    GCP_HWMODELS=GCP_INTEL_TDX
    ;;
  *) die "HARDWARE must be amd-sev (this test only) or intel-tdx (production), got '$HARDWARE'" ;;
esac

# The production Confidential Space image family, never the debug family.
CS_IMAGE_PROJECT=confidential-space-images
CS_IMAGE_FAMILY=confidential-space

BOOT_DISK_SIZE=20GB
BOOT_DISK_TYPE=pd-balanced

# ---- derived names ----------------------------------------------------------
SERVICE_ACCOUNT="$SA_NAME@$PROJECT_ID.iam.gserviceaccount.com"
KMS_KEY_RESOURCE="projects/$PROJECT_ID/locations/$REGION/keyRings/$KMS_RING/cryptoKeys/$KMS_KEY"
WIF_POOL_RESOURCE="projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/$WIF_POOL"
WIF_PROVIDER_RESOURCE="//iam.googleapis.com/$WIF_POOL_RESOURCE/providers/$WIF_PROVIDER"
# Every identity of the pool. The pool has one provider, whose attribute
# condition pins the image, hardware model and launcher settings; the KMS key
# and the buckets grant their roles to this set, never to the service account.
WIF_PRINCIPAL_SET="principalSet://iam.googleapis.com/$WIF_POOL_RESOURCE/*"
REGISTRY="$REGION-docker.pkg.dev"
IMAGE_REPO="$REGISTRY/$PROJECT_ID/$AR_REPO/$IMAGE_NAME"
# IMAGE_FLAVOR=testnet puts "-testnet" into the build folder and the image name.
IMAGE_SUFFIX="$(image_suffix)"
OUT="$OUT$IMAGE_SUFFIX"

# Local name of the image build-image.sh makes. Nothing pushes it unless
# deploy.sh image-push runs with CONFIRM=yes.
LOCAL_RUNNER_IMAGE="signer-cloud/gcp-runner$IMAGE_SUFFIX:$IMAGE_TAG"

# The Dockerfile as build-image.sh builds it. Nothing of a signer goes in.
# The build overlay may change it (devnet_gcp_render_dockerfile).
render_dockerfile() { # render_dockerfile SRC > DST
  local s
  s="$(cat "$1")"
  [ -z "$MARK_STORE" ] || [[ "$MARK_STORE" =~ ^gcs:bucket=[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$ ]] || die "MARK_STORE=$MARK_STORE is not gcs:bucket=NAME"
  for v in STATE_STORE MARK_SIGNER; do
    [ -z "${!v:-}" ] || die "$v is set, but the image is generic: the setup names the state copy and the signer"
  done
  if devnet_has gcp_render_dockerfile; then
    s="$(devnet_gcp_render_dockerfile "$1" <<<"$s")"
  fi
  printf '%s\n' "$s"
}
