#!/usr/bin/env bash
# The deploy plan for one Confidential Space signer node
# (platform-gcp/deploy/README.md).
#
#   deploy.sh <command>
#
# Commands that never create or change anything:
#   plan              print every step in order with its exact commands. It
#                     runs no gcloud, docker or network command at all
#   preflight         read-only gcloud calls: project number, enabled APIs,
#                     free names, quota, the newest Confidential Space image
#   verifier-config   write the gcp-cs settings for the Dirk fork, cloud-import
#                     and share-import to a local file (no secrets). Without
#                     SIGNER_ADDRESS it reads the reserved address, read-only
#   logs              read-only: the VM's serial console and Cloud Logging
#
# Steps that create or change something in GCP. Each one prints what it does
# and its commands, and refuses to run unless CONFIRM=yes is set:
#   services-enable   enable the APIs the setup needs
#   network-create    VPC and subnet of the signer
#   address-reserve   static external IPv4 address (the entry's address)
#   firewall-create   TCP 7100 from OPERATOR_IP only (the network entry)
#   firewall-delete   delete the TCP 7100 rule (when another entry replaces it)
#   registry-create   Artifact Registry Docker repository
#   image-push        push the image that build-image.sh made
#   kms-create        key ring and HSM key that wrap the runner's data key
#   kms-key-create    an HSM key alone, in the key ring kms-create made: the
#                     key of a second signer next to a running one (KMS_KEY)
#   sa-create         workload service account (the VM runs as it)
#   sa-bindings       its roles: attestation tokens, logs, registry reads. No
#                     key use: an unmeasured VM can run as the account too
#   wif-create        workload identity pool and provider, pinned to the image
#                     digest and the hardware model, and the KMS key's
#                     encrypt/decrypt role for the pool's principal set
#   bucket-bind B     object create and read on bucket B (mark log, state
#                     copy) and the bucket read of the lock check, for the
#                     pool's principal set
#   vm-create         the Confidential Space VM
#   provider-update   after a rebuild: point the provider at the new digest
#   vm-delete         delete the VM (it bills while it exists)
#   teardown          delete everything except the KMS key ring and key
#
# Settings (environment): see common.sh. The ones you set for a test:
#   SETUP_FILE    vm-create: the signer's binary setup (signer-config setup
#                 for the signers of a cluster, or signer-admin/cmd/setup-tool
#                 encode). vm-create checks it with the runner's decoder (a
#                 GCP setup of chain CHAIN, naming this project's WIF
#                 provider, KMS key and identity audience) and puts it,
#                 base64, into the instance metadata attribute signer-setup
#   CHAIN         vm-create: the chain of the setup, hoodi, devnet or
#                 testnet (governance/chains/chain.sh picks its chain config)
#   OPERATOR_IP   public IPv4 address of the machine that runs the Dirk fork
#                 (firewall-create; one address, /32)
#   HARDWARE      amd-sev (default, THIS TEST ONLY) or intel-tdx (production)
#   NETWORK_ENTRY public (default; common.sh). The build overlay
#                 (SIGNER_BUILD_OVERLAY_DIR) adds its entries, their
#                 settings and commands
#   IMAGE_TAG     registry tag of image-push (default poc)
#   VM, ADDRESS_NAME, KMS_KEY, WIF_POOL, WIF_PROVIDER
#                 a second signer next to a running one, for example the
#                 handover target (common.sh): its own VM, address,
#                 key (kms-key-create), pool and provider (wif-create, which
#                 then pins the target's digest alone and binds the new key
#                 to the new pool), bucket-bind for the new pool. The
#                 project's network, firewall rules, registry, key ring and
#                 service account stay shared, so teardown refuses with
#                 these set and lists the target's own deletes instead
#
# The image digest decides which code gets the KMS key. The image holds no
# chain, client CA or project name, so only a new runner (or overlay
# build) changes it: then run build-image.sh again, image-push,
# provider-update and vm-create. A new chain or signer is a new setup only.
# Secrets never appear on a command line. This script handles none: the
# registry login token goes through stdin into a temporary Docker config.
set -euo pipefail
# shellcheck source=common.sh
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

DRY=0
TMP_DIR=""
trap '[ -z "$TMP_DIR" ] || rm -rf "$TMP_DIR"' EXIT

# ---- output helpers ---------------------------------------------------------
show() { # plan output goes to stdout, a real run reports on stderr
  if [ "$DRY" = 1 ]; then echo "$*"; else echo "$*" >&2; fi
}

quote() { # one shell-safe line for the arguments
  local a out="" sq="'\\''"
  for a in "$@"; do
    if [[ "$a" =~ ^[A-Za-z0-9_./:=@%+,-]+$ ]]; then
      out+=" $a"
    elif [[ "$a" != *[\$\`\\\"!]* ]]; then
      out+=" \"$a\""
    else
      out+=" '${a//\'/$sq}'"
    fi
  done
  printf '%s' "${out# }"
}

run() { # show a command, run it unless this is the plan
  show "  \$ $(quote "$@")"
  if [ "$DRY" != 1 ]; then "$@"; fi
}

gate() { # gate NAME "what this step does": stop unless CONFIRM=yes
  show "step $1: $2"
  if [ "$DRY" = 1 ]; then return 0; fi
  if [ "${CONFIRM:-}" != yes ]; then
    echo "refused: this step creates or changes something in GCP. Set CONFIRM=yes to run it." >&2
    exit 3
  fi
}

# ---- inputs -----------------------------------------------------------------
image_digest() { # the digest build-image.sh recorded
  local f="$OUT/runner.digest" d
  if [ -s "$f" ]; then
    d="$(cat "$f")"
    [[ "$d" =~ ^sha256:[0-9a-f]{64}$ ]] || die "$f does not hold a sha256 digest"
    echo "$d"
  elif [ "$DRY" = 1 ]; then
    echo "sha256:<run platform-gcp/deploy/build-image.sh first>"
  else
    die "no $f: run platform-gcp/deploy/build-image.sh first"
  fi
}

operator_ip() {
  local ip="${OPERATOR_IP:-}"
  if [ -z "$ip" ]; then
    if [ "$DRY" = 1 ]; then echo "<OPERATOR_IP>"; return 0; fi
    die "set OPERATOR_IP to the public IPv4 address that runs the Dirk fork"
  fi
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "OPERATOR_IP '$ip' is not one IPv4 address"
  case "$ip" in
    0.0.0.0 | 127.* | 10.* | 192.168.* | 172.1[6-9].* | 172.2?.* | 172.3[01].*) die "OPERATOR_IP $ip is not a public address" ;;
  esac
  echo "$ip"
}

# The WIF attribute condition. All of it must hold, or the STS exchange fails:
# a production Confidential Space image (no debug), the pinned image digest,
# the VM's service account, and the hardware model.
attribute_condition() {
  printf '%s' "assertion.swname == 'CONFIDENTIAL_SPACE'" \
    " && 'STABLE' in assertion.submods.confidential_space.support_attributes" \
    " && assertion.dbgstat == 'disabled-since-boot'" \
    " && assertion.hwmodel == '$GCP_HWMODELS'" \
    " && assertion.submods.container.image_digest == '$(image_digest)'" \
    " && '$SERVICE_ACCOUNT' in assertion.google_service_accounts"
}

# ---- steps ------------------------------------------------------------------
cmd_services_enable() {
  gate services-enable "enable the APIs of the setup in $PROJECT_ID (preflight shows which are on; enabling is idempotent)"
  run gcloud services enable compute.googleapis.com cloudkms.googleapis.com artifactregistry.googleapis.com \
    confidentialcomputing.googleapis.com iam.googleapis.com iamcredentials.googleapis.com sts.googleapis.com \
    logging.googleapis.com --project="$PROJECT_ID"
}

cmd_network_create() {
  gate network-create "custom VPC $VPC and subnet $SUBNET ($SUBNET_RANGE, $REGION). A custom VPC has no allow rule, so the default network's ssh, rdp and icmp rules do not apply"
  run gcloud compute networks create "$VPC" --subnet-mode=custom --project="$PROJECT_ID"
  run gcloud compute networks subnets create "$SUBNET" --network="$VPC" --region="$REGION" \
    --range="$SUBNET_RANGE" --project="$PROJECT_ID"
}

cmd_address_reserve() {
  gate address-reserve "reserve the regional external IPv4 address $ADDRESS_NAME, so the Dirk fork's address survives a VM restart (billed while reserved)"
  run gcloud compute addresses create "$ADDRESS_NAME" --region="$REGION" --project="$PROJECT_ID"
}

cmd_firewall_create() {
  local ip
  ip="$(operator_ip)"
  gate firewall-create "the network entry: ingress TCP $SIGNER_PORT from $ip/32 to VMs tagged $NET_TAG in $VPC. Nothing else comes in. The firewall limits exposure and denial of service. Mutual TLS is what protects the runner"
  run gcloud compute firewall-rules create "$FW_RULE" --network="$VPC" --direction=INGRESS --priority=1000 \
    --allow="tcp:$SIGNER_PORT" --source-ranges="$ip/32" --target-tags="$NET_TAG" \
    --description="Signer PoC: TCP $SIGNER_PORT from the operator only" --project="$PROJECT_ID"
}

# The public entry's rule, when another network entry replaces it.
cmd_firewall_delete() {
  gate firewall-delete "delete $FW_RULE (TCP $SIGNER_PORT from the operator). firewall-create makes it again"
  run gcloud compute firewall-rules delete "$FW_RULE" --project="$PROJECT_ID" --quiet
}

cmd_registry_create() {
  gate registry-create "Artifact Registry Docker repository $AR_REPO in $REGION"
  run gcloud artifacts repositories create "$AR_REPO" --repository-format=docker --location="$REGION" \
    --description="Signer PoC runner image" --project="$PROJECT_ID"
}

cmd_image_push() {
  local digest ref pushed cfg
  digest="$(image_digest)"
  ref="$IMAGE_REPO:$IMAGE_TAG"
  gate image-push "push $LOCAL_RUNNER_IMAGE to $ref, digest $digest. The login uses a short-lived token through stdin and a temporary Docker config, so ~/.docker is not changed"
  if [ "$DRY" = 1 ]; then
    show "  \$ cfg=\$(mktemp -d)    # removed afterwards"
    show "  \$ gcloud auth print-access-token | DOCKER_CONFIG=\$cfg docker login -u oauth2accesstoken --password-stdin $REGISTRY"
    show "  \$ docker tag $LOCAL_RUNNER_IMAGE $ref"
    show "  \$ DOCKER_CONFIG=\$cfg docker push $ref"
    show "  \$ gcloud artifacts docker images describe $ref --format='value(image_summary.digest)'    # must print $digest"
    return 0
  fi
  docker image inspect "$LOCAL_RUNNER_IMAGE" >/dev/null 2>&1 || die "no local image $LOCAL_RUNNER_IMAGE: run platform-gcp/deploy/build-image.sh first"
  TMP_DIR="$(umask 077 && mktemp -d)"
  cfg="$TMP_DIR/docker"
  mkdir -m 700 "$cfg"
  gcloud auth print-access-token | DOCKER_CONFIG="$cfg" docker login -u oauth2accesstoken --password-stdin "$REGISTRY" >&2
  docker tag "$LOCAL_RUNNER_IMAGE" "$ref"
  DOCKER_CONFIG="$cfg" docker push "$ref" >&2
  pushed="$(gcloud artifacts docker images describe "$ref" --format='value(image_summary.digest)')"
  [ "$pushed" = "$digest" ] || die "the registry reports digest '$pushed', build-image.sh made $digest. Build again before the WIF step"
}

cmd_kms_create() {
  if side_by_side && [ "$DRY" != 1 ]; then die "the key ring $KMS_RING is the running signer's: a second signer takes kms-key-create"; fi
  gate kms-create "key ring $KMS_RING and HSM key $KMS_KEY in $REGION (purpose encryption). A key ring and a key cannot be deleted later. Only key versions can be destroyed"
  run gcloud kms keyrings create "$KMS_RING" --location="$REGION" --project="$PROJECT_ID"
  run gcloud kms keys create "$KMS_KEY" --keyring="$KMS_RING" --location="$REGION" \
    --purpose=encryption --protection-level=hsm --project="$PROJECT_ID"
}

cmd_kms_key_create() {
  gate kms-key-create "HSM key $KMS_KEY in the existing key ring $KMS_RING ($REGION, purpose encryption). A key cannot be deleted later. Only its versions can be destroyed. About 1 USD a month per key version (README, \"Cost estimate\")"
  if [ "$DRY" != 1 ] && gcloud kms keys describe "$KMS_KEY" --keyring="$KMS_RING" --location="$REGION" --project="$PROJECT_ID" >/dev/null 2>&1; then
    die "key $KMS_KEY exists in $KMS_RING already; this step makes a new key and never a new version of one"
  fi
  run gcloud kms keys create "$KMS_KEY" --keyring="$KMS_RING" --location="$REGION" \
    --purpose=encryption --protection-level=hsm --project="$PROJECT_ID"
}

cmd_sa_create() {
  gate sa-create "service account $SERVICE_ACCOUNT: the VM runs as it (attestation tokens, logs, image pull). It gets no key use and no bucket access"
  run gcloud iam service-accounts create "$SA_NAME" --display-name="Signer PoC workload" --project="$PROJECT_ID"
}

# The account gets no KMS or bucket role: any VM can be made to run as it,
# a VM without Confidential Space included, and that VM's metadata server
# hands out the account's token. Key release goes to the WIF principal set
# only (wif-create), which needs an attestation token that passes the
# provider's condition.
cmd_sa_bindings() {
  local member="serviceAccount:$SERVICE_ACCOUNT"
  gate sa-bindings "roles of $SERVICE_ACCOUNT. Registry: read of $AR_REPO only. Project: attestation tokens and log writing. No KMS role"
  run gcloud artifacts repositories add-iam-policy-binding "$AR_REPO" --location="$REGION" \
    --member="$member" --role=roles/artifactregistry.reader --project="$PROJECT_ID"
  run gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="$member" --role=roles/confidentialcomputing.workloadUser --condition=None
  run gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="$member" --role=roles/logging.logWriter --condition=None
}

cmd_wif_create() {
  local cond
  cond="$(attribute_condition)"
  gate wif-create "workload identity pool $WIF_POOL and OIDC provider $WIF_PROVIDER. It takes tokens from $CS_ISSUER with audience $STS_AUDIENCE only, and only for image $(image_digest) on hardware $GCP_HWMODELS (production image, not debug, STABLE). The pool's principal set, and nothing else, may encrypt and decrypt with $KMS_KEY. Keep the pool to this one provider: any provider added to it gets the key"
  run gcloud iam workload-identity-pools create "$WIF_POOL" --location=global \
    --display-name="Signer PoC" --project="$PROJECT_ID"
  run gcloud iam workload-identity-pools providers create-oidc "$WIF_PROVIDER" --location=global \
    --workload-identity-pool="$WIF_POOL" --issuer-uri="$CS_ISSUER" --allowed-audiences="$STS_AUDIENCE" \
    --attribute-mapping="google.subject=assertion.sub" --attribute-condition="$cond" --project="$PROJECT_ID"
  # The federated token from STS calls KMS itself (Cloud KMS takes federated
  # principals; README, "Key release through the principal set").
  run gcloud kms keys add-iam-policy-binding "$KMS_KEY" --keyring="$KMS_RING" --location="$REGION" \
    --member="$WIF_PRINCIPAL_SET" --role=roles/cloudkms.cryptoKeyEncrypterDecrypter --project="$PROJECT_ID"
}

# bucket-bind BUCKET: the mark log's bucket, which also holds the state copy
# under state/ when the setup's encrypted_state_store names the same bucket. Create
# and read, no delete or overwrite role; uniform bucket-level access, which
# identity federation needs, is on (review/marklog stores.sh creates the
# bucket with it). The lock check at every start reads the bucket's
# retention policy (GET storage/v1/b/BUCKET?fields=retentionPolicy), which
# needs storage.buckets.get: roles/storage.legacyBucketReader has it, and
# storage.objects.list, and no write. Without it the runner stops at the
# lock check.
cmd_bucket_bind() {
  local bucket="${1:-}"
  if [ "$DRY" = 1 ]; then
    bucket="${bucket:-<mark log bucket>}"
  else
    [[ "$bucket" =~ ^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$ ]] || die "bucket-bind needs a bucket name"
  fi
  gate bucket-bind "on gs://$bucket only: roles/storage.objectCreator, roles/storage.objectViewer and roles/storage.legacyBucketReader (the lock check's bucket read) for the WIF principal set, not for $SERVICE_ACCOUNT"
  run gcloud storage buckets add-iam-policy-binding "gs://$bucket" --project="$PROJECT_ID" \
    --member="$WIF_PRINCIPAL_SET" --role=roles/storage.objectCreator
  run gcloud storage buckets add-iam-policy-binding "gs://$bucket" --project="$PROJECT_ID" \
    --member="$WIF_PRINCIPAL_SET" --role=roles/storage.objectViewer
  run gcloud storage buckets add-iam-policy-binding "gs://$bucket" --project="$PROJECT_ID" \
    --member="$WIF_PRINCIPAL_SET" --role=roles/storage.legacyBucketReader
}

cmd_provider_update() {
  local cond
  cond="$(attribute_condition)"
  gate provider-update "after a rebuild: provider $WIF_PROVIDER takes image $(image_digest) only"
  run gcloud iam workload-identity-pools providers update-oidc "$WIF_PROVIDER" --location=global \
    --workload-identity-pool="$WIF_POOL" --attribute-condition="$cond" --project="$PROJECT_ID"
}

cmd_vm_create() {
  local digest meta setup_hash mff
  digest="$(image_digest)"
  meta="^~^tee-image-reference=$IMAGE_REPO@$digest~tee-restart-policy=OnFailure~tee-container-log-redirect=true"
  # The setup goes into the metadata attribute signer-setup, base64, from a
  # file. Not a tee-env-* value: those are in every attestation token.
  if [ "$DRY" = 1 ]; then
    setup_hash="<setup_sha256 of SETUP_FILE>"
    mff="signer-setup=/tmp/XXXX/setup.b64"
  else
    # Once on its own: inside $(...) a failed check would not stop the step.
    need_setup >/dev/null
    setup_hash="$(need_setup)"
    TMP_DIR="$(umask 077 && mktemp -d)"
    base64 -w0 <"$SETUP_FILE" >"$TMP_DIR/setup.b64"
    mff="signer-setup=$TMP_DIR/setup.b64"
  fi
  local args=(gcloud compute instances create "$VM" --project="$PROJECT_ID" --zone="$ZONE"
    --machine-type="$MACHINE" --confidential-compute-type="$CC_TYPE")
  [ -z "$MIN_CPU_PLATFORM" ] || args+=(--min-cpu-platform="$MIN_CPU_PLATFORM")
  args+=(--maintenance-policy="$MAINTENANCE" --shielded-secure-boot
    --image-project="$CS_IMAGE_PROJECT" --image-family="$CS_IMAGE_FAMILY"
    --boot-disk-size="$BOOT_DISK_SIZE" --boot-disk-type="$BOOT_DISK_TYPE"
    --network="$VPC" --subnet="$SUBNET" --address="$ADDRESS_NAME" --tags="$NET_TAG"
    --service-account="$SERVICE_ACCOUNT" --scopes=cloud-platform --labels=purpose=signer-poc
    --metadata="$meta")
  local what="$VM in $ZONE: $MACHINE, $CC_TYPE, image family $CS_IMAGE_FAMILY (production), service account $SERVICE_ACCOUNT, external address $ADDRESS_NAME, setup_sha256 $setup_hash. It bills per second while it exists"
  # A network entry of the build overlay may make its own vm-create.
  if devnet_has gcp_vm_create && devnet_gcp_vm_create "$what" "$mff" "${args[@]}"; then
    return 0
  fi
  gate vm-create "$what"
  run "${args[@]}" --metadata-from-file="$mff"
}

cmd_vm_delete() {
  gate vm-delete "delete $VM and its boot disk. The runner's state goes with it, so the next VM makes a new data key and the shares need a new import"
  run gcloud compute instances delete "$VM" --zone="$ZONE" --project="$PROJECT_ID" --quiet
}

cmd_teardown() {
  # A second signer shares the network, rules, registry and service account
  # with the running one: list its own deletes, never the shared ones.
  if side_by_side; then
    show "teardown of a second signer: its own resources only (the network, firewall rules, registry, key ring and service account are shared)"
    show "  \$ $(quote gcloud compute instances delete "$VM" --zone="$ZONE" --project="$PROJECT_ID" --quiet)"
    show "  \$ $(quote gcloud compute addresses delete "$ADDRESS_NAME" --region="$REGION" --project="$PROJECT_ID" --quiet)"
    show "  \$ $(quote gcloud iam workload-identity-pools providers delete "$WIF_PROVIDER" --location=global --workload-identity-pool="$WIF_POOL" --project="$PROJECT_ID" --quiet)"
    show "  \$ $(quote gcloud iam workload-identity-pools delete "$WIF_POOL" --location=global --project="$PROJECT_ID" --quiet)"
    show "  key $KMS_KEY stays (GCP cannot delete a key); destroy its version: $(quote gcloud kms keys versions destroy 1 --key="$KMS_KEY" --keyring="$KMS_RING" --location="$REGION" --project="$PROJECT_ID")"
    [ "$DRY" = 1 ] && return 0
    die "teardown refuses with VM, ADDRESS_NAME, KMS_KEY, WIF_POOL or WIF_PROVIDER set: run the deletes above yourself"
  fi
  gate teardown "delete the VM, firewall rule, address, subnet, VPC, registry, WIF provider and pool, and the service account. The KMS key ring and key stay: GCP cannot delete them"
  run gcloud compute instances delete "$VM" --zone="$ZONE" --project="$PROJECT_ID" --quiet
  run gcloud compute firewall-rules delete "$FW_RULE" --project="$PROJECT_ID" --quiet
  run gcloud compute addresses delete "$ADDRESS_NAME" --region="$REGION" --project="$PROJECT_ID" --quiet
  run gcloud compute networks subnets delete "$SUBNET" --region="$REGION" --project="$PROJECT_ID" --quiet
  run gcloud compute networks delete "$VPC" --project="$PROJECT_ID" --quiet
  run gcloud artifacts repositories delete "$AR_REPO" --location="$REGION" --project="$PROJECT_ID" --quiet
  run gcloud iam workload-identity-pools providers delete "$WIF_PROVIDER" --location=global \
    --workload-identity-pool="$WIF_POOL" --project="$PROJECT_ID" --quiet
  run gcloud iam workload-identity-pools delete "$WIF_POOL" --location=global --project="$PROJECT_ID" --quiet
  run gcloud iam service-accounts delete "$SERVICE_ACCOUNT" --project="$PROJECT_ID" --quiet
}

# ---- read-only commands -----------------------------------------------------
cmd_plan() {
  DRY=1
  local digest
  digest="$(image_digest)"
  cat <<EOF
Deploy plan for one Confidential Space signer node. Nothing below ran, and
this command calls no gcloud, docker or network command.

Project   $PROJECT_ID (number $PROJECT_NUMBER), region $REGION, zone $ZONE
Hardware  $HARDWARE: $MACHINE, --confidential-compute-type=$CC_TYPE, hwmodel $GCP_HWMODELS
EOF
  if [ "$HARDWARE" = amd-sev ]; then
    cat <<EOF
          THIS IS THE TEST SETTING. Azure runs on AMD SEV-SNP too, so a test on AMD
          SEV puts two of the three shares on one chip family. Production uses
          HARDWARE=intel-tdx (c3-highcpu-4, hwmodel GCP_INTEL_TDX).
EOF
  fi
  cat <<EOF
Image     $IMAGE_REPO@$digest
Network   entry: external IPv4 address $ADDRESS_NAME, firewall $FW_RULE: TCP $SIGNER_PORT from the operator's IP only
Names     key $KMS_KEY_RESOURCE
          service account $SERVICE_ACCOUNT
          WIF provider $WIF_PROVIDER_RESOURCE
          identity audience $IDENTITY_AUDIENCE (the WIF provider accepts $STS_AUDIENCE only)

Setup     ${SETUP_FILE:-SETUP_FILE (unset)}, chain ${CHAIN:-unset (set CHAIN)}; build folder $OUT, image tag $IMAGE_TAG

Step 0, local: platform-gcp/deploy/build-image.sh   (builds twice, writes $OUT/runner.digest; the same image for every signer)
        and the signer's setup (SETUP_FILE): signer-config setup -out setups cluster.conf, or signer-admin/cmd/setup-tool encode setup.conf setup.bin
Then each step below needs CONFIRM=yes: CONFIRM=yes platform-gcp/deploy/deploy.sh <step>
Read-only before the first step: platform-gcp/deploy/deploy.sh preflight

EOF
  local n=1 s steps="services-enable network-create address-reserve firewall-create registry-create image-push
    kms-create sa-create sa-bindings wif-create bucket-bind vm-create"
  if side_by_side; then
    # The project's network, rules, registry, key ring and service account
    # are the running signer's; the second signer adds its own parts only.
    steps="address-reserve image-push kms-key-create wif-create bucket-bind vm-create"
    echo "A second signer next to a running one: VM $VM, address $ADDRESS_NAME, key $KMS_KEY, pool $WIF_POOL, provider $WIF_PROVIDER."
    echo "The network $VPC, the firewall rules, the registry $AR_REPO, the key ring $KMS_RING and $SERVICE_ACCOUNT are shared and exist."
    echo
  fi
  for s in $steps; do
    printf '%s. ' "$n"
    # bucket-bind takes the mark log's bucket; the other steps take nothing.
    "cmd_${s//-/_}" "${MARK_STORE#gcs:bucket=}"
    echo
    n=$((n + 1))
  done
  echo "After a rebuild (new digest): build-image.sh, image-push, provider-update, vm-delete, vm-create."
  echo
  printf 'Redeploy. '
  cmd_provider_update
  echo
  printf 'Stop billing. '
  cmd_teardown
  echo
  cat <<EOF
Not in the steps: the KMS key version can be destroyed (30 days by default) with
  gcloud kms keys versions destroy 1 --key=$KMS_KEY --keyring=$KMS_RING --location=$REGION --project=$PROJECT_ID
A deleted WIF pool and provider are kept for 30 days and their names stay taken.
EOF
}

cmd_preflight() {
  local fail=0 api enabled d
  ok() { echo "ok    $*"; }
  bad() { echo "FAIL  $*"; fail=1; }
  note() { echo "note  $*"; }
  free() { # free WHAT cmd...: the describe call must fail, or the name is taken
    local what="$1"
    shift
    if "$@" >/dev/null 2>&1; then bad "$what exists already"; else ok "$what is free"; fi
  }
  [ "$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')" = "$PROJECT_NUMBER" ] &&
    ok "project $PROJECT_ID has number $PROJECT_NUMBER" || bad "project number is not $PROJECT_NUMBER"
  enabled="$(gcloud services list --enabled --project="$PROJECT_ID" --format='value(config.name)')"
  for api in compute cloudkms artifactregistry confidentialcomputing iamcredentials logging; do
    if grep -qx "$api.googleapis.com" <<<"$enabled"; then ok "API $api is on"; else note "API $api is off (services-enable turns it on)"; fi
  done
  for api in iam sts; do
    if grep -qx "$api.googleapis.com" <<<"$enabled"; then ok "API $api is on"; else note "API $api is not in the enabled list (services-enable turns it on)"; fi
  done
  free "VPC $VPC" gcloud compute networks describe "$VPC" --project="$PROJECT_ID"
  free "address $ADDRESS_NAME" gcloud compute addresses describe "$ADDRESS_NAME" --region="$REGION" --project="$PROJECT_ID"
  free "firewall rule $FW_RULE" gcloud compute firewall-rules describe "$FW_RULE" --project="$PROJECT_ID"
  free "registry $AR_REPO" gcloud artifacts repositories describe "$AR_REPO" --location="$REGION" --project="$PROJECT_ID"
  free "key ring $KMS_RING" gcloud kms keyrings describe "$KMS_RING" --location="$REGION" --project="$PROJECT_ID"
  free "service account $SA_NAME" gcloud iam service-accounts describe "$SERVICE_ACCOUNT" --project="$PROJECT_ID"
  free "WIF pool $WIF_POOL" gcloud iam workload-identity-pools describe "$WIF_POOL" --location=global --project="$PROJECT_ID"
  free "VM $VM" gcloud compute instances describe "$VM" --zone="$ZONE" --project="$PROJECT_ID"
  d="$(gcloud compute images describe-from-family "$CS_IMAGE_FAMILY" --project="$CS_IMAGE_PROJECT" \
    --format='value(name,creationTimestamp,labels.deprecation)')" && ok "newest $CS_IMAGE_FAMILY image: $d" || bad "image family $CS_IMAGE_FAMILY not readable"
  if [ -n "$MIN_CPU_PLATFORM" ]; then
    d="$(gcloud compute zones describe "$ZONE" --project="$PROJECT_ID" --format='value(availableCpuPlatforms)')"
    if grep -q "$MIN_CPU_PLATFORM" <<<"$d"; then ok "$ZONE offers $MIN_CPU_PLATFORM"; else bad "$ZONE does not offer $MIN_CPU_PLATFORM"; fi
  fi
  gcloud compute machine-types describe "$MACHINE" --zone="$ZONE" --project="$PROJECT_ID" \
    --format='value(name,guestCpus,memoryMb)' >/dev/null 2>&1 && ok "machine type $MACHINE exists in $ZONE" || bad "machine type $MACHINE not found in $ZONE"
  gcloud compute regions describe "$REGION" --project="$PROJECT_ID" --format=json |
    jq -r '.quotas[] | select(.metric=="CPUS" or .metric=="N2D_CPUS" or .metric=="IN_USE_ADDRESSES" or .metric=="STATIC_ADDRESSES") | "note  quota \(.metric): \(.usage) of \(.limit)"'
  [ "$fail" = 0 ] || exit 1
}

cmd_verifier_config() {
  local digest dir addr cert key
  digest="$(image_digest)"
  # No defaults: the output directory and the client certificate are private
  # files outside the repo.
  [ -n "${GCP_TEST_DIR:-}" ] || die "verifier-config: set GCP_TEST_DIR (a private directory outside the repo for gcp-signer.json)"
  [ -n "${CLIENT_CERT:-}" ] || die "verifier-config: set CLIENT_CERT (the Dirk fork's client certificate, for example client.pem of make-test-ca.sh)"
  [ -n "${CLIENT_KEY:-}" ] || die "verifier-config: set CLIENT_KEY (the private key of CLIENT_CERT)"
  dir="$GCP_TEST_DIR" cert="$CLIENT_CERT" key="$CLIENT_KEY"
  addr="${SIGNER_ADDRESS:-}"
  # A network entry of the build overlay may name the address.
  [ -n "$addr" ] || addr="$(devnet_hook gcp_signer_address)"
  if [ -z "$addr" ]; then
    addr="$(gcloud compute addresses describe "$ADDRESS_NAME" --region="$REGION" --project="$PROJECT_ID" \
      --format='value(address)' 2>/dev/null || true)"
  fi
  addr="tcp:${addr:-SIGNER_IP}:$SIGNER_PORT"
  mkdir -p "$dir"
  chmod 700 "$dir"
  (
    umask 077
    # A testnet image (IMAGE_FLAVOR=testnet): the client takes it only with
    # allow_testnet_build.
    jq -n --arg addr "$addr" --arg cert "$cert" --arg key "$key" --arg digest "$digest" \
      --arg aud "$IDENTITY_AUDIENCE" --arg hw "$GCP_HWMODELS" --arg sa "$SERVICE_ACCOUNT" \
      --arg flavor "$IMAGE_FLAVOR" '{
        address: $addr, client_cert: $cert, client_key: $key,
        attestation: {verifier: "gcp-cs", gcp_image_digest: $digest, gcp_audience: $aud,
          gcp_hwmodels: [$hw], gcp_service_account: $sa}
      } + (if $flavor == "testnet" then {allow_testnet_build: true} else {} end)' >"$dir/gcp-signer$CHAIN_SUFFIX.json"
  )
  chmod 600 "$dir/gcp-signer$CHAIN_SUFFIX.json"
  echo "wrote $dir/gcp-signer$CHAIN_SUFFIX.json (mode 600): the Connection of attestation-verify/runnerclient for this signer, chain $CHAIN" >&2
  if [ "$HARDWARE" = amd-sev ]; then
    echo "gcp_hwmodels is [$GCP_HWMODELS]: THIS TEST ONLY. Production: [GCP_INTEL_TDX] only" >&2
    # The JSON has no room for a comment, so the warning sits next to it.
    (
      umask 077
      printf '%s\n' "gcp-signer.json is for the AMD SEV test only (gcp_hwmodels GCP_AMD_SEV)." \
        "Azure runs on AMD SEV-SNP, so this puts two of the three shares on one chip family." \
        "Production must be Intel TDX: gcp_hwmodels [GCP_INTEL_TDX] only (HARDWARE=intel-tdx)." >"$dir/NOTE.txt"
    )
  fi
  case "$addr" in *SIGNER_IP*) echo "address has no IP yet: set SIGNER_ADDRESS, or run address-reserve and this command again" >&2 ;; esac
  echo "share-import flags: -addr $addr -verifier gcp-cs -gcp-image-digest $digest -gcp-audience $IDENTITY_AUDIENCE -gcp-hwmodel $GCP_HWMODELS -gcp-service-account $SERVICE_ACCOUNT"
}

cmd_logs() {
  # Read-only. The log name of the launcher is from Google's docs and not checked on a VM.
  gcloud compute instances get-serial-port-output "$VM" --zone="$ZONE" --project="$PROJECT_ID" | tail -n 60
  gcloud logging read 'resource.type="gce_instance" AND logName:"confidential-space-launcher"' \
    --project="$PROJECT_ID" --freshness=1h --limit=60 --order=asc --format='value(timestamp,textPayload,jsonPayload.message)'
}

usage() {
  sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed -e '/^set -euo/d' -e 's/^# \{0,1\}//' >&2
  exit 2
}

main() {
  local cmd="${1:-}"
  case "$cmd" in
    plan) cmd_plan ;;
    preflight) cmd_preflight ;;
    verifier-config) cmd_verifier_config ;;
    logs) cmd_logs ;;
    services-enable) cmd_services_enable ;;
    network-create) cmd_network_create ;;
    address-reserve) cmd_address_reserve ;;
    firewall-create) cmd_firewall_create ;;
    firewall-delete) cmd_firewall_delete ;;
    registry-create) cmd_registry_create ;;
    image-push) cmd_image_push ;;
    kms-create) cmd_kms_create ;;
    kms-key-create) cmd_kms_key_create ;;
    sa-create) cmd_sa_create ;;
    sa-bindings) cmd_sa_bindings ;;
    wif-create) cmd_wif_create ;;
    bucket-bind) cmd_bucket_bind "${2:-}" ;;
    provider-update) cmd_provider_update ;;
    vm-create) cmd_vm_create ;;
    vm-delete) cmd_vm_delete ;;
    teardown) cmd_teardown ;;
    *)
      # Commands of the build overlay (devnet_gcp_cmd_<name>).
      if [ -n "$cmd" ] && devnet_has "gcp_cmd_${cmd//-/_}"; then
        "devnet_gcp_cmd_${cmd//-/_}" "${@:2}"
      else
        usage
      fi ;;
  esac
}

main "$@"
