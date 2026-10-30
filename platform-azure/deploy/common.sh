# shellcheck shell=bash disable=SC2034
# Shared settings for the Azure scripts (build-image.sh, deploy.sh). Source
# it, do not run it. Everything pinned lives here.

AZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../scripts/common.sh
. "$AZ_DIR/../../scripts/common.sh"

die() { echo "azure: $*" >&2; exit 1; }

# The image is the same for every signer and every chain (Dockerfile). Its
# build folder is build/azure. Another IMAGE_TAG keeps the deployed image's
# tags, local and in the registry, for a rollback.
if [ -n "${CHAIN:-}" ]; then check_chain_name "$CHAIN" || exit 1; fi
OUT="$BUILD/azure"
IMAGE_TAG="${IMAGE_TAG:-poc}"
# IMAGE_FLAVOR=testnet (scripts/common.sh): the testnet build, with
# "-testnet" in the tag (generic-testnet, then generic-testnet-ts below).
if [ "$IMAGE_FLAVOR" = testnet ]; then
  case "$IMAGE_TAG" in *-testnet) ;; *) IMAGE_TAG="$IMAGE_TAG-testnet" ;; esac
fi

# Setup of signer N (research/setup-phase.md in the threshold-signer-poc repo,
# section 3): SETUP_FILE_N, a binary setup. signer-config setup (the Dirk
# fork's tool) writes one per signer of a cluster with one cluster_id;
# signer-admin/cmd/setup-tool encode makes a single one. It holds what were
# per-signer flags: chain config, client CA, MAA host, vault and key, mark
# and state stores (the mark log is required; an Azure store names its
# subscription and resource group for the lock check) and signer name. group-deploy hands it to the runner in SIGNER_SETUP. The
# mark log and state copy settings of the per-signer commands
# are fields of the setup.
setup_file() { local v="SETUP_FILE_$1"; echo "${!v:-}"; }

# need_setup N: SETUP_FILE_N is a setup the Azure runner accepts, of chain
# $CHAIN, whose key release names this deploy's attestation provider, vault
# and key of signer N (key-create made that key for the policy). With
# SUBSCRIPTION_ID set, its stores must name that subscription. Prints
# setup_sha256.
need_setup() {
  local n="$1" f out kid part
  f="$(setup_file "$n")"
  [ -n "$f" ] || die "set SETUP_FILE_$n to the binary setup of signer $n (signer-config setup, or signer-admin/cmd/setup-tool encode)"
  out="$(check_setup "$f" azure)" || die "SETUP_FILE_$n=$f refused"
  [ "$(setup_value "$f" sealing_key_release.maa_endpoint)" = "$(signer_maa_endpoint "$n")" ] ||
    die "SETUP_FILE_$n names attestation provider $(setup_value "$f" sealing_key_release.maa_endpoint), this deploy $(signer_maa_endpoint "$n")"
  [ "$(setup_value "$f" sealing_key_release.akv_endpoint)" = "$(vault_endpoint)" ] ||
    die "SETUP_FILE_$n names vault $(setup_value "$f" sealing_key_release.akv_endpoint), this deploy $(vault_endpoint)"
  kid="$(setup_value "$f" sealing_key_release.kid)"
  [ "${kid%%/*}" = "$(key_name "$n")" ] || die "SETUP_FILE_$n names key $kid, this deploy $(key_name "$n")"
  if [ -n "${SUBSCRIPTION_ID:-}" ]; then
    for part in slashing_log_store encrypted_state_store; do
      [ -z "$(setup_value "$f" "$part.account")" ] || [ "$(setup_value "$f" "$part.subscription")" = "$SUBSCRIPTION_ID" ] ||
        die "SETUP_FILE_$n names subscription $(setup_value "$f" "$part.subscription") in $part, SUBSCRIPTION_ID is $SUBSCRIPTION_ID"
    done
  fi
  sed -n 's/^setup_sha256 //p' <<<"$out"
}

# store_scopes N: the resource ID of each container the setup of signer N
# names (slashing_log_store, and encrypted_state_store when it is another container), one per
# line. The role steps grant on these scopes only.
store_scopes() {
  local f part acct
  f="$(setup_file "$1")"
  for part in slashing_log_store encrypted_state_store; do
    acct="$(setup_value "$f" "$part.account")"
    [ -n "$acct" ] || continue
    printf '/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s/blobServices/default/containers/%s\n' \
      "$(setup_value "$f" "$part.subscription")" "$(setup_value "$f" "$part.resource_group")" "$acct" "$(setup_value "$f" "$part.container")"
  done | sort -u
}

# store_accounts N: the resource ID of each storage account that holds a
# container of store_scopes N, one per line. The lock check reads these.
store_accounts() {
  local f part acct
  f="$(setup_file "$1")"
  for part in slashing_log_store encrypted_state_store; do
    acct="$(setup_value "$f" "$part.account")"
    [ -n "$acct" ] || continue
    printf '/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s\n' \
      "$(setup_value "$f" "$part.subscription")" "$(setup_value "$f" "$part.resource_group")" "$acct"
  done | sort -u
}

RG="${RG:-signer-poc-rg}"

# Network entry: how the Dirk forks reach port 7100 of a signer (README,
# "Network entry"). It is one part of the container group template, which
# deploy.sh render merges into aci-template.json. The network is not
# trusted and can be replaced; nothing but the runner's port 7100 may
# listen inside the group. This tree implements none: the private devnet
# overlay (SIGNER_BUILD_OVERLAY_DIR) adds its network entries and may
# set NETWORK's default, its build folder and image tag.
NETWORK="${NETWORK:-}"
devnet_hook azure_network_defaults

check_network() {
  [ -n "$NETWORK" ] && devnet_has azure_network_file && return 0
  die "NETWORK=${NETWORK:-unset}: this tree has no Azure network entry; the build overlay (SIGNER_BUILD_OVERLAY_DIR) adds its own (README, Network entry)"
}

# IMAGE_FLAVOR=testnet puts "-testnet" into the build folder and the image name.
IMAGE_SUFFIX="$(image_suffix)"
OUT="$OUT$IMAGE_SUFFIX"

# Local name of the image build-image.sh makes. The registry name is added
# by deploy.sh, once ACR_NAME is chosen.
LOCAL_RUNNER_IMAGE="signer-cloud/azure-runner$IMAGE_SUFFIX:$IMAGE_TAG"

# Regional shared Microsoft Azure Attestation providers. West Europe and
# North Europe follow the documented pattern of the default providers
# (Get-AzAttestationDefaultProvider lists sharedeus.eus, sharedeus2.eus2,
# sharedcus.cus, shareduks.uks); all three answered
# /.well-known/openid-configuration with their own issuer.
maa_endpoint_for() {
  case "$1" in
    westeurope) echo sharedweu.weu.attest.azure.net ;;
    northeurope) echo sharedneu.neu.attest.azure.net ;;
    eastus) echo sharedeus.eus.attest.azure.net ;;
    *) die "no shared attestation provider known for region $1 (set MAA_ENDPOINT_<N>)" ;;
  esac
}

check_signer() {
  case "${1:-}" in 1 | 2 | 3) ;; *) die "signer index must be 1, 2 or 3 (got '${1:-}')" ;; esac
}

# signer_location N: LOCATION_N, else one region per signer: West Europe for
# 1, North Europe for 2, East US for 3. With the runner at 1 CPU and the
# network entry at 0.5, a group asks for 1.5 of the 4 confidential cores of a
# region, so each region holds one with room to spare.
signer_location() {
  local v="LOCATION_$1" d=westeurope
  [ "$1" = 2 ] && d=northeurope
  [ "$1" = 3 ] && d=eastus
  echo "${!v:-$d}"
}

signer_maa_endpoint() {
  local v="MAA_ENDPOINT_$1"
  if [ -n "${!v:-}" ]; then echo "${!v}"; else maa_endpoint_for "$(signer_location "$1")"; fi
}

# signer_dir N: the build files of one group (template, policy, the hash
# its key's release policy names), by group name, so a second group of
# signer N (GROUP_NAME_N) keeps its own.
signer_dir() { echo "$OUT/$(group_name "$1")"; }

# Names. Index N is 1..3 and sets the group, the key,
# the identity and the location.
#
# A second group of signer N next to the running one (a handover target)
# takes GROUP_NAME_N (for example signer-1b) and KEY_NAME_N, a new
# key name. Never the running group's key: key-create on an existing name
# adds a version, and the running runner releases the newest version at its
# next start, which would take its key away (key-create refuses an existing
# name). IDENTITY_NAME_N stays the running group's identity unless set.
# override_name VAR DEFAULT: the value of VAR if set, else DEFAULT, checked.
override_name() {
  local v="${!1:-$2}"
  [[ "$v" =~ ^[A-Za-z0-9][A-Za-z0-9-]{0,62}$ ]] || die "$1=$v: letters, digits and dashes, at most 63"
  echo "$v"
}
group_name() { override_name "GROUP_NAME_$1" "signer-$1"; }
# key_name N: the Key Vault key of signer N, KEY_NAME_PREFIX-N (default
# signer-kek-N). Another prefix gives an image its own keys: a new version
# of a key a running image releases by name would take that image's
# release away, because the runner releases the newest version.
key_name() {
  local p="${KEY_NAME_PREFIX:-signer-kek}"
  [[ "$p" =~ ^[A-Za-z0-9-]{1,100}$ ]] || die "KEY_NAME_PREFIX=$p: letters, digits and dashes only"
  override_name "KEY_NAME_$1" "$p-$1"
}
identity_name() { override_name "IDENTITY_NAME_$1" "signer-id-$1"; }

need() { # need VAR...: stop unless every named variable is set
  local v
  for v in "$@"; do
    [ -n "${!v:-}" ] || die "set $v ($(describe_var "$v"))"
  done
}

describe_var() {
  case "$1" in
    VAULT) echo "Key Vault name, 3 to 24 letters, digits and dashes, globally unique" ;;
    ACR_NAME) echo "container registry name, 5 to 50 letters and digits, globally unique" ;;
    *) echo "see platform-azure/deploy/README.md" ;;
  esac
}

registry_server() { echo "${ACR_NAME}.azurecr.io"; }
vault_endpoint() { echo "${VAULT}.vault.azure.net"; }

# The name overrides are checked here, outside any $(...), so a bad one
# stops the script instead of leaving an empty name.
for _n in 1 2 3; do
  group_name "$_n" >/dev/null
  key_name "$_n" >/dev/null
  identity_name "$_n" >/dev/null
done
unset _n
