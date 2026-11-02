#!/usr/bin/env bash
# UNTESTED ON AZURE. The Azure deployment: three signers, each one confidential
# container group (the runner, which does the attestation and the key
# release itself, plus the network entry container).
#
#   deploy.sh <command> [N]        N is the signer index 1, 2 or 3
#
# Local commands. They never touch an Azure account:
#   plan             list the Azure steps in order, with the names they would use
#   render N         fill aci-template.json for signer N and add the network part
#   policy [N]       render, then run az confcom acipolicygen on this machine and
#                    print the CCE policy SHA-256 (all three signers without N).
#                    For a network entry whose command holds nothing of a
#                    signer, with no N it checks that the three are one policy and writes it to $OUT/policy.sha256:
#                    the hash every release policy and verifier pins, for any
#                    signer and any chain
#
# Azure commands. Each one creates or changes something in Azure, prints
# what it would do and refuses to run unless CONFIRM=yes is set:
#   rg-create                 resource group
#   vault-create              Key Vault Premium, RBAC authorization
#   vault-operator-role       you get Key Vault Crypto Officer on the vault
#   identity-create N         user-assigned managed identity of signer N
#   key-create N              exportable RSA-HSM key signer-kek-N with the release policy
#   key-role N                identity N gets Key Vault Crypto Service Release User on its key,
#                             and Key Vault Reader on it (the runner reads the key's
#                             release policy for key_release_hash)
#   store-role N              identity N gets Storage Blob Data Contributor (records)
#                             on the containers of SETUP_FILE_N, and Reader (the lock
#                             check reads the account and the container) on their accounts
#   acr-create                container registry (Basic)
#   acr-role N                identity N gets AcrPull on the registry
#   image-push                az acr login, then docker push of the runner image
#   group-deploy N            deploy the container group of signer N
#
# Settings (environment): SETUP_FILE_N (group-deploy: the binary setup of
# signer N, see "Setup" below), CHAIN (group-deploy: the chain of the setups,
# hoodi, devnet or testnet), VAULT and ACR_NAME (globally unique names, no
# default), RG (default signer-poc-rg), SUBSCRIPTION_ID (the identity's
# resource ID in the template; when set, group-deploy and store-role check
# that the setup's stores name it), LOCATION_N, MAA_ENDPOINT_N,
# NETWORK (the network entry; this tree has none, the build overlay
# SIGNER_BUILD_OVERLAY_DIR adds its own, with their settings), STDIO=enable|disable (default enable),
# KEY_IMMUTABLE=true|false (default false), KEY_SIZE (default 2048),
# KEY_NAME_PREFIX (default signer-kek: the keys are signer-kek-N; the
# generic image takes its own, for example signer-gkek, so a running
# per-chain image keeps its key),
# GROUP_NAME_N, KEY_NAME_N, IDENTITY_NAME_N (a second group of signer N
# next to the running one, for example a handover target: group
# signer-1b with a new key name and the running group's identity; build
# files in $OUT/<group>; key-create refuses a key name that exists, since
# that would add a version to the running group's key),
# See README.md for
# the order and for what each step costs.
#
# The hash of the CCE policy decides which code gets the key. Any change to
# the runner image, the container commands or the network image changes it,
# so run `policy` again and create the keys after the last change. Secrets
# never appear on a command line: a network part's secret goes to ARM in a
# mode 600 parameters file.
#
# Setup: the image and the command hold no chain config, client CA, vault,
# key, attestation provider or mark log. Each signer's setup holds them, made with
# signer-config setup (one per signer of a cluster) or signer-admin/cmd/setup-tool
# encode from a human file. group-deploy N checks
# SETUP_FILE_N with the runner's decoder: an Azure setup, of chain CHAIN
# (governance/chains/chain.sh picks its chain config), naming this deploy's
# attestation provider, vault and key of signer N. It then passes the setup
# in the parameter signerSetup, base64, which the template puts into the
# runner's SIGNER_SETUP. The parameter has no default, so the CCE policy has
# a wildcard rule for it, and the setup_hash in the runner's identity
# shows which setup it runs.
set -euo pipefail
# shellcheck source=common.sh
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

STDIO="${STDIO:-enable}"
KEY_IMMUTABLE="${KEY_IMMUTABLE:-false}"
KEY_SIZE="${KEY_SIZE:-2048}"
ZERO_GUID="00000000-0000-0000-0000-000000000000"
TMP_DIR=""
trap '[ -z "$TMP_DIR" ] || rm -rf "$TMP_DIR"' EXIT

# gate "what this step does": print it and stop unless CONFIRM=yes.
gate() {
  echo "step: $1" >&2
  if [ "${CONFIRM:-}" != yes ]; then
    echo "refused: this step creates or changes something in Azure. Set CONFIRM=yes to run it." >&2
    exit 3
  fi
}

# ---- the network entry part -----------------------------------------------
# The network entry is not trusted and can be replaced; nothing but the
# runner's port 7100 may listen inside the group. This tree has none of its
# own. The build overlay (SIGNER_BUILD_OVERLAY_DIR) adds its
# network entries: each entry is a template part (network_file) and the
# functions below, which call the overlay's devnet_azure_network_<name>.

network_fn() {
  local f="azure_network_$1"
  shift
  devnet_has "$f" || die "NETWORK=${NETWORK:-unset}: no network entry (this tree has none; the build overlay adds its own)"
  "devnet_$f" "$@"
}
# network_file: the template part, a JSON file (see aci-template.json).
network_file() { network_fn file; }
# network_images: "local name|public name" of each image of the part that the
# policy tool needs in the local Docker daemon.
network_images() { network_fn images; }
# network_need: the settings group-deploy needs from the environment.
network_need() { network_fn need; }
# network_check_secrets: stop unless the secret files of the part are usable.
network_check_secrets() { network_fn check_secrets; }
# network_parameters N: the deployment parameters of the part, as a JSON
# object on stdout. They may hold a secret, so the caller writes them to a
# mode 600 file.
network_parameters() { network_fn parameters "$1"; }
# network_describe N: one line for `plan`.
network_describe() { network_fn describe "$1"; }
# network_vars N: NAME=VALUE lines; render replaces @NAME@ in the template.
network_vars() { network_fn vars "$1"; }
# network_one_policy: true when the command holds nothing of one signer,
# so the three signers' policies must be one.
network_one_policy() { network_fn one_policy; }

# ---- local steps ----------------------------------------------------------

# render N: build/azure/signer-N/template.json from aci-template.json and
# the network part. The per-signer values land in the runner's measured
# command line.
render() {
  local n="$1" dir digest vars
  check_signer "$n"
  check_network
  need ACR_NAME VAULT
  [ -s "$OUT/runner.digest" ] || die "no $OUT/runner.digest: run platform-azure/deploy/build-image.sh first"
  digest="$(cat "$OUT/runner.digest")"
  vars="$(network_vars "$n" | jq -Rn '[inputs | select(length > 0) | capture("^(?<k>[A-Z_]+)=(?<v>.*)$")] | map({(.k): .v}) | add // {}')" || exit 1
  dir="$(signer_dir "$n")"
  mkdir -p "$dir"
  jq \
    --slurpfile net "$(network_file)" \
    --arg group "$(group_name "$n")" --arg loc "$(signer_location "$n")" \
    --arg runner "$(registry_server)/signer-runner@$digest" \
    --arg ident "/subscriptions/${SUBSCRIPTION_ID:-$ZERO_GUID}/resourceGroups/$RG/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$(identity_name "$n")" \
    --arg reg "$(registry_server)" --argjson vars "$vars" '
    .parameters += $net[0].parameters
    | if $net[0].container then .resources[0].properties.containers += [$net[0].container] else . end
    | if $net[0].runner then
        .resources[0].properties.containers[0].properties |=
          (.command = $net[0].runner.commandPrefix + .command[0:1] + $net[0].runner.runnerFlags + .command[1:]
           | .environmentVariables = ((.environmentVariables // []) + $net[0].runner.environmentVariables))
      else . end
    | walk(if type == "string" then reduce ($vars | to_entries[]) as $e (.; gsub("@" + $e.key + "@"; $e.value)) else . end)
    | walk(if type == "string" then
      gsub("@GROUP_NAME@"; $group) | gsub("@LOCATION@"; $loc) | gsub("@RUNNER_IMAGE@"; $runner)
      | gsub("@IDENTITY_ID@"; $ident)
      | gsub("@REGISTRY_SERVER@"; $reg)
    else . end)' "$AZ_DIR/aci-template.json" >"$dir/template.json"
  if grep -Eq '@[A-Z_]+@' "$dir/template.json"; then
    die "unfilled token left in $dir/template.json"
  fi
  # The runner's clock is the NTS clock (runner-azure has the tag nts), and
  # nothing in the command replaces it.
  jq -e '.resources[0].properties.containers[0].properties.command
    | index("-nts-clock") != null and index("-nts-coarse-urls") != null and index("-clock") == null' \
    "$dir/template.json" >/dev/null || die "the runner command in $dir/template.json does not run the NTS clock alone"
  # The runner takes its values from the setup in SIGNER_SETUP, a parameter
  # without a default, and the command names none of them.
  jq -e '.resources[0].properties.containers[0].properties
    | (.command | index("-setup") != null and index("-config") == null and index("-tls-client-ca") == null
       and index("-platform-opt") == null and index("-mark-store") == null)
      and ([.environmentVariables[] | select(.name == "SIGNER_SETUP")][0].value == "[parameters('"'"'signerSetup'"'"')]")' \
    "$dir/template.json" >/dev/null || die "the runner in $dir/template.json does not take its setup from SIGNER_SETUP alone"
  jq -e '.parameters.signerSetup | has("defaultValue") | not' "$dir/template.json" >/dev/null ||
    die "signerSetup has a default in $dir/template.json: the CCE policy would pin one setup"
}

# The policy tool reads images from the local Docker daemon. Pull the pinned
# official image of the network part if it is missing, and give it the name
# the template uses (the policy does not depend on the name, because
# acipolicygen runs with --omit-id). The runner image is local already.
ensure_images() {
  local pair ref public
  while IFS= read -r pair; do
    ref="${pair%%|*}"
    public="${pair#*|}"
    if ! docker image inspect "$public" >/dev/null 2>&1; then
      log "pulling $public"
      docker pull -q "$public" >/dev/null
    fi
    [ "$ref" = "$public" ] || docker tag "$public" "${ref%@*}:poc"
  done < <(network_images)
  docker image inspect "$LOCAL_RUNNER_IMAGE" >/dev/null 2>&1 ||
    die "no local image $LOCAL_RUNNER_IMAGE: run platform-azure/deploy/build-image.sh first"
  docker tag "$LOCAL_RUNNER_IMAGE" "$(registry_server)/signer-runner:$IMAGE_TAG"
}

# policy_for N: render and run az confcom acipolicygen. The template gets
# its ccePolicy and the SHA-256 of the decoded policy is printed on stdout
# (all other output goes to stderr, which is kept in policy.log). The hash
# is the value of the x-ms-sevsnpvm-hostdata claim.
policy_for() {
  local n="$1" dir hash check
  case "$STDIO" in enable | disable) ;; *) die "STDIO must be enable or disable" ;; esac
  render "$n"
  ensure_images
  dir="$(signer_dir "$n")"
  # -y approves the wildcard rule for the parameters without a default
  # (signerSetup and those of the network part). --omit-id keeps the registry and image tag out
  # of the policy. stdin is closed: the tool asks before it overwrites a policy.
  if ! hash="$(az confcom acipolicygen -a "$dir/template.json" -y --omit-id "--$STDIO-stdio" \
    </dev/null 2>"$dir/policy.log")"; then
    tail -n 20 "$dir/policy.log" >&2
    die "az confcom acipolicygen failed (log: $dir/policy.log)"
  fi
  [[ "$hash" =~ ^[0-9a-f]{64}$ ]] || die "unexpected acipolicygen output '$hash' (see $dir/policy.log)"
  jq -r '.resources[0].properties.confidentialComputeProperties.ccePolicy' "$dir/template.json" |
    base64 -d >"$dir/policy.rego"
  check="$(sha256sum <"$dir/policy.rego" | cut -d' ' -f1)"
  [ "$check" = "$hash" ] || die "printed hash $hash is not the SHA-256 of the policy in the template ($check)"
  echo "$hash" >"$dir/policy.sha256"
  echo "$hash"
}

cmd_render() { render "$1"; echo "$(signer_dir "$1")/template.json"; }

cmd_policy() {
  local n h hashes=()
  if [ $# -gt 0 ]; then
    check_signer "$1"
    echo "signer $1  $(policy_for "$1")"
    return 0
  fi
  for n in 1 2 3; do
    h="$(policy_for "$n")"
    hashes+=("$h")
    echo "signer $n  $h"
  done
  # A network entry whose command holds nothing of a signer: the three
  # renders must give one policy. That hash is the image's, set once in the
  # release policies, whatever setup a group gets.
  if network_one_policy; then
    if [ "${hashes[0]}" != "${hashes[1]}" ] || [ "${hashes[0]}" != "${hashes[2]}" ]; then
      die "the three signers have different CCE policies; with NETWORK=$NETWORK they must be one"
    fi
    echo "${hashes[0]}" >"$OUT/policy.sha256"
    echo "one policy for every signer: ${hashes[0]} ($OUT/policy.sha256)"
  fi
}

cmd_plan() {
  local n
  need ACR_NAME VAULT
  cat <<EOF
Azure steps in order. Each one needs CONFIRM=yes. Local steps first:
  build-image.sh, then deploy.sh policy (all three signers, no Azure), and a
  setup per signer (SETUP_FILE_N: signer-config setup for a cluster, or
  signer-admin/cmd/setup-tool encode)
Resource group $RG, registry $ACR_NAME, vault $VAULT, network entry $NETWORK.
Build folder $OUT, image tag signer-runner:$IMAGE_TAG, setups of chain ${CHAIN:-unset (set CHAIN)}.
EOF
  printf '  %-22s %s\n' rg-create "group in $(signer_location 1)"
  printf '  %-22s %s\n' vault-create "Premium vault in $(signer_location 1)"
  printf '  %-22s %s\n' vault-operator-role "you: Key Vault Crypto Officer"
  printf '  %-22s %s\n' acr-create "Basic registry in $(signer_location 1)"
  printf '  %-22s %s\n' image-push "runner image to $(registry_server)"
  for n in 1 2 3; do
    printf '  %-22s %s\n' "identity-create $n" "$(identity_name "$n") in $(signer_location "$n")"
  done
  for n in 1 2 3; do
    printf '  %-22s %s\n' "key-create $n" "$(key_name "$n"), authority $(signer_maa_endpoint "$n")"
  done
  for n in 1 2 3; do
    printf '  %-22s %s\n' "key-role $n" "$(identity_name "$n") releases and reads $(key_name "$n")"
  done
  for n in 1 2 3; do
    printf '  %-22s %s\n' "acr-role $n" "$(identity_name "$n") pulls from $ACR_NAME"
  done
  for n in 1 2 3; do
    printf '  %-22s %s\n' "store-role $n" "$(identity_name "$n") writes records to the containers of SETUP_FILE_$n and reads their lock"
  done
  for n in 1 2 3; do
    printf '  %-22s %s\n' "group-deploy $n" "$(group_name "$n") in $(signer_location "$n"), $(network_describe "$n" 2>/dev/null || echo "no network entry"), setup SETUP_FILE_$n"
  done
}

# ---- Azure steps (each starts with gate) ----------------------------------

cmd_rg_create() {
  gate "create resource group $RG in $(signer_location 1)"
  az group create -n "$RG" -l "$(signer_location 1)" -o none
}

cmd_vault_create() {
  need VAULT
  gate "create Key Vault $VAULT (Premium, RBAC authorization) in $(signer_location 1), group $RG"
  az keyvault create -n "$VAULT" -g "$RG" -l "$(signer_location 1)" --sku premium \
    --enable-rbac-authorization true -o none
}

cmd_vault_operator_role() {
  local oid scope
  need VAULT
  gate "assign Key Vault Crypto Officer on $VAULT to the signed-in user (or OPERATOR_OBJECT_ID)"
  oid="${OPERATOR_OBJECT_ID:-$(az ad signed-in-user show --query id -o tsv)}"
  scope="$(az keyvault show -n "$VAULT" -g "$RG" --query id -o tsv)"
  az role assignment create --assignee-object-id "$oid" --assignee-principal-type User \
    --role "Key Vault Crypto Officer" --scope "$scope" -o none
}

cmd_identity_create() {
  check_signer "$1"
  gate "create user-assigned identity $(identity_name "$1") in $(signer_location "$1"), group $RG"
  az identity create -g "$RG" -n "$(identity_name "$1")" -l "$(signer_location "$1")" -o none
}

cmd_key_create() {
  local n="$1" dir hash
  check_signer "$n"
  need VAULT
  gate "create HSM key $(key_name "$n") (RSA $KEY_SIZE, exportable, immutable=$KEY_IMMUTABLE) in $VAULT with a release policy for the CCE policy of signer $n"
  # key create on an existing name adds a version, and a runner releases the
  # newest version at its next start: that would take a running group's key.
  # Only a clear "not found" lets the step go on.
  local shown
  if shown="$(az keyvault key show --vault-name "$VAULT" -n "$(key_name "$n")" -o none 2>&1)"; then
    die "key $(key_name "$n") exists in $VAULT: key-create makes a new key and never a new version (set KEY_NAME_$n to a new name)"
  fi
  grep -q KeyNotFound <<<"$shown" ||
    die "cannot tell whether key $(key_name "$n") exists in $VAULT: $(tail -n 2 <<<"$shown")"
  hash="$(policy_for "$n")"
  if network_one_policy && [ -s "$OUT/policy.sha256" ] && [ "$(cat "$OUT/policy.sha256")" != "$hash" ]; then
    die "signer $n renders CCE policy $hash, not the image's one policy $(cat "$OUT/policy.sha256") (deploy.sh policy)"
  fi
  dir="$(signer_dir "$n")"
  MAA_ENDPOINT="$(signer_maa_endpoint "$n")" CCE_POLICY_SHA256="$hash" \
    envsubst '${MAA_ENDPOINT} ${CCE_POLICY_SHA256}' <"$AZ_DIR/skr-policy.json.tmpl" >"$dir/skr-policy.json"
  jq -e . "$dir/skr-policy.json" >/dev/null
  local args=(--vault-name "$VAULT" -n "$(key_name "$n")" --kty RSA-HSM --size "$KEY_SIZE"
    --ops wrapKey unwrapKey encrypt decrypt --exportable true --policy "@$dir/skr-policy.json")
  if [ "$KEY_IMMUTABLE" = true ]; then args+=(--immutable true); fi
  az keyvault key create "${args[@]}" -o none
  echo "$hash" >"$dir/key.policy.sha256"
}

cmd_key_role() {
  local n="$1" principal scope
  check_signer "$n"
  need VAULT
  gate "assign Key Vault Crypto Service Release User and Key Vault Reader on key $(key_name "$n") of $VAULT to $(identity_name "$n")"
  principal="$(az identity show -g "$RG" -n "$(identity_name "$n")" --query principalId -o tsv)"
  scope="$(az keyvault show -n "$VAULT" -g "$RG" --query id -o tsv)/keys/$(key_name "$n")"
  az role assignment create --assignee-object-id "$principal" --assignee-principal-type ServicePrincipal \
    --role "Key Vault Crypto Service Release User" --scope "$scope" -o none
  # Get Key: the runner hashes the key's release policy and immutable flag
  # into key_release_hash (platform-azure/azure ReleaseHash). The release
  # role does not allow it; Key Vault Reader reads metadata, never key
  # material.
  az role assignment create --assignee-object-id "$principal" --assignee-principal-type ServicePrincipal \
    --role "Key Vault Reader" --scope "$scope" -o none
}

# store-role N: the mark log's container (and the state copy's, when it is
# another one) of SETUP_FILE_N. Records need the data role on the
# container. The lock check at every start reads the storage account and
# the container from the management plane (platform-azure/azlog Lock),
# which needs Microsoft.Storage/storageAccounts/read and
# .../containers/read: Reader on the account scope grants those reads and
# no write. Without it the runner stops at the lock check.
cmd_store_role() {
  local n="$1" principal scope scopes accounts
  check_signer "$n"
  need_setup "$n" >/dev/null
  scopes="$(store_scopes "$n")"
  [ -n "$scopes" ] || die "SETUP_FILE_$n names no Azure store"
  accounts="$(store_accounts "$n")"
  gate "assign Storage Blob Data Contributor to $(identity_name "$n") on: $(tr '\n' ' ' <<<"$scopes"), and Reader on: $(tr '\n' ' ' <<<"$accounts")"
  principal="$(az identity show -g "$RG" -n "$(identity_name "$n")" --query principalId -o tsv)"
  while IFS= read -r scope; do
    az role assignment create --assignee-object-id "$principal" --assignee-principal-type ServicePrincipal \
      --role "Storage Blob Data Contributor" --scope "$scope" -o none
  done <<<"$scopes"
  while IFS= read -r scope; do
    az role assignment create --assignee-object-id "$principal" --assignee-principal-type ServicePrincipal \
      --role Reader --scope "$scope" -o none
  done <<<"$accounts"
}

cmd_acr_create() {
  need ACR_NAME
  gate "create container registry $ACR_NAME (Basic, admin user off) in $(signer_location 1), group $RG"
  az acr create -n "$ACR_NAME" -g "$RG" -l "$(signer_location 1)" --sku Basic --admin-enabled false -o none
}

cmd_acr_role() {
  local n="$1" principal scope
  check_signer "$n"
  need ACR_NAME
  gate "assign AcrPull on registry $ACR_NAME to $(identity_name "$n")"
  principal="$(az identity show -g "$RG" -n "$(identity_name "$n")" --query principalId -o tsv)"
  scope="$(az acr show -n "$ACR_NAME" -g "$RG" --query id -o tsv)"
  az role assignment create --assignee-object-id "$principal" --assignee-principal-type ServicePrincipal \
    --role AcrPull --scope "$scope" -o none
}

cmd_image_push() {
  local digest ref pushed
  need ACR_NAME
  [ -s "$OUT/runner.digest" ] || die "no $OUT/runner.digest: run platform-azure/deploy/build-image.sh first"
  digest="$(cat "$OUT/runner.digest")"
  ref="$(registry_server)/signer-runner:$IMAGE_TAG"
  gate "az acr login to $ACR_NAME (this runs docker login), then docker push $ref (digest $digest)"
  az acr login -n "$ACR_NAME"
  docker tag "$LOCAL_RUNNER_IMAGE" "$ref"
  pushed="$(docker push "$ref" | tee /dev/stderr | sed -n 's/.*digest: \(sha256:[0-9a-f]*\).*/\1/p' | tail -n 1)"
  [ "$pushed" = "$digest" ] || die "the registry reports digest '$pushed', build-image.sh made $digest; render again before deploying"
}

cmd_group_deploy() {
  local n="$1" dir hash expected identity setup_hash
  check_signer "$n"
  need VAULT ACR_NAME
  network_need
  # Once on its own: inside $(...) a failed check would not stop the step.
  need_setup "$n" >/dev/null
  setup_hash="$(need_setup "$n")"
  gate "deploy confidential container group $(group_name "$n") in $(signer_location "$n"), group $RG, setup $(setup_file "$n") (setup_sha256 $setup_hash); it bills per second while it runs"
  network_check_secrets
  dir="$(signer_dir "$n")"
  # The deployed policy must be the one the key's release policy names.
  hash="$(policy_for "$n")"
  expected="$(cat "$dir/key.policy.sha256" 2>/dev/null || echo "${EXPECT_POLICY_SHA256:-}")"
  [ -n "$expected" ] || die "no $dir/key.policy.sha256 (run key-create $n) and no EXPECT_POLICY_SHA256"
  [ "$hash" = "$expected" ] ||
    die "CCE policy hash $hash is not the one in the release policy of $(key_name "$n") ($expected): create a new key"
  identity="$(az identity show -g "$RG" -n "$(identity_name "$n")" --query id -o tsv)"
  # The parameters file may hold a secret (the network part's): mode 600
  # in a mode 700 directory, removed on exit. The secret never reaches a
  # command line or a log.
  TMP_DIR="$(umask 077 && mktemp -d)"
  (umask 077 && network_parameters "$n" >"$TMP_DIR/network.json")
  # The setup is not secret; it goes in the same file.
  base64 -w0 <"$(setup_file "$n")" >"$TMP_DIR/setup.b64"
  (umask 077 && jq -n --arg id "$identity" --rawfile setup "$TMP_DIR/setup.b64" --slurpfile net "$TMP_DIR/network.json" '{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
    contentVersion: "1.0.0.0",
    parameters: ({identityId: {value: $id}, signerSetup: {value: $setup}} + $net[0])
  }' >"$TMP_DIR/parameters.json")
  az deployment group create -g "$RG" -n "$(group_name "$n")-$(date -u +%Y%m%d%H%M%S)" \
    --template-file "$dir/template.json" --parameters "@$TMP_DIR/parameters.json" -o none
}

usage() {
  sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed -e '/^set -euo/d' -e 's/^# \{0,1\}//' >&2
  exit 2
}

main() {
  local cmd="${1:-}"
  [ $# -gt 0 ] && shift
  case "$cmd" in
    render | policy | group-deploy) check_network ;;
  esac
  case "$cmd" in
    plan) cmd_plan ;;
    render) cmd_render "${1:?signer index}" ;;
    policy) cmd_policy "$@" ;;
    rg-create) cmd_rg_create ;;
    vault-create) cmd_vault_create ;;
    vault-operator-role) cmd_vault_operator_role ;;
    identity-create) cmd_identity_create "${1:?signer index}" ;;
    key-create) cmd_key_create "${1:?signer index}" ;;
    key-role) cmd_key_role "${1:?signer index}" ;;
    store-role) cmd_store_role "${1:?signer index}" ;;
    acr-create) cmd_acr_create ;;
    acr-role) cmd_acr_role "${1:?signer index}" ;;
    image-push) cmd_image_push ;;
    group-deploy) cmd_group_deploy "${1:?signer index}" ;;
    *)
      # Commands of the build overlay (devnet_azure_cmd_<name>).
      if [ -n "$cmd" ] && devnet_has "azure_cmd_${cmd//-/_}"; then
        "devnet_azure_cmd_${cmd//-/_}" "$@"
      else
        usage
      fi ;;
  esac
}

main "$@"
