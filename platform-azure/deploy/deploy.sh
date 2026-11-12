#!/usr/bin/env bash
# UNTESTED ON AZURE. The Azure deployment: three signers, each one confidential
# container group with the runner alone, which does the attestation and the
# key release itself and listens on port 7100.
#
#   deploy.sh <command> [N]        N is the signer index 1, 2 or 3
#
# Local commands. They never touch an Azure account:
#   plan             list the Azure steps in order, with the names they would use
#   render N         fill aci-template.json for signer N (and add the network
#                    part, when NETWORK names one)
#   policy [N]       render, then run az confcom acipolicygen on this machine and
#                    print the CCE policy SHA-256 (all three signers without N).
#                    When the command holds nothing of a signer (the runner
#                    alone, or such a network entry), with no N it checks that
#                    the three are one policy and writes it to $OUT/policy.sha256:
#                    the hash every release policy and verifier pins, for any
#                    signer and any chain. The subnet and the log workspace
#                    are deploy parameters and do not change it. Before it
#                    prints a hash, cce-policy-check.py reads the policy
#                    and refuses one that allows more than the template's
#                    containers with their local images' layers
#   confcom-install  install az confcom CONFCOM_VERSION from its wheel,
#                    checked against CONFCOM_WHEEL_SHA256 (common.sh); the
#                    policy step refuses any other version
#
# Azure commands. Each one creates or changes something in Azure, prints
# what it would do and refuses to run unless CONFIRM=yes is set:
#   rg-create                 resource group
#   vault-create              Key Vault Premium, RBAC authorization, purge protection
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
# signer N, see "Setup" below), CHAIN (the chain of the build and of the
# setups: mainnet, the default, hoodi, devnet or ci-test), VAULT and ACR_NAME (globally unique names, no
# default), RG (default signer-poc-rg), SUBSCRIPTION_ID (the identity's
# resource ID in the template; when set, group-deploy and store-role check
# that the setup's stores name it), LOCATION_N, MAA_ENDPOINT_N,
# SUBNET_ID_N (optional: the resource ID of a subnet delegated to
# Microsoft.ContainerInstance/containerGroups; the group of signer N gets a
# private IP there, port 7100 open; unset, the group has no IP address),
# LOG_WORKSPACE_ID and LOG_WORKSPACE_KEY_FILE (optional, both or neither:
# a Log Analytics workspace ID and a file with its shared key; the group
# sends its logs there), NETWORK (optional, unset for the runner alone:
# a network entry part of the build overlay SIGNER_BUILD_OVERLAY_DIR, with
# its settings), STDIO=enable|disable (default enable),
# KEY_IMMUTABLE=true|false (default true; false only on a non-prod CHAIN),
# KEY_SIZE (default 2048),
# DMVERITY_VHD (optional: the dmverity-vhd binary that hashes the image
# layers for the policy check; default the one in the confcom extension;
# either way its SHA-256 must be DMVERITY_VHD_SHA256 of common.sh),
# KEY_NAME_PREFIX (default signer-kek: the keys are signer-kek-N; the
# generic image takes its own, for example signer-gkek, so a running
# per-chain image keeps its key),
# GROUP_NAME_N, KEY_NAME_N, IDENTITY_NAME_N (a second group of signer N
# next to the running one: group
# signer-1b with a new key name and the running group's identity; build
# files in $OUT/<group>; key-create refuses a key name that exists, since
# that would add a version to the running group's key),
# See README.md for
# the order and for what each step costs.
#
# The hash of the CCE policy decides which code gets the key. Any change to
# the runner image, the container commands or the network image changes it,
# so run `policy` again and create the keys after the last change. Secrets
# never appear on a command line: the workspace key and a network part's
# secret go to ARM in a mode 600 parameters file.
#
# Setup: the image and the command hold no chain config, client CA, vault,
# key, attestation provider or mark log. Each signer's setup holds them, made with
# signer-admin setup (one per signer of a cluster) or signer-admin/cmd/setup-tool
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
KEY_IMMUTABLE="${KEY_IMMUTABLE:-true}"
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
# By default the group holds the runner alone. A build overlay
# (SIGNER_BUILD_OVERLAY_DIR) may add a network entry with NETWORK: a
# template part (network_file) and the functions below, which call the
# overlay's devnet_azure_network_<name>. The entry is not trusted and can be
# replaced; nothing but the runner's port 7100 may listen inside the group.
# Without NETWORK each function gives the runner-alone answer.

network_fn() {
  local f="azure_network_$1"
  shift
  devnet_has "$f" || die "NETWORK=${NETWORK:-unset}: no network entry part (this tree has none)"
  "devnet_$f" "$@"
}
# network_part: the template part as JSON (see aci-template.json); for the
# runner alone, no container and no parameters.
network_part() { if has_network; then cat "$(network_fn file)"; else echo '{"parameters": {}}'; fi; }
# network_images: "local name|public name" of each image of the part that the
# policy tool needs in the local Docker daemon.
network_images() { has_network || return 0; network_fn images; }
# network_need: the settings group-deploy needs from the environment.
network_need() { has_network || return 0; network_fn need; }
# network_check_secrets: stop unless the secret files of the part are usable.
network_check_secrets() { has_network || return 0; network_fn check_secrets; }
# network_parameters N: the deployment parameters of the part, as a JSON
# object on stdout. They may hold a secret, so the caller writes them to a
# mode 600 file.
network_parameters() { if has_network; then network_fn parameters "$1"; else echo '{}'; fi; }
# network_describe N: one line for `plan`.
network_describe() {
  local s
  if has_network; then network_fn describe "$1"; return; fi
  s="$(subnet_id "$1")"
  if [ -n "$s" ]; then echo "runner alone, private IP in subnet ${s##*/}"; else echo "runner alone, no IP address"; fi
}
# network_vars N: NAME=VALUE lines; render replaces @NAME@ in the template.
network_vars() { has_network || return 0; network_fn vars "$1"; }
# network_one_policy: true when the command holds nothing of one signer,
# so the three signers' policies must be one. Always so for the runner alone.
network_one_policy() { has_network || return 0; network_fn one_policy; }

# ---- local steps ----------------------------------------------------------

# render N: build/azure/signer-N/template.json from aci-template.json and
# the network part, if any. The subnet and the log workspace are not
# rendered: group-deploy passes them as parameters, so the rendered
# template is the same whatever subnet or workspace an operator uses.
render() {
  local n="$1" dir digest vars net
  check_signer "$n"
  check_network
  need ACR_NAME
  [ -s "$OUT/runner.digest" ] || die "no $OUT/runner.digest: run platform-azure/deploy/build-image.sh first"
  digest="$(cat "$OUT/runner.digest")"
  vars="$(network_vars "$n" | jq -Rn '[inputs | select(length > 0) | capture("^(?<k>[A-Z_]+)=(?<v>.*)$")] | map({(.k): .v}) | add // {}')" || exit 1
  net="$(network_part)" || exit 1
  dir="$(signer_dir "$n")"
  mkdir -p "$dir"
  jq \
    --argjson net "$net" \
    --arg group "$(group_name "$n")" --arg loc "$(signer_location "$n")" \
    --arg runner "$(registry_server)/signer-runner@$digest" \
    --arg ident "/subscriptions/${SUBSCRIPTION_ID:-$ZERO_GUID}/resourceGroups/$RG/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$(identity_name "$n")" \
    --arg reg "$(registry_server)" --argjson vars "$vars" '
    .parameters += $net.parameters
    | if $net.container then .resources[0].properties.containers += [$net.container] else . end
    | if $net.runner then
        .resources[0].properties.containers[0].properties |=
          (.command = $net.runner.commandPrefix + .command[0:1] + $net.runner.runnerFlags + .command[1:]
           | .environmentVariables = ((.environmentVariables // []) + $net.runner.environmentVariables))
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
  # The runner's clock is the NTS clock (runner-azure has the tag nts), with
  # its start wait in the command, and nothing in the command replaces it.
  jq -e '.resources[0].properties.containers[0].properties.command
    | index("-nts-clock") != null and index("-nts-coarse-urls") != null
      and index("-nts-wait") != null and index("-clock") == null' \
    "$dir/template.json" >/dev/null || die "the runner command in $dir/template.json does not run the NTS clock alone"
  # The protocol, the bounds and the extra servers come from the setup
  # (time_policy, time_servers), and the runner refuses their flags with one.
  jq -e '.resources[0].properties.containers[0].properties.command
    | map(select(test("^-(clock-protocol|nts-max-bound|nts-max-sample-bound|nts-terms-confirmed)(=|$)"))) | length == 0' \
    "$dir/template.json" >/dev/null ||
    die "the runner command in $dir/template.json sets -clock-protocol, -nts-max-bound, -nts-max-sample-bound or -nts-terms-confirmed, which the setup gives (time_policy, time_servers)"
  log "signer $n: clock protocol and bounds from the setup (time_policy)"
  # The runner takes its values from the setup in SIGNER_SETUP, a parameter
  # without a default, and the command names none of them.
  jq -e '.resources[0].properties.containers[0].properties
    | (.command | index("-setup") != null and index("-config") == null and index("-tls-client-ca") == null
       and index("-platform-opt") == null and index("-mark-store") == null)
      and ([.environmentVariables[] | select(.name == "SIGNER_SETUP")][0].value == "[parameters('"'"'signerSetup'"'"')]")' \
    "$dir/template.json" >/dev/null || die "the runner in $dir/template.json does not take its setup from SIGNER_SETUP alone"
  jq -e '.parameters.signerSetup | has("defaultValue") | not' "$dir/template.json" >/dev/null ||
    die "signerSetup has a default in $dir/template.json: the CCE policy would pin one setup"
  # The runner listens on port 7100 of every interface and declares it.
  jq -e '.resources[0].properties.containers[0] | .name == "runner"
    and (.properties.command | index("-listen") as $i | $i != null and .[$i + 1] == "tcp:0.0.0.0:7100")
    and .properties.ports == [{port: 7100, protocol: "TCP"}]' \
    "$dir/template.json" >/dev/null || die "the runner in $dir/template.json does not listen on tcp:0.0.0.0:7100 with port 7100 declared"
  # The subnet and the log workspace are optional group properties. No
  # container may use them, or they would be in the CCE policy.
  jq -e '(.parameters | .subnetId.defaultValue == "" and .logWorkspaceId.defaultValue == ""
      and .logWorkspaceKey.defaultValue == "" and .logWorkspaceId.type == "securestring"
      and .logWorkspaceKey.type == "securestring")
    and ([.resources[0].properties.containers[] | tostring | test("subnetId|logWorkspace")] | any | not)' \
    "$dir/template.json" >/dev/null || die "subnetId or a logWorkspace parameter in $dir/template.json is not optional, or a container uses it"
  if ! has_network; then
    jq -e '.resources[0].properties.containers | length == 1' "$dir/template.json" >/dev/null ||
      die "$dir/template.json holds more than the runner"
  fi
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

# check_confcom: the installed az confcom is CONFCOM_VERSION, the version
# whose policy text cce-policy-check.py rebuilds.
check_confcom() {
  local v
  v="$(az extension show -n confcom --query version -o tsv 2>/dev/null)" || v=""
  [ "$v" = "$CONFCOM_VERSION" ] ||
    die "az confcom ${v:-not installed}: the policy step takes confcom $CONFCOM_VERSION only (deploy.sh confcom-install)"
}

# dmverity_vhd: the path of the dmverity-vhd binary (DMVERITY_VHD, else the
# one in the confcom extension), checked against DMVERITY_VHD_SHA256.
dmverity_vhd() {
  local bin="${DMVERITY_VHD:-}" ext
  if [ -z "$bin" ]; then
    ext="$(az extension show -n confcom --query path -o tsv)" && [ -n "$ext" ] ||
      die "cannot find the folder of the confcom extension (az extension show -n confcom)"
    bin="$ext/azext_confcom/bin/dmverity-vhd"
  fi
  [ -f "$bin" ] || die "no dmverity-vhd at $bin"
  [ "$(sha256sum <"$bin" | cut -d' ' -f1)" = "$DMVERITY_VHD_SHA256" ] ||
    die "$bin is not dmverity-vhd v2.2 (SHA-256 $DMVERITY_VHD_SHA256)"
  # The confcom wheel ships the binary without the exec bit and sets it at
  # its first acipolicygen run, which comes after this check.
  if [ ! -x "$bin" ] && [ -z "${DMVERITY_VHD:-}" ]; then
    chmod u+x "$bin" || die "cannot make $bin executable"
  fi
  [ -x "$bin" ] || die "no executable dmverity-vhd at $bin"
  echo "$bin"
}

# policy_images DIR: DIR/policy-images.json, what cce-policy-check.py needs
# from the local image of each container of DIR/template.json: the
# dm-verity hash of each layer, computed here with the pinned dmverity-vhd
# and not taken from az confcom, and the image config.
policy_images() {
  local dir="$1" bin digest name image src pair layers config out='{}'
  bin="$(dmverity_vhd)" || exit 1
  # policy_for runs inside $(...), where set -e does not stop a failed
  # command, so each step below stops on its own failure.
  digest="$(cat "$OUT/runner.digest")" || die "no $OUT/runner.digest"
  [ "$(docker image inspect "$LOCAL_RUNNER_IMAGE" --format '{{.Id}}')" = "$digest" ] ||
    die "local image $LOCAL_RUNNER_IMAGE is not $digest ($OUT/runner.digest): run build-image.sh again"
  while IFS=$'\t' read -r name image; do
    src=""
    if [ "$image" = "$(registry_server)/signer-runner@$digest" ]; then
      src="$LOCAL_RUNNER_IMAGE"
    else
      while IFS= read -r pair; do
        [ "${pair%%|*}" != "$image" ] || src="${pair#*|}"
      done < <(network_images)
    fi
    [ -n "$src" ] || die "container $name in $dir/template.json runs $image, which is neither the runner image nor one of the network part"
    layers="$("$bin" -d roothash -i "$src" 2>>"$dir/policy.log")" || die "dmverity-vhd could not hash the layers of $src (log: $dir/policy.log)"
    config="$(docker image inspect "$src" --format '{{json .Config}}')" || die "cannot read the config of $src"
    out="$(jq -c --arg n "$name" --argjson l "$layers" --argjson c "$config" '. + {($n): {layers: $l.layers,
      env: ($c.Env // []), working_dir: ($c.WorkingDir // ""), user: ($c.User // ""), stop_signal: ($c.StopSignal // "")}}' <<<"$out")" ||
      die "unexpected dmverity-vhd output for $src: $layers"
  done < <(jq -r '.parameters as $p | .resources[0].properties.containers[]
    | [.name, (.properties.image | (capture("^\\[parameters\\('"'"'(?<p>[A-Za-z0-9_]+)'"'"'\\)\\]$").p as $k | $p[$k].defaultValue) // .)]
    | @tsv' "$dir/template.json")
  [ "$(jq -c 'keys' <<<"$out")" = "$(jq -c '[.resources[0].properties.containers[].name] | sort' "$dir/template.json")" ] ||
    die "could not read the image of every container in $dir/template.json"
  echo "$out" >"$dir/policy-images.json" || die "cannot write $dir/policy-images.json"
}

# policy_for N: render and run az confcom acipolicygen. The template gets
# its ccePolicy and the SHA-256 of the decoded policy is printed on stdout
# (all other output goes to stderr, which is kept in policy.log). The hash
# is the value of the x-ms-sevsnpvm-hostdata claim. Before the hash is
# printed, cce-policy-check.py reads the policy and refuses anything but
# the containers of the template with their images' layers (README.md,
# "CCE policy check").
policy_for() {
  local n="$1" dir hash check
  case "$STDIO" in enable | disable) ;; *) die "STDIO must be enable or disable" ;; esac
  render "$n"
  ensure_images
  check_confcom
  dir="$(signer_dir "$n")"
  # acipolicygen writes the policy into template.json. The check reads the
  # template as rendered, and confcom may change nothing but ccePolicy.
  cp "$dir/template.json" "$dir/template.rendered.json"
  : >"$dir/policy.log"
  policy_images "$dir"
  # -y approves the wildcard rule for the parameters without a default
  # (signerSetup and those of the network part). --omit-id keeps the registry and image tag out
  # of the policy. stdin is closed: the tool asks before it overwrites a policy.
  if ! hash="$(az confcom acipolicygen -a "$dir/template.json" -y --omit-id "--$STDIO-stdio" \
    </dev/null 2>>"$dir/policy.log")"; then
    tail -n 20 "$dir/policy.log" >&2
    die "az confcom acipolicygen failed (log: $dir/policy.log)"
  fi
  [[ "$hash" =~ ^[0-9a-f]{64}$ ]] || die "unexpected acipolicygen output '$hash' (see $dir/policy.log)"
  jq -r '.resources[0].properties.confidentialComputeProperties.ccePolicy' "$dir/template.json" |
    base64 -d >"$dir/policy.rego"
  check="$(sha256sum <"$dir/policy.rego" | cut -d' ' -f1)"
  [ "$check" = "$hash" ] || die "printed hash $hash is not the SHA-256 of the policy in the template ($check)"
  local nopol='.resources[0].properties.confidentialComputeProperties.ccePolicy = ""'
  cmp -s <(jq -S "$nopol" "$dir/template.rendered.json") <(jq -S "$nopol" "$dir/template.json") ||
    die "signer $n: az confcom changed the template beyond ccePolicy (compare $dir/template.rendered.json with $dir/template.json)"
  python3 -I "$AZ_DIR/cce-policy-check.py" check "$dir/policy.rego" "$dir/template.rendered.json" "$dir/policy-images.json" "$STDIO" ||
    die "signer $n: the CCE policy is not the one this tree expects; nothing pinned (compare with: python3 -I $AZ_DIR/cce-policy-check.py render $dir/template.json $dir/policy-images.json $STDIO)"
  echo "$hash" >"$dir/policy.sha256"
  echo "$hash"
}

cmd_render() { render "$1"; echo "$(signer_dir "$1")/template.json"; }

# confcom-install: the confcom wheel of CONFCOM_VERSION, checked against
# CONFCOM_WHEEL_SHA256 before az installs it (in place of any other
# confcom version). pip resolves the wheel's own dependencies.
cmd_confcom_install() {
  local got wheel
  TMP_DIR="$(mktemp -d)"
  wheel="$TMP_DIR/${CONFCOM_WHEEL_URL##*/}"
  log "downloading $CONFCOM_WHEEL_URL"
  curl -fsSL --proto '=https' -o "$wheel" "$CONFCOM_WHEEL_URL"
  got="$(sha256sum <"$wheel" | cut -d' ' -f1)"
  [ "$got" = "$CONFCOM_WHEEL_SHA256" ] || die "confcom wheel SHA-256 $got, want $CONFCOM_WHEEL_SHA256"
  # If the add below fails, no confcom is left: run confcom-install again.
  if az extension show -n confcom -o none 2>/dev/null; then
    az extension remove -n confcom
  fi
  az extension add --source "$wheel" --yes
  check_confcom
  dmverity_vhd >/dev/null
  log "az confcom $CONFCOM_VERSION installed"
}

cmd_policy() {
  local n h hashes=()
  if [ $# -gt 0 ]; then
    check_signer "$1"
    # An assignment, so a refused policy stops here.
    h="$(policy_for "$1")"
    echo "signer $1  $h"
    return 0
  fi
  for n in 1 2 3; do
    h="$(policy_for "$n")"
    hashes+=("$h")
    echo "signer $n  $h"
  done
  # The runner alone, or a network entry whose command holds nothing of a
  # signer: the three renders must give one policy. That hash is the
  # image's, set once in the release policies, whatever setup, subnet or
  # log workspace a group gets.
  if network_one_policy; then
    if [ "${hashes[0]}" != "${hashes[1]}" ] || [ "${hashes[0]}" != "${hashes[2]}" ]; then
      die "the three signers have different CCE policies; with NETWORK=${NETWORK:-unset} they must be one"
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
  setup per signer (SETUP_FILE_N: signer-admin setup for a cluster, or
  signer-admin/cmd/setup-tool encode)
Resource group $RG, registry $ACR_NAME, vault $VAULT, network entry ${NETWORK:-none (the runner alone)}.
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
  gate "create Key Vault $VAULT (Premium, RBAC authorization, purge protection) in $(signer_location 1), group $RG"
  # Purge protection: a deleted key stays recoverable for the retention
  # period, and nobody can purge it before. It cannot be turned off, and
  # the runner's lock check refuses a key without it.
  az keyvault create -n "$VAULT" -g "$RG" -l "$(signer_location 1)" --sku premium \
    --enable-rbac-authorization true --enable-purge-protection true -o none
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
  case "$KEY_IMMUTABLE" in true | false) ;; *) die "KEY_IMMUTABLE must be true or false (got '$KEY_IMMUTABLE')" ;; esac
  # A mutable release policy lets the key's owner release the key to any
  # code, so a prod chain takes only an immutable key.
  if [ "$KEY_IMMUTABLE" = false ] && chain_is_prod "$CHAIN"; then
    die "KEY_IMMUTABLE=false on prod chain $CHAIN: key-create makes only immutable keys there"
  fi
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
  # Record the version made here: group-deploy takes only a setup that names
  # it, so a later version under this name cannot replace the signer's key.
  local kid
  kid="$(az keyvault key create "${args[@]}" --query key.kid -o tsv)"
  [[ "$kid" =~ /([0-9a-f]{32})$ ]] || die "key create returned no key version: $kid"
  echo "${BASH_REMATCH[1]}" >"$dir/key.version"
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

# check_log_workspace: LOG_WORKSPACE_ID and LOG_WORKSPACE_KEY_FILE are both
# set or both unset, the ID is a GUID and the key file is not empty.
check_log_workspace() {
  local id="${LOG_WORKSPACE_ID:-}" key="${LOG_WORKSPACE_KEY_FILE:-}"
  [ -z "$id" ] && [ -z "$key" ] && return 0
  [ -n "$id" ] && [ -n "$key" ] || die "set both LOG_WORKSPACE_ID and LOG_WORKSPACE_KEY_FILE, or neither"
  [[ "$id" =~ ^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$ ]] || die "LOG_WORKSPACE_ID=$id: not a workspace ID (a GUID)"
  [ -s "$key" ] && [ -r "$key" ] || die "LOG_WORKSPACE_KEY_FILE=$key: no such readable, non-empty file"
}

# optional_parameters N: the subnet and log workspace parameters of signer
# N, as a JSON object on stdout. It holds the workspace key, so the caller
# writes it to a mode 600 file. Unset settings give no parameter: the
# template's empty defaults leave the property out.
optional_parameters() {
  jq -n --arg subnet "$(subnet_id "$1")" --arg ws "${LOG_WORKSPACE_ID:-}" \
    --rawfile key "${LOG_WORKSPACE_KEY_FILE:-/dev/null}" '
    (if $subnet == "" then {} else {subnetId: {value: $subnet}} end)
    + (if $ws == "" then {} else {logWorkspaceId: {value: $ws}, logWorkspaceKey: {value: ($key | rtrimstr("\n"))}} end)'
}

cmd_group_deploy() {
  local n="$1" dir hash expected identity setup_hash
  check_signer "$n"
  need VAULT ACR_NAME
  network_need
  check_log_workspace
  # Once on its own: inside $(...) a failed check would not stop the step.
  need_setup "$n" >/dev/null
  setup_hash="$(need_setup "$n")"
  dir="$(signer_dir "$n")"
  if [ -s "$dir/key.version" ]; then
    local kid
    kid="$(setup_value "$(setup_file "$n")" sealing_key_release.kid)"
    [ "$kid" = "$(key_name "$n")/$(cat "$dir/key.version")" ] ||
      die "SETUP_FILE_$n names key $kid, not $(key_name "$n")/$(cat "$dir/key.version") that key-create made"
  fi
  gate "deploy confidential container group $(group_name "$n") in $(signer_location "$n"), group $RG, $(network_describe "$n"), logs $([ -n "${LOG_WORKSPACE_ID:-}" ] && echo "to workspace $LOG_WORKSPACE_ID" || echo "not sent to a workspace"), setup $(setup_file "$n") (setup_sha256 $setup_hash); it bills per second while it runs"
  network_check_secrets
  # The deployed policy must be the one the key's release policy names.
  hash="$(policy_for "$n")"
  expected="$(cat "$dir/key.policy.sha256" 2>/dev/null || echo "${EXPECT_POLICY_SHA256:-}")"
  [ -n "$expected" ] || die "no $dir/key.policy.sha256 (run key-create $n) and no EXPECT_POLICY_SHA256"
  [ "$hash" = "$expected" ] ||
    die "CCE policy hash $hash is not the one in the release policy of $(key_name "$n") ($expected): create a new key"
  identity="$(az identity show -g "$RG" -n "$(identity_name "$n")" --query id -o tsv)"
  # The parameters file may hold secrets (the workspace key, the network
  # part's): mode 600 in a mode 700 directory, removed on exit. A secret
  # never reaches a command line or a log.
  TMP_DIR="$(umask 077 && mktemp -d)"
  (umask 077 && network_parameters "$n" >"$TMP_DIR/network.json")
  (umask 077 && optional_parameters "$n" >"$TMP_DIR/optional.json")
  # The setup is not secret; it goes in the same file.
  base64 -w0 <"$(setup_file "$n")" >"$TMP_DIR/setup.b64"
  (umask 077 && jq -n --arg id "$identity" --rawfile setup "$TMP_DIR/setup.b64" \
    --slurpfile net "$TMP_DIR/network.json" --slurpfile opt "$TMP_DIR/optional.json" '{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
    contentVersion: "1.0.0.0",
    parameters: ({identityId: {value: $id}, signerSetup: {value: $setup}} + $opt[0] + $net[0])
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
    confcom-install) cmd_confcom_install ;;
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
