#!/usr/bin/env bash
# The deploy scripts' names for a second signer next to a running one, a
# handover target, checked without Azure or GCP:
#
#   GCP    VM, ADDRESS_NAME, KMS_KEY, WIF_POOL and WIF_PROVIDER: the plan
#          makes the target's address, key (kms-key-create, no key ring),
#          pool and provider pinned to its digest, binds the new key and
#          the mark bucket to the new pool only, and creates the VM with the
#          new address. teardown and kms-create refuse; vm-create takes a
#          setup that names the new provider and key and refuses the
#          running signer's
#   Azure  GROUP_NAME_N, KEY_NAME_N, IDENTITY_NAME_N: the plan takes the new
#          key name, key-create refuses a key name that exists (a new
#          version would take the running group's key) and one whose
#          existence it cannot read. With the build overlay
#          (SIGNER_BUILD_OVERLAY_DIR, which has the network entries)
#          also: the render goes to the
#          group's own folder with the running group's identity, the plan
#          and group-deploy take the new key name, key-create refuses a key
#          name that exists (a new version would take the running group's
#          key) and one whose existence it cannot read
#
# The scripts run in a copy of the repo's scripts and cloud folders, with a
# fake image digest and a fake az for key-create, so build/ of this checkout
# is never touched and no cloud command runs.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/scripts" "$work/platform-gcp" "$work/platform-azure" "$work/governance" "$work/bin"
cp "$ROOT/scripts/common.sh" "$work/scripts/"
cp -r "$ROOT/platform-gcp/deploy" "$work/platform-gcp/"
cp -r "$ROOT/platform-azure/deploy" "$work/platform-azure/"
cp -r "$ROOT/governance/chains" "$work/governance/"
fail=0
bad() { echo "FAIL $*"; fail=1; }
ok() { echo "ok   $*"; }
run_rc() { if out="$("$@" 2>&1)"; then rc=0; else rc=$?; fi; }

arch="$(uname -m)"
case "$arch" in amd64) arch=x86_64 ;; arm64) arch=aarch64 ;; esac
TOOL="$work/build/$arch/bin/setup-tool"
mkdir -p "$(dirname "$TOOL")"
(cd "$ROOT/signer-admin" && CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "$TOOL" ./cmd/setup-tool)
"$TOOL" chain-lines "$ROOT/governance/chains/chain.testnet.json" >"$work/chain.lines"
make_setup() { # make_setup SAMPLE OUT [KEY=VALUE...]
  local sample="$1" out="$2" kv
  shift 2
  awk -F' = ' 'NR == FNR { if (NF > 1) drop[$1] = 1; next } !($1 in drop)' \
    "$work/chain.lines" "$ROOT/governance/setuptext/testdata/$sample" >"$work/setup.conf"
  cat "$work/chain.lines" >>"$work/setup.conf"
  for kv in "$@"; do
    sed -i "s|^${kv%%=*} = .*|${kv%%=*} = ${kv#*=}|" "$work/setup.conf"
  done
  "$TOOL" encode "$work/setup.conf" "$out" >/dev/null
}

# ---- GCP --------------------------------------------------------------------
mkdir -p "$work/build/gcp"
digest="sha256:$(printf 'target' | sha256sum | cut -d' ' -f1)"
echo "$digest" >"$work/build/gcp/runner.digest"
T3=(VM=signer-node-3b ADDRESS_NAME=signer-node-3b-ip KMS_KEY=sealing-3b WIF_POOL=signer-pool-3b WIF_PROVIDER=signer-attestation-3b)
gcp() { env "$@" NETWORK_ENTRY=public MARK_STORE=gcs:bucket=signer-marks-3 bash "$work/platform-gcp/deploy/deploy.sh" "${GCP_CMD[@]}"; }
GCP_CMD=(plan)
p="$(gcp "${T3[@]}" 2>&1)"
pool="projects/[^/]*/locations/global/workloadIdentityPools"
want=(
  "A second signer next to a running one: VM signer-node-3b"
  "gcloud compute addresses create signer-node-3b-ip"
  "gcloud kms keys create sealing-3b --keyring=signer"
  "gcloud iam workload-identity-pools create signer-pool-3b"
  "providers create-oidc signer-attestation-3b --location=global --workload-identity-pool=signer-pool-3b"
  "assertion.submods.container.image_digest == '$digest'"
  "gcloud kms keys add-iam-policy-binding sealing-3b"
  "gcloud compute instances create signer-node-3b"
  "--address=signer-node-3b-ip"
  "gcloud compute instances delete signer-node-3b"
)
miss=""
for w in "${want[@]}"; do grep -q -F -- "$w" <<<"$p" || miss+=" [$w]"; done
[ -z "$miss" ] && ok "gcp plan of the target: its address, key, pool, provider and VM" || bad "gcp plan of the target lacks$miss"
grep -q -- "--member=principalSet://iam.googleapis.com/$pool/signer-pool-3b/\*" <<<"$(grep -A2 'add-iam-policy-binding sealing-3b' <<<"$p")" &&
  ok "gcp plan: the new key's role goes to the new pool's principal set" || bad "gcp plan: key binding $(grep -A2 'add-iam-policy-binding sealing-3b' <<<"$p")"
b="$(grep -A9 'step bucket-bind' <<<"$p")"
grep -q 'signer-pool-3b/\*' <<<"$b" && ! grep -q 'signer-pool/\*' <<<"$b" &&
  ok "gcp plan: bucket-bind for the new pool only" || bad "gcp plan bucket-bind: $b"
for w in "keyrings create" "networks create" "networks delete" "firewall-rules delete" "service-accounts delete" \
  "artifacts repositories delete" "sa-create" "providers update-oidc signer-attestation "; do
  grep -q -F -- "$w" <<<"$p" && bad "gcp plan of the target has '$w'"
done
ok "gcp plan of the target: no step on the shared network, registry, key ring or service account"
p0="$(gcp 2>&1)"
grep -q 'gcloud kms keyrings create signer' <<<"$p0" && grep -q 'gcloud compute instances create signer-node-1' <<<"$p0" &&
  grep -q 'gcloud compute networks delete signer-net' <<<"$p0" && ! grep -q 'A second signer' <<<"$p0" &&
  ok "gcp plan without overrides: the full plan for signer-node-1, as before" || bad "gcp plan without overrides changed"
GCP_CMD=(teardown)
run_rc gcp "${T3[@]}"
[ "$rc" != 0 ] && grep -q 'teardown refuses' <<<"$out" && ! grep -q 'networks delete' <<<"$out" &&
  ok "gcp teardown refuses for a target and lists its own deletes" || bad "gcp teardown with overrides: rc $rc $out"
GCP_CMD=(kms-create)
run_rc gcp "${T3[@]}"
[ "$rc" != 0 ] && [ "$rc" != 3 ] && grep -q 'takes kms-key-create' <<<"$out" && ok "gcp kms-create refuses for a target" || bad "gcp kms-create: rc $rc $out"
GCP_CMD=(kms-key-create)
run_rc gcp "${T3[@]}"
[ "$rc" = 3 ] && grep -q 'HSM key sealing-3b in the existing key ring signer' <<<"$out" && ok "gcp kms-key-create stops at its gate" || bad "gcp kms-key-create: rc $rc $out"
GCP_CMD=(plan)
run_rc gcp VM=Signer_3
[ "$rc" != 0 ] && grep -q 'VM=Signer_3 is not a Compute Engine name' <<<"$out" && ok "gcp refuses VM=Signer_3" || bad "gcp VM=Signer_3: rc $rc $out"

# vm-create: the target's setup names the new provider and key.
names="$(env "${T3[@]}" bash -c '. "$1/platform-gcp/deploy/common.sh" && printf "%s\n%s\n" "$WIF_PROVIDER_RESOURCE" "$KMS_KEY_RESOURCE"' _ "$work")"
make_setup setup-gcp.conf "$work/gcp-3b.bin" "sealing_key_release.wif_provider=$(sed -n 1p <<<"$names")" "sealing_key_release.kms_key=$(sed -n 2p <<<"$names")"
names0="$(bash -c '. "$1/platform-gcp/deploy/common.sh" && printf "%s\n%s\n" "$WIF_PROVIDER_RESOURCE" "$KMS_KEY_RESOURCE"' _ "$work")"
make_setup setup-gcp.conf "$work/gcp-3.bin" "sealing_key_release.wif_provider=$(sed -n 1p <<<"$names0")" "sealing_key_release.kms_key=$(sed -n 2p <<<"$names0")"
vm_create() { run_rc env "${T3[@]}" CHAIN=testnet NETWORK_ENTRY=public SETUP_FILE="$1" bash "$work/platform-gcp/deploy/deploy.sh" vm-create; }
vm_create "$work/gcp-3b.bin"
[ "$rc" = 3 ] && grep -q 'step vm-create: signer-node-3b' <<<"$out" && grep -q 'external address signer-node-3b-ip' <<<"$out" &&
  ok "gcp vm-create of the target: its setup passes, VM and address are the target's" || bad "gcp vm-create target: rc $rc $out"
vm_create "$work/gcp-3.bin"
[ "$rc" != 0 ] && [ "$rc" != 3 ] && grep -q 'names WIF provider' <<<"$out" && grep -q 'signer-pool-3b' <<<"$out" &&
  ok "gcp vm-create of the target refuses the running signer's provider" || bad "gcp vm-create with the source's names: rc $rc $out"

# ---- Azure ------------------------------------------------------------------
out_az="$work/build/azure"
mkdir -p "$out_az"
echo "sha256:$(printf 'az' | sha256sum | cut -d' ' -f1)" >"$out_az/runner.digest"
A1=(GROUP_NAME_1=signer-1b KEY_NAME_1=signer-1b-kek)
az_env=(ACR_NAME=signeracr VAULT=signer-vault LOCATION_1=northeurope)
# The render and group-deploy need a network entry, which only the build
# overlay has.
net=0
if [ -n "${SIGNER_BUILD_OVERLAY_DIR:-}" ]; then
  net=1
  # The overlay's azure_network_defaults hook picks NETWORK when unset.
  [ -z "${NETWORK:-}" ] || az_env+=(NETWORK="$NETWORK")
fi
if [ "$net" = 1 ]; then
env "${A1[@]}" "${az_env[@]}" bash "$work/platform-azure/deploy/deploy.sh" render 1 >/dev/null 2>&1 || bad "azure render of signer-1b failed"
t="$out_az/signer-1b/template.json"
if [ -f "$t" ] && [ "$(jq -r .parameters.name.defaultValue "$t")" = signer-1b ] &&
  jq -r .parameters.identityId.defaultValue "$t" | grep -q '/userAssignedIdentities/signer-id-1$' && [ ! -e "$out_az/signer-1" ]; then
  ok "azure render: group signer-1b in its own folder, identity signer-id-1"
else bad "azure render of signer-1b: $(ls "$out_az")"; fi
else
  echo "skip azure render and group-deploy: no network entry without the build overlay"
fi
p="$(env "${A1[@]}" "${az_env[@]}" bash "$work/platform-azure/deploy/deploy.sh" plan 2>&1)"
grep -q 'key-create 1 *signer-1b-kek' <<<"$p" && grep -q 'group-deploy 1 *signer-1b in northeurope' <<<"$p" &&
  grep -q 'key-role 1 *signer-id-1 releases and reads signer-1b-kek' <<<"$p" && grep -q 'key-create 2 *signer-kek-2' <<<"$p" &&
  ok "azure plan: signer 1's second group and key, the others as before" || bad "azure plan: $p"
az_ok=("sealing_key_release.maa_endpoint=sharedneu.neu.attest.azure.net" "sealing_key_release.akv_endpoint=signer-vault.vault.azure.net")
make_setup setup-azure.conf "$work/az-1b.bin" "${az_ok[@]}" "sealing_key_release.kid=signer-1b-kek"
make_setup setup-azure.conf "$work/az-1.bin" "${az_ok[@]}" "sealing_key_release.kid=signer-kek-1"
deploy() { run_rc env "${A1[@]}" "${az_env[@]}" CHAIN=testnet "SETUP_FILE_1=$1" bash "$work/platform-azure/deploy/deploy.sh" group-deploy 1; }
if [ "$net" = 1 ]; then
deploy "$work/az-1b.bin"
[ "$rc" = 3 ] && grep -q 'deploy confidential container group signer-1b in northeurope' <<<"$out" &&
  ok "azure group-deploy of signer-1b: its setup passes" || bad "azure group-deploy signer-1b: rc $rc $out"
deploy "$work/az-1.bin"
[ "$rc" != 0 ] && [ "$rc" != 3 ] && grep -q 'names key signer-kek-1, this deploy signer-1b-kek' <<<"$out" &&
  ok "azure group-deploy of signer-1b refuses the running group's key" || bad "azure group-deploy signer-1b, old key: rc $rc $out"
fi
run_rc env GROUP_NAME_1=signer_1b "${az_env[@]}" bash "$work/platform-azure/deploy/deploy.sh" plan
[ "$rc" != 0 ] && grep -q 'GROUP_NAME_1=signer_1b' <<<"$out" && ok "azure refuses GROUP_NAME_1=signer_1b" || bad "azure GROUP_NAME_1=signer_1b: rc $rc $out"

# key-create: a fake az answers the existence check; nothing else may run.
fake_az() { # fake_az MODE: exists, notfound or denied
  cat >"$work/bin/az" <<EOF
#!/usr/bin/env bash
echo "az \$*" >>"$work/az.log"
case "\$1 \$2 \$3" in
  "keyvault key show")
    case "$1" in
      exists) exit 0 ;;
      notfound) echo "ERROR: (KeyNotFound) A key with (name/id) x was not found in this key vault." >&2; exit 3 ;;
      denied) echo "ERROR: (Forbidden) The user does not have keys get permission." >&2; exit 1 ;;
    esac ;;
esac
echo "unexpected az call" >&2
exit 99
EOF
  chmod +x "$work/bin/az"
  : >"$work/az.log"
}
key_create() { run_rc env PATH="$work/bin:$PATH" CONFIRM=yes "${A1[@]}" "${az_env[@]}" bash "$work/platform-azure/deploy/deploy.sh" key-create 1; }
fake_az exists
key_create
[ "$rc" != 0 ] && grep -q 'key signer-1b-kek exists in signer-vault' <<<"$out" && [ "$(wc -l <"$work/az.log")" = 1 ] &&
  ok "azure key-create refuses a key name that exists (no new version)" || bad "azure key-create, key exists: rc $rc $out"
fake_az denied
key_create
[ "$rc" != 0 ] && grep -q 'cannot tell whether key signer-1b-kek exists' <<<"$out" && [ "$(wc -l <"$work/az.log")" = 1 ] &&
  ok "azure key-create refuses when it cannot read whether the key exists" || bad "azure key-create, denied: rc $rc $out"
fake_az notfound
key_create
grep -q 'exists in' <<<"$out" && bad "azure key-create, not found: $out"
grep -q 'unexpected az call' <<<"$out" && bad "azure key-create went on to another az call before the policy step: $out"
[ "$rc" != 0 ] && ! grep -q 'cannot tell' <<<"$out" && ok "azure key-create goes past the check for a new name (stops later, at the local image)" ||
  bad "azure key-create, not found: rc $rc $out"

[ "$fail" = 0 ] || exit 1
echo "side-by-side-test: all cases as expected"
