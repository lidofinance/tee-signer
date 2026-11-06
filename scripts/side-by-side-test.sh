#!/usr/bin/env bash
# The deploy scripts' names for a second signer next to a running one,
# checked without Azure or GCP:
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
#          version would take the running group's key), one whose
#          existence it cannot read and a mutable key on mainnet, and makes
#          the key immutable unless KEY_IMMUTABLE=false. The render goes to the group's own
#          folder with the running group's identity, and group-deploy
#          takes the new key name and refuses the running group's. After
#          key-create it takes only a setup that names the created version
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
"$TOOL" chain-lines "$ROOT/governance/chains/chain.ci-test.json" >"$work/chain.lines"
make_setup() { # make_setup SAMPLE OUT [KEY=VALUE...]
  local sample="$1" out="$2" kv
  shift 2
  awk -F' = ' 'NR == FNR { if (NF > 1) drop[$1] = 1; next } !($1 in drop)' \
    "$work/chain.lines" "$ROOT/governance/setuptext/testdata/$sample" >"$work/setup.conf"
  cat "$work/chain.lines" >>"$work/setup.conf"
  # The GCP sample lists no gcp image; setup-tool refuses a setup without one.
  case "$sample" in
    setup-gcp*) echo "allowed_image_measurements = gcp 0x$(printf '9%.0s' {1..64})" >>"$work/setup.conf" ;;
  esac
  for kv in "$@"; do
    sed -i "s|^${kv%%=*} = .*|${kv%%=*} = ${kv#*=}|" "$work/setup.conf"
  done
  "$TOOL" encode "$work/setup.conf" "$out" >/dev/null
}

# ---- GCP --------------------------------------------------------------------
mkdir -p "$work/build/gcp"
digest="sha256:$(printf 'target' | sha256sum | cut -d' ' -f1)"
echo "$digest" >"$work/build/gcp/runner.digest"
# vm-create takes setups of the ci-test chain, so CHAIN=ci-test and its
# build folder; the other steps run with the default chain.
ln -s gcp "$work/build/gcp-ci-test"
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
vm_create() { run_rc env "${T3[@]}" CHAIN=ci-test NETWORK_ENTRY=public SETUP_FILE="$1" bash "$work/platform-gcp/deploy/deploy.sh" vm-create; }
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
ln -s azure "$work/build/azure-ci-test"
A1=(GROUP_NAME_1=signer-1b KEY_NAME_1=signer-1b-kek)
az_env=(ACR_NAME=signeracr VAULT=signer-vault LOCATION_1=northeurope)
# With the build overlay, its azure_network_defaults hook picks NETWORK
# when unset. Without it the group is the runner alone.
if [ -n "${SIGNER_BUILD_OVERLAY_DIR:-}" ] && [ -n "${NETWORK:-}" ]; then az_env+=(NETWORK="$NETWORK"); fi
env "${A1[@]}" "${az_env[@]}" bash "$work/platform-azure/deploy/deploy.sh" render 1 >/dev/null 2>&1 || bad "azure render of signer-1b failed"
t="$out_az/signer-1b/template.json"
if [ -f "$t" ] && [ "$(jq -r .parameters.name.defaultValue "$t")" = signer-1b ] &&
  jq -r .parameters.identityId.defaultValue "$t" | grep -q '/userAssignedIdentities/signer-id-1$' && [ ! -e "$out_az/signer-1" ]; then
  ok "azure render: group signer-1b in its own folder, identity signer-id-1"
else bad "azure render of signer-1b: $(ls "$out_az")"; fi
p="$(env "${A1[@]}" "${az_env[@]}" bash "$work/platform-azure/deploy/deploy.sh" plan 2>&1)"
grep -q 'key-create 1 *signer-1b-kek' <<<"$p" && grep -q 'group-deploy 1 *signer-1b in northeurope' <<<"$p" &&
  grep -q 'key-role 1 *signer-id-1 releases and reads signer-1b-kek' <<<"$p" && grep -q 'key-create 2 *signer-kek-2' <<<"$p" &&
  ok "azure plan: signer 1's second group and key, the others as before" || bad "azure plan: $p"
az_ok=("sealing_key_release.maa_endpoint=sharedneu.neu.attest.azure.net" "sealing_key_release.akv_endpoint=signer-vault.vault.azure.net")
make_setup setup-azure.conf "$work/az-1b.bin" "${az_ok[@]}" "sealing_key_release.kid=signer-1b-kek"
make_setup setup-azure.conf "$work/az-1.bin" "${az_ok[@]}" "sealing_key_release.kid=signer-kek-1"
deploy() { run_rc env "${A1[@]}" "${az_env[@]}" CHAIN=ci-test "SETUP_FILE_1=$1" bash "$work/platform-azure/deploy/deploy.sh" group-deploy 1; }
deploy "$work/az-1b.bin"
[ "$rc" = 3 ] && grep -q 'deploy confidential container group signer-1b in northeurope' <<<"$out" &&
  ok "azure group-deploy of signer-1b: its setup passes" || bad "azure group-deploy signer-1b: rc $rc $out"
deploy "$work/az-1.bin"
[ "$rc" != 0 ] && [ "$rc" != 3 ] && grep -q 'names key signer-kek-1, this deploy signer-1b-kek' <<<"$out" &&
  ok "azure group-deploy of signer-1b refuses the running group's key" || bad "azure group-deploy signer-1b, old key: rc $rc $out"
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
# IMAGE_TAG names no local image, so key-create stops at ensure_images
# before az confcom on any machine.
key_create() { run_rc env PATH="$work/bin:$PATH" CONFIRM=yes IMAGE_TAG=no-such-local-image "${A1[@]}" "${az_env[@]}" bash "$work/platform-azure/deploy/deploy.sh" key-create 1; }
fake_az exists
key_create
[ "$rc" != 0 ] && grep -q 'key signer-1b-kek exists in signer-vault' <<<"$out" && [ "$(wc -l <"$work/az.log")" = 1 ] &&
  ok "azure key-create refuses a key name that exists (no new version)" || bad "azure key-create, key exists: rc $rc $out"
fake_az denied
key_create
[ "$rc" != 0 ] && grep -q 'cannot tell whether key signer-1b-kek exists' <<<"$out" && [ "$(wc -l <"$work/az.log")" = 1 ] &&
  ok "azure key-create refuses when it cannot read whether the key exists" || bad "azure key-create, denied: rc $rc $out"
fake_az notfound
run_rc env PATH="$work/bin:$PATH" CONFIRM=yes KEY_IMMUTABLE=false IMAGE_TAG=no-such-local-image "${A1[@]}" "${az_env[@]}" bash "$work/platform-azure/deploy/deploy.sh" key-create 1
[ "$rc" != 0 ] && grep -q 'KEY_IMMUTABLE=false on prod chain mainnet' <<<"$out" && [ ! -s "$work/az.log" ] &&
  ok "azure key-create refuses a mutable key on mainnet" || bad "azure key-create, mutable on mainnet: rc $rc $out"
key_create
grep -q 'exists in' <<<"$out" && bad "azure key-create, not found: $out"
grep -q 'unexpected az call' <<<"$out" && bad "azure key-create went on to another az call before the policy step: $out"
[ "$rc" != 0 ] && ! grep -q 'cannot tell' <<<"$out" && ok "azure key-create goes past the check for a new name (stops later, at the local image)" ||
  bad "azure key-create, not found: rc $rc $out"

# key-create to the end: a fake docker has every image and a fake az
# writes a policy, so the create call runs and its arguments are logged.
mkdir -p "$work/bin-img"
printf '#!/usr/bin/env bash
case "$1 $2" in "image inspect" | tag*) exit 0 ;; esac
exit 99
' >"$work/bin-img/docker"
chmod +x "$work/bin-img/docker"
ln -s azure "$work/build/azure-hoodi"
ver="$(printf '0123456789abcdef%.0s' 1 2)"
fake_az_create() {
  cat >"$work/bin/az" <<EOF
#!/usr/bin/env bash
echo "az \$*" >>"$work/az.log"
case "\$1 \$2 \$3" in
  "keyvault key show") echo "ERROR: (KeyNotFound) not found" >&2; exit 3 ;;
  "keyvault key create") echo "https://signer-vault.vault.azure.net/keys/signer-1b-kek/$ver"; exit 0 ;;
  "confcom acipolicygen -a")
    jq --arg p "\$(printf policy | base64 -w0)" '.resources[0].properties.confidentialComputeProperties.ccePolicy = \$p' "\$4" >"\$4.new" && mv "\$4.new" "\$4"
    printf policy | sha256sum | cut -d' ' -f1; exit 0 ;;
esac
echo "unexpected az call" >&2
exit 99
EOF
  chmod +x "$work/bin/az"
  : >"$work/az.log"
}
key_create_all() { run_rc env PATH="$work/bin-img:$work/bin:$PATH" CONFIRM=yes "${A1[@]}" "${az_env[@]}" "$@" bash "$work/platform-azure/deploy/deploy.sh" key-create 1; }
fake_az_create
key_create_all CHAIN=ci-test
[ "$rc" = 0 ] && grep -q '^az keyvault key create .* --immutable true' "$work/az.log" &&
  ok "azure key-create makes the key immutable by default" || bad "azure key-create, default: rc $rc $out $(cat "$work/az.log")"
fake_az_create
key_create_all CHAIN=hoodi KEY_IMMUTABLE=false
[ "$rc" = 0 ] && grep -q '^az keyvault key create ' "$work/az.log" && ! grep -q -- '--immutable' "$work/az.log" &&
  ok "azure key-create makes a mutable key on hoodi with KEY_IMMUTABLE=false" || bad "azure key-create, mutable on hoodi: rc $rc $out $(cat "$work/az.log")"

# key-create records the version it made; group-deploy then takes only a
# setup that names that version, so a later version under the same name
# never replaces the key that sealed the signer's data.
[ "$(cat "$out_az/signer-1b/key.version" 2>/dev/null)" = "$ver" ] &&
  ok "azure key-create records the key version" || bad "azure key-create, key.version: $(cat "$out_az/signer-1b/key.version" 2>&1)"
deploy "$work/az-1b.bin"
[ "$rc" != 0 ] && [ "$rc" != 3 ] && grep -q "names key signer-1b-kek, not signer-1b-kek/$ver" <<<"$out" &&
  ok "azure group-deploy refuses a setup without the created key version" || bad "azure group-deploy, versionless kid: rc $rc $out"
make_setup setup-azure.conf "$work/az-1b-v.bin" "${az_ok[@]}" "sealing_key_release.kid=signer-1b-kek/$ver"
deploy "$work/az-1b-v.bin"
[ "$rc" = 3 ] && ok "azure group-deploy takes a setup with the created key version" || bad "azure group-deploy, versioned kid: rc $rc $out"

[ "$fail" = 0 ] || exit 1
echo "side-by-side-test: all cases as expected"
