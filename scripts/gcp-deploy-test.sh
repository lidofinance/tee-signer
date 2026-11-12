#!/usr/bin/env bash
# The GCP deploy script's network and switch settings, checked without GCP:
#
#   public   the default plan: an external address, TCP 7100 from
#            OPERATOR_IP, the egress rules
#   private  NETWORK_ENTRY=private: no address step, vm-create with
#            --no-address and PRIVATE_IP, firewall-create from
#            ENTRY_SOURCE_RANGES and ENTRY_SOURCE_TAGS. With a second
#            signer's names and SUBNET and NET_TAG set, the plan makes its
#            subnet and rules and the teardown list deletes them
#   switch   PREV_IMAGE_DIGEST: the WIF condition takes both digests;
#            the VM metadata keeps tee-restart-policy=OnFailure
#   hardware intel-tdx by default on a prod chain, amd-sev on a non-prod
#            chain; the provider-update gate names the hwmodel
#   refused  entry sources with the public entry, a private firewall rule
#            without sources, an address for a private VM, bad names and
#            addresses, a subnet-create on the running signer's subnet, a
#            bad previous digest, wif-create and provider-update without
#            a valid runner.digest, amd-sev on mainnet, a VM self-link
#            over 127 bytes, a malformed PROJECT_ID
#   domain   a domain-scoped PROJECT_ID: service account and registry path
#
# deploy.sh runs in a copy of the repo's scripts and cloud folders with a
# fake gcloud that records its arguments, as in side-by-side-test.sh, so no
# cloud command runs.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/scripts" "$work/platform-gcp" "$work/governance" "$work/bin"
cp "$ROOT/scripts/common.sh" "$work/scripts/"
cp -r "$ROOT/platform-gcp/deploy" "$work/platform-gcp/"
cp -r "$ROOT/governance/chains" "$work/governance/"
fail=0
bad() { echo "FAIL $*"; fail=1; }
ok() { echo "ok   $*"; }
run_rc() { if out="$("$@" 2>&1)"; then rc=0; else rc=$?; fi; }
has() { grep -q -F -- "$1" <<<"$2"; }

# A fake gcloud: each call's arguments, one per line, then a blank line.
cat >"$work/bin/gcloud" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$@" "" >>"$work/gcloud.calls"
EOF
chmod +x "$work/bin/gcloud"

arch="$(uname -m)"
case "$arch" in amd64) arch=x86_64 ;; arm64) arch=aarch64 ;; esac
TOOL="$work/build/$arch/bin/setup-tool"
mkdir -p "$(dirname "$TOOL")"
(cd "$ROOT/signer-admin" && CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "$TOOL" ./cmd/setup-tool)
"$TOOL" chain-lines "$ROOT/governance/chains/chain.ci-test.json" >"$work/chain.lines"

mkdir -p "$work/build/gcp"
digest="sha256:$(printf 'gcp-deploy-test' | sha256sum | cut -d' ' -f1)"
echo "$digest" >"$work/build/gcp/runner.digest"
ln -s gcp "$work/build/gcp-ci-test"
DEPLOY="$work/platform-gcp/deploy/deploy.sh"
base=(-u SIGNER_BUILD_OVERLAY_DIR -u NETWORK_ENTRY -u PRIVATE_IP -u ENTRY_SOURCE_RANGES -u ENTRY_SOURCE_TAGS
  -u SUBNET -u SUBNET_RANGE -u NET_TAG -u FW_RULE -u FW_EGRESS_ALLOW -u FW_EGRESS_DENY -u CONFIRM
  -u PREV_IMAGE_DIGEST -u HARDWARE
  MARK_STORE=gcs:bucket=signer-marks-2 PATH="$work/bin:$PATH")
dep() { env "${base[@]}" "$@"; }
# A private second signer with a subnet, tag and rules of its own.
P2=(NETWORK_ENTRY=private PRIVATE_IP=10.10.1.10 ENTRY_SOURCE_TAGS=entry-gw SUBNET=signer-private SUBNET_RANGE=10.10.1.0/24
  NET_TAG=signer-private FW_RULE=signer-private-in-7100 FW_EGRESS_ALLOW=signer-private-out FW_EGRESS_DENY=signer-private-out-deny
  VM=signer-node-2 KMS_KEY=sealing-2 WIF_POOL=signer-pool-2 WIF_PROVIDER=signer-attestation-2)

# ---- public -----------------------------------------------------------------
p="$(dep bash "$DEPLOY" plan 2>&1)"
miss=""
for w in "gcloud compute addresses create signer-node-1-ip" "--address=signer-node-1-ip" "--subnet=signer-subnet" \
  "--source-ranges=<OPERATOR_IP>/32\" --target-tags=signer-node" \
  "firewall-rules create signer-egress-allow --network=signer-net --direction=EGRESS --priority=1000 --allow=tcp:80,tcp:443,tcp:4460,udp:123,udp:4123 --destination-ranges=0.0.0.0/0 --target-tags=signer-node" \
  "firewall-rules create signer-egress-deny --network=signer-net --direction=EGRESS --priority=65000 --action=DENY --rules=all --destination-ranges=0.0.0.0/0 --target-tags=signer-node" \
  "firewall-rules delete signer-egress-allow" "addresses delete signer-node-1-ip"; do
  has "$w" "$p" || miss+=" [$w]"
done
[ -z "$miss" ] && ok "public plan: the address, TCP 7100 from OPERATOR_IP, the egress rules" || bad "public plan lacks$miss"
has "--no-address" "$p" && bad "public plan has --no-address"
has "subnet-create" "$p" && bad "public plan has subnet-create"

# ---- private ----------------------------------------------------------------
p="$(dep NETWORK_ENTRY=private ENTRY_SOURCE_RANGES=10.20.0.0/24 bash "$DEPLOY" plan 2>&1)"
has "address-reserve" "$p" && bad "private plan has address-reserve"
has "--no-address" "$p" && has "--source-ranges=10.20.0.0/24 --target-tags=signer-node" "$p" && has "egress-create" "$p" &&
  ! has "addresses delete" "$p" && ok "private plan: no address, TCP 7100 from the entry's range, the egress rules" ||
  bad "private plan: $(grep -E 'address|source-ranges' <<<"$p")"

p="$(dep "${P2[@]}" bash "$DEPLOY" plan 2>&1)"
miss=""
for w in "1. step subnet-create" "subnets create signer-private --network=signer-net --region=europe-west4 --range=10.10.1.0/24" \
  "firewall-rules create signer-private-in-7100 --network=signer-net --direction=INGRESS --priority=1000 --allow=tcp:7100 --source-tags=entry-gw --target-tags=signer-private" \
  "firewall-rules create signer-private-out " "firewall-rules create signer-private-out-deny " \
  "--subnet=signer-private --private-network-ip=10.10.1.10 --no-address --tags=signer-private" \
  "firewall-rules delete signer-private-in-7100" "firewall-rules delete signer-private-out-deny" "subnets delete signer-private"; do
  has "$w" "$p" || miss+=" [$w]"
done
[ -z "$miss" ] && ok "private second signer: its subnet, rules and VM, and their deletes" || bad "private second signer plan lacks$miss"
for w in "addresses create" "addresses delete" "--address=" "networks create" "keyrings create" "sa-create" "signer-allow-7100" "subnets delete signer-subnet"; do
  has "$w" "$p" && bad "private second signer plan has '$w'"
done
ok "private second signer: no address, nothing of the running signer's"

: >"$work/gcloud.calls"
make_setup() { # make_setup OUT [KEY=VALUE...]
  local out="$1" kv
  shift
  awk -F' = ' 'NR == FNR { if (NF > 1) drop[$1] = 1; next } !($1 in drop)' \
    "$work/chain.lines" "$ROOT/governance/setuptext/testdata/setup-gcp.conf" >"$work/setup.conf"
  cat "$work/chain.lines" >>"$work/setup.conf"
  # The GCP sample lists no gcp image; setup-tool refuses a setup without one.
  echo "allowed_image_measurements = gcp 0x$(printf '9%.0s' {1..64})" >>"$work/setup.conf"
  for kv in "$@"; do sed -i "s|^${kv%%=*} = .*|${kv%%=*} = ${kv#*=}|" "$work/setup.conf"; done
  "$TOOL" encode "$work/setup.conf" "$out" >/dev/null
}
names="$(env "${base[@]}" "${P2[@]}" bash -c '. "$1/platform-gcp/deploy/common.sh" && printf "%s\n%s\n" "$WIF_PROVIDER_RESOURCE" "$KMS_KEY_RESOURCE"' _ "$work")"
make_setup "$work/gcp-2.bin" "sealing_key_release.wif_provider=$(sed -n 1p <<<"$names")" "sealing_key_release.kms_key=$(sed -n 2p <<<"$names")" \
  "slashing_log_store.bucket=signer-marks-2"
run_rc dep "${P2[@]}" CHAIN=ci-test CONFIRM=yes SETUP_FILE="$work/gcp-2.bin" bash "$DEPLOY" vm-create
call="$(cat "$work/gcloud.calls")"
if [ "$rc" = 0 ] && has "--no-address" "$call" && has "--private-network-ip=10.10.1.10" "$call" && has "--subnet=signer-private" "$call" &&
  ! grep -q -- '^--address=' <<<"$call"; then
  ok "private vm-create: gcloud gets --no-address, the subnet and PRIVATE_IP"
else
  bad "private vm-create: rc $rc $out $call"
fi
: >"$work/gcloud.calls"
run_rc dep "${P2[@]}" ENTRY_SOURCE_RANGES=10.20.0.0/24,10.30.0.0/24 CONFIRM=yes bash "$DEPLOY" firewall-create
call="$(cat "$work/gcloud.calls")"
[ "$rc" = 0 ] && has "--source-ranges=10.20.0.0/24,10.30.0.0/24" "$call" && has "--source-tags=entry-gw" "$call" &&
  ok "private firewall-create: the entry's ranges and tags" || bad "private firewall-create: rc $rc $out $call"

# ---- previous digest and restart policy -------------------------------------
prev="sha256:$(printf 'previous' | sha256sum | cut -d' ' -f1)"
p="$(dep PREV_IMAGE_DIGEST="$prev" bash "$DEPLOY" plan 2>&1)"
both="assertion.submods.container.image_digest in ['$prev', '$digest']"
[ "$(grep -c -F -- "$both" <<<"$p")" = 2 ] && ! has "image_digest == " "$p" &&
  ok "PREV_IMAGE_DIGEST: wif-create and provider-update take both digests, previous first" || bad "PREV_IMAGE_DIGEST plan: $(grep -o 'image_digest[^&]*' <<<"$p")"
p="$(dep PREV_IMAGE_DIGEST="$digest" bash "$DEPLOY" plan 2>&1)"
has "image_digest == '$digest'" "$p" && ! has "image_digest in" "$p" &&
  ok "PREV_IMAGE_DIGEST equal to runner.digest: one digest" || bad "PREV_IMAGE_DIGEST = digest: $(grep -o 'image_digest[^&]*' <<<"$p")"
: >"$work/gcloud.calls"
run_rc dep PREV_IMAGE_DIGEST="$prev" CONFIRM=yes bash "$DEPLOY" provider-update
has "--attribute-condition=assertion.swname == 'CONFIDENTIAL_SPACE'" "$(cat "$work/gcloud.calls")" && has "$both" "$(cat "$work/gcloud.calls")" &&
  ok "provider-update with PREV_IMAGE_DIGEST: gcloud gets both digests" || bad "provider-update: rc $rc $out $(cat "$work/gcloud.calls")"
p="$(dep bash "$DEPLOY" plan 2>&1)"
has "~tee-restart-policy=OnFailure~" "$p" && ok "restart policy OnFailure" || bad "restart policy: $(grep -o 'tee-restart-policy=[A-Za-z]*' <<<"$p")"

# ---- hardware ---------------------------------------------------------------
p="$(dep CHAIN=mainnet bash "$DEPLOY" plan 2>&1)"
has "assertion.hwmodel == 'GCP_INTEL_TDX'" "$p" && has "--confidential-compute-type=TDX" "$p" && ! has "GCP_AMD_SEV" "$p" &&
  ok "HARDWARE unset: intel-tdx, the WIF condition pins GCP_INTEL_TDX" || bad "HARDWARE unset: $(grep -E 'Hardware|hwmodel' <<<"$p")"
p="$(dep HARDWARE=amd-sev CHAIN=ci-test bash "$DEPLOY" plan 2>&1)"
has "assertion.hwmodel == 'GCP_AMD_SEV'" "$p" && ok "HARDWARE=amd-sev on a non-prod chain" || bad "amd-sev on ci-test: $(grep -E 'Hardware|hwmodel|gcp:' <<<"$p")"
# A non-prod run without HARDWARE keeps amd-sev, so it does not move the WIF
# condition of a running AMD signer to GCP_INTEL_TDX.
p="$(dep CHAIN=ci-test bash "$DEPLOY" plan 2>&1)"
has "assertion.hwmodel == 'GCP_AMD_SEV'" "$p" && ! has "GCP_INTEL_TDX'" "$p" &&
  ok "HARDWARE unset on a non-prod chain: amd-sev" || bad "HARDWARE unset on ci-test: $(grep -E 'Hardware|hwmodel' <<<"$p")"
p="$(dep HARDWARE=intel-tdx CHAIN=ci-test bash "$DEPLOY" plan 2>&1)"
has "assertion.hwmodel == 'GCP_INTEL_TDX'" "$p" && ok "HARDWARE=intel-tdx on a non-prod chain" || bad "intel-tdx on ci-test: $(grep -E 'Hardware|hwmodel' <<<"$p")"
: >"$work/gcloud.calls"
run_rc dep CHAIN=ci-test bash "$DEPLOY" provider-update </dev/null
[ "$rc" = 3 ] && has "on hardware GCP_AMD_SEV" "$out" && [ ! -s "$work/gcloud.calls" ] && ok "provider-update gate names the hwmodel" || bad "provider-update gate: rc $rc $out"
: >"$work/gcloud.calls"

# ---- domain-scoped project ----------------------------------------------------
# rv-b9e.3: PROJECT_ID=example.com:signer names the KMS key by that ID, the
# service account as signer.example.com and the registry path as
# example.com/signer.
p="$(dep PROJECT_ID=example.com:signer bash "$DEPLOY" plan 2>&1)"
miss=""
for w in "--project=example.com:signer" "signer-workload@signer.example.com.iam.gserviceaccount.com"   "europe-west4-docker.pkg.dev/example.com/signer/signer/runner"; do
  has "$w" "$p" || miss+=" [$w]"
done
[ -z "$miss" ] && ok "domain-scoped project: the service account and registry path" || bad "domain-scoped plan lacks$miss"

# ---- refused ----------------------------------------------------------------
refused() { # refused WHAT PATTERN ENV... -- CMD
  local what="$1" pat="$2" envs=()
  shift 2
  while [ "$1" != -- ]; do envs+=("$1"); shift; done
  shift
  : >"$work/gcloud.calls"
  run_rc dep "${envs[@]}" CONFIRM=yes bash "$DEPLOY" "$@"
  if [ "$rc" != 0 ] && [ "$rc" != 3 ] && grep -q -- "$pat" <<<"$out" && [ ! -s "$work/gcloud.calls" ]; then
    ok "refused: $what"
  else
    bad "$what: rc $rc $out"
  fi
}
refused "entry sources with the public entry" "for NETWORK_ENTRY=private" ENTRY_SOURCE_TAGS=entry-gw -- plan
refused "a private firewall rule without sources" "set ENTRY_SOURCE_RANGES or ENTRY_SOURCE_TAGS" NETWORK_ENTRY=private -- firewall-create
refused "an address for a private VM" "gets no external address" NETWORK_ENTRY=private -- address-reserve
refused "a bad PRIVATE_IP" "PRIVATE_IP=10.10.1 is not" PRIVATE_IP=10.10.1 -- plan
refused "a bad ENTRY_SOURCE_RANGES" "is not a comma-separated list of IPv4 CIDR" NETWORK_ENTRY=private ENTRY_SOURCE_RANGES=10.0.0.0 -- plan
refused "a bad NET_TAG" "NET_TAG=Signer_Tag is not" NET_TAG=Signer_Tag -- plan
refused "an unknown entry without an overlay" "NETWORK_ENTRY must be public or private" NETWORK_ENTRY=example -- plan
refused "subnet-create on the running signer's subnet" "is the running signer's" VM=signer-node-2 -- subnet-create
refused "a bad PREV_IMAGE_DIGEST" "PREV_IMAGE_DIGEST=sha256:abc is not" PREV_IMAGE_DIGEST=sha256:abc -- provider-update
refused "amd-sev on mainnet" "HARDWARE=amd-sev is for a non-prod CHAIN" HARDWARE=amd-sev CHAIN=mainnet -- plan
refused "amd-sev on mainnet, wif-create" "HARDWARE=amd-sev is for a non-prod CHAIN" HARDWARE=amd-sev CHAIN=mainnet -- wif-create
refused "a malformed domain-scoped PROJECT_ID" "is not a project ID" PROJECT_ID=Example.com:signer -- plan
refused "a PROJECT_ID with two domains" "is not a project ID" PROJECT_ID=x.org:example.com:signer -- plan
refused "a VM self-link over 127 bytes" "the WIF subject limit" PROJECT_ID=example-validator-staking-prod VM=signer-node-replacement-production -- plan
refused "an unknown HARDWARE" "HARDWARE must be intel-tdx or amd-sev" HARDWARE=amd-sev-snp CHAIN=ci-test -- plan

# A missing or malformed runner.digest stops wif-create and provider-update
# before any gcloud call, so no condition with an empty digest goes out.
mv "$work/build/gcp/runner.digest" "$work/runner.digest.keep"
refused "provider-update without runner.digest" "runner.digest: run" -- provider-update
refused "wif-create without runner.digest" "runner.digest: run" -- wif-create
echo sha256:abc >"$work/build/gcp/runner.digest"
refused "provider-update with a malformed runner.digest" "does not hold a sha256 digest" -- provider-update
refused "wif-create with a malformed runner.digest" "does not hold a sha256 digest" -- wif-create
mv "$work/runner.digest.keep" "$work/build/gcp/runner.digest"

[ "$fail" = 0 ] || exit 1
echo "gcp-deploy-test: all cases as expected"
