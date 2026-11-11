#!/usr/bin/env bash
# The Azure template (platform-azure/deploy/aci-template.json) as deploy.sh
# renders and deploys it, without a build overlay:
#
#   render   the runner alone, on tcp:0.0.0.0:7100 with port 7100 declared
#            and the fixed NTS flags, without the clock flags the setup
#            gives (a template with one is refused). The three signers' containers are
#            the same. The subnet and the log workspace are optional
#            parameters that no container uses, so SUBNET_ID_N and the
#            workspace settings leave the rendered file unchanged.
#            NETWORK without an overlay part, a bad SUBNET_ID_N and half a
#            workspace setting are refused
#   policy   the CCE policy of the hoodi build's image (CHAIN=hoodi
#            build-image.sh): deploy.sh policy gives one hash for the three
#            signers, and acipolicygen gives that same hash on the template
#            and parameters file that group-deploy hands to ARM, with and
#            without a subnet and a log workspace, stdio on and off.
#            az confcom runs in a network namespace with only lo (unshare
#            -rn), so it reads the local image and nothing else. Skipped,
#            with a line saying so, when az confcom, Docker or unshare is
#            missing
#
# deploy.sh runs in a copy of the repo's scripts and cloud folders with a
# fake az, as in side-by-side-test.sh, so no cloud command runs. The policy
# part builds the hoodi image into build/azure-hoodi of this checkout.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=common.sh
. "$ROOT/scripts/common.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/scripts" "$work/platform-azure" "$work/governance" "$work/bin"
cp "$ROOT/scripts/common.sh" "$work/scripts/"
cp -r "$ROOT/platform-azure/deploy" "$work/platform-azure/"
cp -r "$ROOT/governance/chains" "$work/governance/"
fail=0
bad() { echo "FAIL $*"; fail=1; }
ok() { echo "ok   $*"; }
run_rc() { if out="$("$@" 2>&1)"; then rc=0; else rc=$?; fi; }

DEPLOY="$work/platform-azure/deploy/deploy.sh"
SUBNET=/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/signer
WS_ID=11111111-2222-3333-4444-555555555555
printf 'dGVzdCB3b3Jrc3BhY2Uga2V5\n' >"$work/ws.key"
# The settings of every run: the hoodi build, no overlay, no network entry.
base=(-u SIGNER_BUILD_OVERLAY_DIR -u NETWORK -u SUBNET_ID_1 -u SUBNET_ID_2 -u SUBNET_ID_3
  -u LOG_WORKSPACE_ID -u LOG_WORKSPACE_KEY_FILE CHAIN=hoodi ACR_NAME=signeracr VAULT=signer-vault
  IMAGE_TAG=template-test LOCATION_1=northeurope PATH="$work/bin:$PATH")
dep() { env "${base[@]}" "$@"; }
out_az="$work/build/azure-hoodi"
mkdir -p "$out_az"
echo "sha256:$(printf 'template-test' | sha256sum | cut -d' ' -f1)" >"$out_az/runner.digest"
tpl() { echo "$out_az/signer-$1/template.json"; }

# ---- render -----------------------------------------------------------------
for n in 1 2 3; do
  dep bash "$DEPLOY" render "$n" >/dev/null 2>"$work/render.log" || { cat "$work/render.log"; bad "render $n"; }
done
grep -q 'signer 3: clock protocol and bounds from the setup' "$work/render.log" && ok "render: states that the setup gives the clock protocol" ||
  bad "render: no clock protocol line: $(cat "$work/render.log")"
t="$(tpl 1)"
c='.resources[0].properties.containers'
if jq -e "$c | length == 1 and .[0].name == \"runner\"" "$t" >/dev/null; then ok "render: the runner alone"; else bad "render: containers $(jq -c "[${c}[].name]" "$t")"; fi
cmd="$(jq -c "${c}[0].properties.command" "$t")"
for w in '"-listen","tcp:0.0.0.0:7100"' '"-nts-wait","90s"' '"-setup","platform"'; do
  grep -qF -- "$w" <<<"$cmd" || bad "render: runner command lacks $w: $cmd"
done
for w in '"-clock-protocol' '"-nts-max-bound' '"-nts-max-sample-bound' '"-nts-terms-confirmed'; do
  ! grep -qF -- "$w" <<<"$cmd" || bad "render: runner command has ${w#\"}, which the setup gives: $cmd"
done
# A template that sets one of them is refused: the setup gives them.
tpl_src="$work/platform-azure/deploy/aci-template.json"
cp "$tpl_src" "$work/aci-template.orig"
for f in -clock-protocol -nts-max-bound -nts-max-sample-bound=1s -nts-terms-confirmed; do
  jq --arg f "$f" '.resources[0].properties.containers[0].properties.command |= (.[:-1] + [$f] + .[-1:])' \
    "$work/aci-template.orig" >"$tpl_src"
  run_rc dep bash "$DEPLOY" render 1
  [ "$rc" -ne 0 ] && grep -q 'which the setup gives' <<<"$out" && ok "render: refuses ${f%%=*} in the command" ||
    bad "render: ${f%%=*} in the command: rc $rc: $out"
done
cp "$work/aci-template.orig" "$tpl_src"
dep bash "$DEPLOY" render 1 >/dev/null 2>&1 || bad "render 1 again on the template as it is"
jq -e "${c}[0].properties.ports == [{port: 7100, protocol: \"TCP\"}]" "$t" >/dev/null &&
  ok "render: tcp:0.0.0.0:7100, port 7100 declared, the fixed NTS flags" || bad "render: runner ports $(jq -c "${c}[0].properties.ports" "$t")"
p='.resources[0].properties'
jq -e "($p.subnetIds | test(\"parameters\\\\('subnetId'\\\\)\")) and ($p.ipAddress | test(\"'Private'\") and test(\"7100\") and (test(\"Public\") | not))
  and ($p.diagnostics | test(\"parameters\\\\('logWorkspaceKey'\\\\)\"))" "$t" >/dev/null &&
  ok "render: subnet, private IP and diagnostics come from the parameters" || bad "render: group properties $(jq -c "$p | del(.containers)" "$t")"
for n in 2 3; do
  [ "$(jq -c "$c" "$t")" = "$(jq -c "$c" "$(tpl "$n")")" ] || bad "render: signer $n's containers differ from signer 1's"
done
ok "render: the three signers' containers are the same"
cp "$t" "$work/plain.json"
dep SUBNET_ID_1="$SUBNET" LOG_WORKSPACE_ID="$WS_ID" LOG_WORKSPACE_KEY_FILE="$work/ws.key" bash "$DEPLOY" render 1 >/dev/null 2>&1 || bad "render 1 with a subnet and a workspace"
cmp -s "$t" "$work/plain.json" && ok "render: a subnet and a workspace leave the rendered template unchanged" || bad "render: SUBNET_ID_1 or the workspace changed the template"
run_rc dep NETWORK=example bash "$DEPLOY" render 1
[ "$rc" != 0 ] && grep -q 'NETWORK=example: this tree has no Azure network entry part' <<<"$out" &&
  ok "render refuses NETWORK without an overlay part" || bad "render with NETWORK, no overlay: rc $rc $out"
run_rc dep SUBNET_ID_2=/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet bash "$DEPLOY" plan
[ "$rc" != 0 ] && grep -q 'SUBNET_ID_2=.*not a subnet resource ID' <<<"$out" && ok "a SUBNET_ID_N that is not a subnet is refused" || bad "bad SUBNET_ID_2: rc $rc $out"
run_rc dep LOG_WORKSPACE_ID="$WS_ID" SETUP_FILE_1=/nonexistent bash "$DEPLOY" group-deploy 1
[ "$rc" != 0 ] && [ "$rc" != 3 ] && grep -q 'set both LOG_WORKSPACE_ID and LOG_WORKSPACE_KEY_FILE' <<<"$out" &&
  ok "group-deploy refuses a workspace ID without its key" || bad "group-deploy, half a workspace: rc $rc $out"
p="$(dep SUBNET_ID_1="$SUBNET" bash "$DEPLOY" plan 2>&1)"
grep -q 'group-deploy 1 .*runner alone, private IP in subnet signer' <<<"$p" && grep -q 'group-deploy 2 .*runner alone, no IP address' <<<"$p" &&
  ok "plan: each group's subnet or no IP address" || bad "plan: $p"

# ---- policy -----------------------------------------------------------------
skip=""
az confcom --help >/dev/null 2>&1 || skip="no az confcom"
[ -n "$skip" ] || docker info >/dev/null 2>&1 || skip="no Docker"
[ -n "$skip" ] || unshare -rn true 2>/dev/null || skip="unshare -rn does not work here"
if [ -n "$skip" ]; then
  echo "skip the CCE policy checks: $skip"
else
  log "building the hoodi Azure image (log $LOGS/azure-template-image.log)"
  mkdir -p "$LOGS"
  env -u SIGNER_BUILD_OVERLAY_DIR CHAIN=hoodi IMAGE_TAG=template-test bash "$ROOT/platform-azure/deploy/build-image.sh" \
    >"$LOGS/azure-template-image.log" 2>&1 || { tail -n 30 "$LOGS/azure-template-image.log"; exit 1; }
  cp "$BUILD/azure-hoodi/runner.digest" "$out_az/runner.digest"
  echo "image $(cat "$out_az/runner.digest")"

  # Network namespace with only lo: the policy tool reads the local image.
  # shellcheck disable=SC2016 # the inner script's "$@", expanded by the inner bash
  offline() { unshare -rn bash -c 'ip -o link | grep -qv "lo:" && { echo "a link besides lo" >&2; exit 1; }; exec "$@"' _ "$@"; }
  # A fake az for group-deploy: the identity, then a copy of the template
  # and parameters file it would deploy, and the file's mode.
  cat >"$work/bin/az" <<EOF
#!/usr/bin/env bash
case "\$1 \$2 \$3" in
  "identity show "*) echo /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/signer-id-1; exit 0 ;;
  "deployment group create")
    while [ \$# -gt 0 ]; do
      case "\$1" in
        --template-file) cp "\$2" "$work/deployed-template.json"; shift ;;
        --parameters) f="\${2#@}"; cp "\$f" "$work/deployed-parameters.json"; stat -c %a "\$f" >"$work/deployed-mode"; shift ;;
      esac
      shift
    done
    exit 0 ;;
esac
exec "$(command -v az)" "\$@"
EOF
  chmod +x "$work/bin/az"
  # A setup of signer 1 for the hoodi chain, naming this deploy's names.
  arch="$(uname -m)"
  case "$arch" in amd64) arch=x86_64 ;; arm64) arch=aarch64 ;; esac
  TOOL="$work/build/$arch/bin/setup-tool"
  mkdir -p "$(dirname "$TOOL")"
  (cd "$ROOT/signer-admin" && CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "$TOOL" ./cmd/setup-tool)
  "$TOOL" chain-lines "$ROOT/governance/chains/hoodi.json" >"$work/chain.lines"
  awk -F' = ' 'NR == FNR { if (NF > 1) drop[$1] = 1; next } !($1 in drop)' \
    "$work/chain.lines" "$ROOT/governance/setuptext/testdata/setup-azure.conf" >"$work/setup.conf"
  cat "$work/chain.lines" >>"$work/setup.conf"
  sed -i -e 's|^sealing_key_release.maa_endpoint = .*|sealing_key_release.maa_endpoint = sharedneu.neu.attest.azure.net|' \
    -e 's|^sealing_key_release.akv_endpoint = .*|sealing_key_release.akv_endpoint = signer-vault.vault.azure.net|' \
    -e 's|^sealing_key_release.kid = .*|sealing_key_release.kid = signer-kek-1|' "$work/setup.conf"
  "$TOOL" encode "$work/setup.conf" "$work/signer-1.bin" >/dev/null

  for stdio in enable disable; do
    run_rc offline env "${base[@]}" STDIO="$stdio" bash "$DEPLOY" policy
    h="$(sed -n 's/^one policy for every signer: \([0-9a-f]\{64\}\) .*/\1/p' <<<"$out")"
    if [ "$rc" = 0 ] && [ -n "$h" ]; then ok "policy, stdio $stdio: one policy for the three signers: $h"; else bad "deploy.sh policy, stdio $stdio: rc $rc $out"; continue; fi
    for v in none subnet workspace both; do
      env=()
      case "$v" in
        subnet) env=(SUBNET_ID_1="$SUBNET") ;;
        workspace) env=(LOG_WORKSPACE_ID="$WS_ID" LOG_WORKSPACE_KEY_FILE="$work/ws.key") ;;
        both) env=(SUBNET_ID_1="$SUBNET" LOG_WORKSPACE_ID="$WS_ID" LOG_WORKSPACE_KEY_FILE="$work/ws.key") ;;
      esac
      rm -f "$work"/deployed-*
      run_rc offline env "${base[@]}" STDIO="$stdio" CONFIRM=yes EXPECT_POLICY_SHA256="$h" SETUP_FILE_1="$work/signer-1.bin" \
        ${env[@]+"${env[@]}"} bash "$DEPLOY" group-deploy 1
      if [ "$rc" != 0 ] || [ ! -s "$work/deployed-parameters.json" ]; then bad "group-deploy 1, $v, stdio $stdio: rc $rc $out"; continue; fi
      [ "$(cat "$work/deployed-mode")" = 600 ] || bad "group-deploy 1, $v: parameters file mode $(cat "$work/deployed-mode")"
      prm="$(jq -c '.parameters | del(.signerSetup, .identityId) | with_entries(.value |= .value)' "$work/deployed-parameters.json")"
      case "$v" in
        none) want='{}' ;;
        subnet) want="{\"subnetId\":\"$SUBNET\"}" ;;
        workspace) want="{\"logWorkspaceId\":\"$WS_ID\",\"logWorkspaceKey\":\"dGVzdCB3b3Jrc3BhY2Uga2V5\"}" ;;
        both) want="{\"subnetId\":\"$SUBNET\",\"logWorkspaceId\":\"$WS_ID\",\"logWorkspaceKey\":\"dGVzdCB3b3Jrc3BhY2Uga2V5\"}" ;;
      esac
      [ "$prm" = "$want" ] || bad "group-deploy 1, $v: optional parameters $prm, want $want"
      # The deployed template with its policy taken out, then the policy
      # again from that template and the deployed parameters. signerSetup
      # stays out of the file: with a value, az confcom would pin that one
      # setup instead of the wildcard rule (README, "CCE policy and secrets").
      jq '.resources[0].properties.confidentialComputeProperties.ccePolicy = ""' "$work/deployed-template.json" >"$work/re.json"
      jq 'del(.parameters.signerSetup)' "$work/deployed-parameters.json" >"$work/re-parameters.json"
      if got="$(offline az confcom acipolicygen -a "$work/re.json" -p "$work/re-parameters.json" -y --omit-id "--$stdio-stdio" </dev/null 2>"$work/confcom.log")" &&
        [ "$got" = "$h" ]; then
        ok "policy, stdio $stdio, $v: the deployed template and parameters give $h"
      else
        tail -n 5 "$work/confcom.log"
        bad "policy, stdio $stdio, $v: '$got', want $h"
      fi
    done
  done
fi

[ "$fail" = 0 ] || exit 1
echo "azure-template-test: all cases as expected"
