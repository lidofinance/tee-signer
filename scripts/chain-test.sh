#!/usr/bin/env bash
# Offline tests of governance/chains/chain.sh and platform-azure/deploy/chain-from-devnet.sh:
# the committed chain files rebuild to the same bytes, identify and verify tell the chains apart, check-source and
# check-beacon pass on matching data and fail on each kind of difference. The
# upstream config and the beacon answers are made here from the source file,
# in a temporary folder, so the test needs no network.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

CHAIN="$ROOT/governance/chains/chain.sh"
SRC="$ROOT/governance/chains/hoodi.source.json"
HOODI="$ROOT/governance/chains/hoodi.json"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
pass=0
fail=0

ok() { pass=$((pass + 1)); echo "PASS  $*"; }
bad() { fail=$((fail + 1)); echo "FAIL  $*"; }
# expect_ok NAME CMD...: the command exits 0. expect_fail NAME CMD...: it does not.
expect_ok() { local n="$1"; shift; if "$@" >"$T/out" 2>&1; then ok "$n"; else bad "$n"; sed 's/^/      /' "$T/out"; fi; }
expect_fail() { local n="$1"; shift; if "$@" >"$T/out" 2>&1; then bad "$n (exit 0)"; sed 's/^/      /' "$T/out"; else ok "$n"; fi; }

# ---- build ----
bash "$CHAIN" build hoodi "$T/hoodi.json" 2>/dev/null
if cmp -s "$T/hoodi.json" "$HOODI"; then ok "hoodi.json rebuilds to the committed bytes"; else bad "hoodi.json differs from a fresh build"; fi
FEE_RECIPIENT=0x1111111111111111111111111111111111111111 bash "$CHAIN" build hoodi "$T/hoodi-fee.json" 2>/dev/null
if [ "$(jq -r '.fee_recipients[0]' "$T/hoodi-fee.json")" = 0x1111111111111111111111111111111111111111 ] &&
  bash "$CHAIN" verify hoodi "$T/hoodi-fee.json" 2>/dev/null; then
  ok "another fee recipient: another file, still chain hoodi"
else
  bad "FEE_RECIPIENT override"
fi
EXIT_ALLOWLIST=1234567 bash "$CHAIN" build hoodi "$T/hoodi-exit.json" 2>/dev/null
if [ "$(jq -c .exit_allowlist "$T/hoodi-exit.json")" = "[1234567]" ] && bash "$CHAIN" verify hoodi "$T/hoodi-exit.json" 2>/dev/null; then
  ok "an exit allowlist: another file, still chain hoodi"
else
  bad "EXIT_ALLOWLIST override"
fi
[ "$(jq -c '[.forks[] | .epoch]' "$HOODI")" = "[0,0,0,0,2048,50688,132352]" ] && ok "fork epochs Altair to Gloas" || bad "fork epochs: $(jq -c '[.forks[] | .epoch]' "$HOODI")"
[ "$(jq -c .gloas_fork_epoch "$HOODI")" = 132352 ] && ok "gloas_fork_epoch 132352" || bad "gloas_fork_epoch: $(jq -c .gloas_fork_epoch "$HOODI")"

# ---- identify and verify ----
[ "$(bash "$CHAIN" identify "$HOODI")" = hoodi ] && ok "identify hoodi.json" || bad "identify hoodi.json"
[ "$(bash "$CHAIN" identify "$ROOT/governance/chains/chain.testnet.json")" = testnet ] && ok "identify chain.testnet.json" || bad "identify chain.testnet.json"
jq '.genesis_fork_version = "0x10000038" | .genesis_validators_root = "0x" + ("ab" * 32) | .forks = [{epoch: 0, version: "0x20000038"}] | .seconds_per_slot = 6 | .genesis_time = 1792157697 | del(.gloas_fork_epoch)' \
  "$HOODI" >"$T/devnet.json"
[ "$(bash "$CHAIN" identify "$T/devnet.json")" = devnet ] && ok "identify a Kurtosis devnet file" || bad "identify devnet"
expect_ok "verify hoodi hoodi.json" bash "$CHAIN" verify hoodi "$HOODI"
expect_fail "verify hoodi refuses the devnet file" bash "$CHAIN" verify hoodi "$T/devnet.json"
expect_fail "verify devnet refuses hoodi.json" bash "$CHAIN" verify devnet "$HOODI"
expect_fail "verify hoodi refuses chain.testnet.json" bash "$CHAIN" verify hoodi "$ROOT/governance/chains/chain.testnet.json"
for mut in '.genesis_validators_root = "0x" + ("00" * 32)' '.genesis_time += 1' '.forks[6].epoch = 132353' \
  '.forks |= .[:6]' '.seconds_per_slot = 6' '.voluntary_exit_fork_version = "0x50000910"'   'del(.gloas_fork_epoch)' '.gloas_fork_epoch = 132353' '.gloas_fork_epoch = 50688'; do
  jq "$mut" "$HOODI" >"$T/mut.json"
  expect_fail "identify refuses hoodi.json with $mut" bash "$CHAIN" identify "$T/mut.json"
done
jq '.genesis_fork_version = "0x00000000"' "$HOODI" >"$T/mainnet.json"
expect_fail "identify refuses a mainnet genesis fork version" bash "$CHAIN" identify "$T/mainnet.json"
jq '.genesis_fork_version = "0x90000069"' "$HOODI" >"$T/sepolia.json"
expect_fail "identify refuses Sepolia (not pinned)" bash "$CHAIN" identify "$T/sepolia.json"
jq '.genesis_time += 1' "$ROOT/governance/chains/chain.testnet.json" >"$T/testnet-mut.json"
expect_fail "identify refuses a changed test chain" bash "$CHAIN" identify "$T/testnet-mut.json"
echo '{"x": 1}' >"$T/notchain.json"
expect_fail "identify refuses a file that is not a chain config" bash "$CHAIN" identify "$T/notchain.json"

# ---- check-source: config.yaml and genesis_validators_root.txt made from the source file ----
make_yaml() { # make_yaml OUT [jq filter on .config]
  {
    echo "# Extends the mainnet preset"
    jq -r "(.config | ${2:-.}) | to_entries[] | \"\(.key): \(.value)\"" "$SRC"
    echo "SECONDS_PER_ETH1_BLOCK: 12"
    echo "BLOB_SCHEDULE:"
    echo "  - EPOCH: 52480"
    echo "    MAX_BLOBS_PER_BLOCK: 15"
  } >"$1"
}
jq -r .genesis_validators_root "$SRC" >"$T/gvr.txt"
make_yaml "$T/config.yaml"
expect_ok "check-source passes on matching files" bash "$CHAIN" check-source hoodi "$T/config.yaml" "$T/gvr.txt"
make_yaml "$T/c1.yaml" '.GLOAS_FORK_EPOCH = "132353"'
expect_fail "check-source: a moved fork epoch" bash "$CHAIN" check-source hoodi "$T/c1.yaml" "$T/gvr.txt"
make_yaml "$T/c2.yaml" '. + {HEZE_FORK_VERSION: "0x90000910", HEZE_FORK_EPOCH: "200000"}'
expect_fail "check-source: a new fork scheduled upstream" bash "$CHAIN" check-source hoodi "$T/c2.yaml" "$T/gvr.txt"
make_yaml "$T/c3.yaml" '. + {HEZE_FORK_VERSION: "0x90000910", HEZE_FORK_EPOCH: "18446744073709551615"}'
expect_ok "check-source: a fork at the far future epoch is left out" bash "$CHAIN" check-source hoodi "$T/c3.yaml" "$T/gvr.txt"
make_yaml "$T/c4.yaml" '.DEPOSIT_CONTRACT_ADDRESS = "0x4242424242424242424242424242424242424242"'
expect_fail "check-source: another deposit contract" bash "$CHAIN" check-source hoodi "$T/c4.yaml" "$T/gvr.txt"
make_yaml "$T/c5.yaml" '.GENESIS_DELAY = "300"'
expect_fail "check-source: another genesis time" bash "$CHAIN" check-source hoodi "$T/c5.yaml" "$T/gvr.txt"
make_yaml "$T/c6.yaml" '.PRESET_BASE = "minimal"'
expect_fail "check-source: the minimal preset" bash "$CHAIN" check-source hoodi "$T/c6.yaml" "$T/gvr.txt"
echo "0x$(printf '00%.0s' {1..32})" >"$T/gvr-bad.txt"
expect_fail "check-source: another genesis validators root" bash "$CHAIN" check-source hoodi "$T/config.yaml" "$T/gvr-bad.txt"

# ---- check-beacon: a beacon API made of files, read through file:// ----
make_beacon() { # make_beacon DIR [jq filter on the fork schedule]
  local d="$1/eth/v1"
  mkdir -p "$d/beacon" "$d/config"
  jq '{data: {genesis_time: (.genesis_time | tostring), genesis_validators_root, genesis_fork_version: .config.GENESIS_FORK_VERSION}}' "$SRC" >"$d/beacon/genesis"
  jq '{data: (.config + {SLOTS_PER_EPOCH: (.slots_per_epoch | tostring)})}' "$SRC" >"$d/config/spec"
  jq "{data: ([{previous_version: .config.GENESIS_FORK_VERSION, current_version: .config.GENESIS_FORK_VERSION, epoch: \"0\"}]
    + [.config as \$c | .forks[] | {previous_version: \"x\", current_version: \$c[. + \"_FORK_VERSION\"], epoch: \$c[. + \"_FORK_EPOCH\"]}]) | ${2:-.}}" \
    "$SRC" >"$d/config/fork_schedule"
}
make_beacon "$T/bn"
expect_ok "check-beacon passes on a matching node" bash "$CHAIN" check-beacon hoodi "file://$T/bn"
make_beacon "$T/bn-nogloas" '.[:-1]'
expect_fail "check-beacon: a node that does not know Gloas" bash "$CHAIN" check-beacon hoodi "file://$T/bn-nogloas"
make_beacon "$T/bn-glep"
jq '.data.GLOAS_FORK_EPOCH = "18446744073709551615"' "$T/bn-glep/eth/v1/config/spec" >"$T/s" && mv "$T/s" "$T/bn-glep/eth/v1/config/spec"
expect_fail "check-beacon: a node whose spec has Gloas unscheduled" bash "$CHAIN" check-beacon hoodi "file://$T/bn-glep"
make_beacon "$T/bn-gvr"
jq '.data.genesis_validators_root = "0x" + ("11" * 32)' "$T/bn-gvr/eth/v1/beacon/genesis" >"$T/g" && mv "$T/g" "$T/bn-gvr/eth/v1/beacon/genesis"
expect_fail "check-beacon: a node of another chain" bash "$CHAIN" check-beacon hoodi "file://$T/bn-gvr"
make_beacon "$T/bn-dep"
jq '.data.DEPOSIT_CHAIN_ID = "3151908"' "$T/bn-dep/eth/v1/config/spec" >"$T/s" && mv "$T/s" "$T/bn-dep/eth/v1/config/spec"
expect_fail "check-beacon: another deposit chain id" bash "$CHAIN" check-beacon hoodi "file://$T/bn-dep"
# A URL with credentials: refused (nothing listens on port 9), and neither the
# user nor the password shows in the output.
if bash "$CHAIN" check-beacon hoodi "http://hoodiuser:s3cr3tpass@127.0.0.1:9/x" >"$T/out" 2>&1; then
  bad "check-beacon on a closed port exited 0"
elif grep -qE 'hoodiuser|s3cr3tpass' "$T/out"; then
  bad "check-beacon printed the credentials of the URL"
else
  ok "check-beacon keeps the credentials of the URL out of its output ($(tail -n 1 "$T/out"))"
fi

make_beacon "$T/bn-ms"
jq '.data |= del(.SECONDS_PER_SLOT)' "$T/bn-ms/eth/v1/config/spec" >"$T/s" && mv "$T/s" "$T/bn-ms/eth/v1/config/spec"
expect_ok "check-beacon: a spec with SLOT_DURATION_MS only" bash "$CHAIN" check-beacon hoodi "file://$T/bn-ms"
jq '.data.SLOT_DURATION_MS = "6000"' "$T/bn-ms/eth/v1/config/spec" >"$T/s" && mv "$T/s" "$T/bn-ms/eth/v1/config/spec"
expect_fail "check-beacon: SLOT_DURATION_MS of another slot time" bash "$CHAIN" check-beacon hoodi "file://$T/bn-ms"

# ---- build from a config with SLOT_DURATION_MS only (a copy of chain.sh next to the changed source) ----
mkdir -p "$T/cl/chains"
cp "$CHAIN" "$T/cl/chains/chain.sh"
jq '.config |= del(.SECONDS_PER_SLOT)' "$SRC" >"$T/cl/chains/hoodi.source.json"
if bash "$T/cl/chains/chain.sh" build hoodi "$T/hoodi-ms.json" 2>/dev/null && cmp -s "$T/hoodi-ms.json" "$HOODI"; then
  ok "build: SLOT_DURATION_MS only gives the committed hoodi.json"
else
  bad "build with SLOT_DURATION_MS only"
fi

# ---- platform-azure/deploy/chain-from-devnet.sh on a devnet beacon API made of files ----
FROM_DEVNET="$ROOT/platform-azure/deploy/chain-from-devnet.sh"
FAR=18446744073709551615
# make_devnet DIR SPEC_FILTER SCHEDULE_FILTER: a Kurtosis-like devnet, every
# fork up to Fulu at epoch 0, Gloas and Heze at FAR_FUTURE_EPOCH, 6 s slots
# written both ways. The filters change the spec data and the schedule list.
make_devnet() {
  local d="$1/eth/v1"
  mkdir -p "$d/beacon" "$d/config"
  echo '{"data":{"genesis_time":"1792157697","genesis_validators_root":"0xabababababababababababababababababababababababababababababababab","genesis_fork_version":"0x10000038"}}' >"$d/beacon/genesis"
  jq -n --arg far "$FAR" "{data: ({PRESET_BASE: \"mainnet\", SECONDS_PER_SLOT: \"6\", SLOT_DURATION_MS: \"6000\", SLOTS_PER_EPOCH: \"32\",
    CAPELLA_FORK_VERSION: \"0x40000038\", GLOAS_FORK_VERSION: \"0x80000038\", GLOAS_FORK_EPOCH: \$far,
    HEZE_FORK_VERSION: \"0x90000038\", HEZE_FORK_EPOCH: \$far} | $2)}" >"$d/config/spec"
  jq -n --arg far "$FAR" "{data: ([\"10\",\"20\",\"30\",\"40\",\"50\",\"60\",\"70\"] as \$v
    | [range(0; 7) | {previous_version: (\"0x\" + \$v[[. - 1, 0] | max] + \"000038\"), current_version: (\"0x\" + \$v[.] + \"000038\"), epoch: \"0\"}]
    + [{previous_version: \"0x70000038\", current_version: \"0x80000038\", epoch: \$far},
       {previous_version: \"0x80000038\", current_version: \"0x90000038\", epoch: \$far}] | $3)}" >"$d/config/fork_schedule"
}
make_devnet "$T/dv-old" . 'map(select(.epoch != $far))'
expect_ok "chain-from-devnet: SECONDS_PER_SLOT config" bash "$FROM_DEVNET" "file://$T/dv-old" "$T/dv-old.json"
[ "$(jq -c '[.seconds_per_slot, (.forks | length), has("gloas_fork_epoch")]' "$T/dv-old.json")" = '[6,6,false]' ] &&
  ok "chain-from-devnet: 6 s, six forks, no gloas_fork_epoch" || bad "chain-from-devnet old style: $(jq -c . "$T/dv-old.json")"
expect_ok "chain-from-devnet: identify devnet" bash "$CHAIN" verify devnet "$T/dv-old.json"
make_devnet "$T/dv-far" . .
bash "$FROM_DEVNET" "file://$T/dv-far" "$T/dv-far.json" 2>/dev/null
[ "$(jq -c '[.forks[].epoch] | max' "$T/dv-far.json")" = 0 ] && ok "chain-from-devnet: forks at FAR_FUTURE_EPOCH left out" ||
  bad "chain-from-devnet far forks: $(jq -c .forks "$T/dv-far.json")"
make_devnet "$T/dv-new" 'del(.SECONDS_PER_SLOT) | .GLOAS_FORK_EPOCH = "16"' '(.[] | select(.current_version == "0x80000038")).epoch = "16"'
expect_ok "chain-from-devnet: SLOT_DURATION_MS config (generator 6.2.7)" bash "$FROM_DEVNET" "file://$T/dv-new" "$T/dv-new.json"
[ "$(jq -c '[.seconds_per_slot, .gloas_fork_epoch, [.forks[].epoch]]' "$T/dv-new.json")" = '[6,16,[0,0,0,0,0,0,16]]' ] &&
  ok "chain-from-devnet: 6 s, gloas_fork_epoch 16, Heze left out" || bad "chain-from-devnet new style: $(jq -c . "$T/dv-new.json")"
expect_ok "chain-from-devnet: identify the Gloas devnet" bash "$CHAIN" verify devnet "$T/dv-new.json"
make_devnet "$T/dv-half" 'del(.SECONDS_PER_SLOT) | .SLOT_DURATION_MS = "6500"' .
expect_fail "chain-from-devnet: a slot time that is not whole seconds" bash "$FROM_DEVNET" "file://$T/dv-half" "$T/dv-half.json"
[ -s "$T/dv-half.json" ] && bad "chain-from-devnet: wrote a file on failure" || ok "chain-from-devnet: no file content on failure"
make_devnet "$T/dv-none" 'del(.SECONDS_PER_SLOT, .SLOT_DURATION_MS)' .
expect_fail "chain-from-devnet: no slot time in the spec" bash "$FROM_DEVNET" "file://$T/dv-none" "$T/dv-none.json"
make_devnet "$T/dv-two" '.SLOT_DURATION_MS = "12000"' .
expect_fail "chain-from-devnet: SECONDS_PER_SLOT and SLOT_DURATION_MS disagree" bash "$FROM_DEVNET" "file://$T/dv-two" "$T/dv-two.json"
make_devnet "$T/dv-gl" '.GLOAS_FORK_EPOCH = "16"' .
expect_fail "chain-from-devnet: GLOAS_FORK_EPOCH not in the fork schedule" bash "$FROM_DEVNET" "file://$T/dv-gl" "$T/dv-gl.json"

# ---- the build record that the deploy steps check (scripts/common.sh) ----
mkdir -p "$T/build-hoodi"
cp "$HOODI" "$T/build-hoodi/chain.json"
(CHAIN=hoodi; write_build_chain "$T/build-hoodi/runner.chain" "$T/build-hoodi/chain.json")
expect_ok "deploy check: CHAIN=hoodi and a Hoodi build" env CHAIN=hoodi bash -c '. "$1/scripts/common.sh"; check_build_chain "$2/runner.chain" "$2/chain.json"' _ "$ROOT" "$T/build-hoodi"
expect_fail "deploy check: CHAIN=devnet and a Hoodi build" env CHAIN=devnet bash -c '. "$1/scripts/common.sh"; check_build_chain "$2/runner.chain" "$2/chain.json"' _ "$ROOT" "$T/build-hoodi"
expect_fail "deploy check: no CHAIN" env -u CHAIN bash -c '. "$1/scripts/common.sh"; check_build_chain "$2/runner.chain" "$2/chain.json"' _ "$ROOT" "$T/build-hoodi"
expect_fail "deploy check: CHAIN=mainnet is not a chain name" env CHAIN=mainnet bash -c '. "$1/scripts/common.sh"; check_build_chain "$2/runner.chain" "$2/chain.json"' _ "$ROOT" "$T/build-hoodi"
mkdir -p "$T/build-swap"
cp "$T/devnet.json" "$T/build-swap/chain.json"
cp "$T/build-hoodi/runner.chain" "$T/build-swap/runner.chain"
expect_fail "deploy check: record says hoodi, chain.json is a devnet file" env CHAIN=hoodi bash -c '. "$1/scripts/common.sh"; check_build_chain "$2/runner.chain" "$2/chain.json"' _ "$ROOT" "$T/build-swap"
mkdir -p "$T/build-old"
cp "$HOODI" "$T/build-old/chain.json"
expect_fail "deploy check: a build without a chain record" env CHAIN=hoodi bash -c '. "$1/scripts/common.sh"; check_build_chain "$2/runner.chain" "$2/chain.json"' _ "$ROOT" "$T/build-old"
expect_fail "build: CHAIN=devnet without CHAIN_JSON" env CHAIN=devnet bash -c 'unset CHAIN_JSON; . "$1/scripts/common.sh"; chain_select' _ "$ROOT"
expect_fail "build: CHAIN=hoodi with a devnet CHAIN_JSON" env CHAIN=hoodi CHAIN_JSON="$T/devnet.json" bash -c '. "$1/scripts/common.sh"; chain_select' _ "$ROOT"
expect_ok "build: CHAIN=hoodi takes governance/chains/hoodi.json" env CHAIN=hoodi bash -c 'unset CHAIN_JSON; . "$1/scripts/common.sh"; chain_select && [ "$CHAIN_JSON" = "$1/governance/chains/hoodi.json" ]' _ "$ROOT"
expect_ok "build: CHAIN=testnet takes governance/chains/chain.testnet.json" env CHAIN=testnet bash -c 'unset CHAIN_JSON; . "$1/scripts/common.sh"; chain_select && [ "$CHAIN_JSON" = "$1/governance/chains/chain.testnet.json" ]' _ "$ROOT"

echo "chain-test: $pass passed, $fail failed"
[ "$fail" = 0 ]
