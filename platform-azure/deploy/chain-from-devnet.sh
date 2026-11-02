#!/usr/bin/env bash
# Writes the runner's chain.json for a local test chain by reading its
# beacon node, for example a Kurtosis ethereum-package network.
#
#   chain-from-devnet.sh [BEACON_URL [OUT]]
#
# BEACON_URL defaults to http://127.0.0.1:33001 (fixed port of the devnet's
# beacon node). OUT defaults to stdout. The chain fields come from the beacon
# API. The policy fields (fee recipient, gas limits, exits) are set here with
# the values of the signing client's devnet mode; override them with the variables
# below.
#
# Chain fields, as governance/chains/chain.sh build writes them for Hoodi:
#   - forks at FAR_FUTURE_EPOCH (not scheduled) are left out.
#   - gloas_fork_epoch is the spec's GLOAS_FORK_EPOCH when Gloas is
#     scheduled, and absent when it is not. Without it the signer core treats
#     Gloas as unscheduled and refuses every PTC vote, payload envelope and
#     proposer preferences.
#   - seconds_per_slot is SECONDS_PER_SLOT, or SLOT_DURATION_MS / 1000 when
#     the spec has no SECONDS_PER_SLOT (the config.yaml of generator 6.2.7
#     has only SLOT_DURATION_MS). When both are there they must agree.
#
# genesis_time changes every time the devnet is created, so a chain.json
# made for one devnet run does not fit the next one. The file is part of the
# runner image, so a new devnet means a new image, a new CCE policy hash and
# new Key Vault keys (platform-azure/deploy/README.md).
#
# This is for the devnet only. Hoodi has a committed chain config,
# governance/chains/hoodi.json, built from the chain's published config by
# governance/chains/chain.sh, which also checks a Hoodi beacon node against it.
set -euo pipefail

BEACON="${1:-http://127.0.0.1:33001}"
OUT="${2:-/dev/stdout}"
MAX_EPOCHS_AHEAD="${MAX_EPOCHS_AHEAD:-2}"
FEE_RECIPIENT="${FEE_RECIPIENT:-0x000000000000000000000000000000000000dEaD}"
GAS_LIMIT_MIN="${GAS_LIMIT_MIN:-30000000}"
GAS_LIMIT_MAX="${GAS_LIMIT_MAX:-60000000}"
EXIT_ALLOWLIST="${EXIT_ALLOWLIST:-}" # comma separated validator indices, empty = no exits
COMMIT_AHEAD="${COMMIT_AHEAD:-32,2,2}" # block_slots,source_epochs,target_epochs
FAR_FUTURE=18446744073709551615

api() { curl -fsS --max-time 20 "$BEACON/eth/v1/$1"; }

genesis="$(api beacon/genesis)"
spec="$(api config/spec)"
forks="$(api config/fork_schedule)"

# The whole file is made before OUT is opened, so a failed check leaves no
# half-written file behind.
chain="$(jq -n \
  --argjson genesis "$genesis" --argjson spec "$spec" --argjson forks "$forks" \
  --argjson maxahead "$MAX_EPOCHS_AHEAD" --arg fee "$FEE_RECIPIENT" \
  --argjson gasmin "$GAS_LIMIT_MIN" --argjson gasmax "$GAS_LIMIT_MAX" \
  --arg exits "$EXIT_ALLOWLIST" --arg commit "$COMMIT_AHEAD" --arg far "$FAR_FUTURE" '
  def fail(m): error("chain-from-devnet: " + m);
  ($commit | split(",") | map(tonumber)) as $c
  | $genesis.data.genesis_fork_version as $gfv
  | $spec.data as $s
  | ($s.SLOT_DURATION_MS // null | if . == null then null else tonumber / 1000 end) as $ms
  | (if $s.SECONDS_PER_SLOT != null then ($s.SECONDS_PER_SLOT | tonumber)
     elif $ms != null then $ms
     else fail("the spec has neither SECONDS_PER_SLOT nor SLOT_DURATION_MS") end) as $sps
  | if ($sps | floor) != $sps or $sps <= 0 then fail("slot time \($sps) s is not a whole number of seconds") else . end
  | if $ms != null and $ms != $sps then fail("SECONDS_PER_SLOT \($sps) and SLOT_DURATION_MS \($s.SLOT_DURATION_MS) disagree") else . end
  | ($s.GLOAS_FORK_EPOCH // $far | tostring) as $gloas
  | [ $forks.data[]
      | select(.current_version != $gfv and (.epoch | tostring) != $far)
      | {epoch: (.epoch | tonumber), version: .current_version} ]
    | sort_by(.epoch) as $fl
  | if $gloas != $far and ([$fl[] | select(.epoch == ($gloas | tonumber) and .version == $s.GLOAS_FORK_VERSION)] | length) == 0
    then fail("GLOAS_FORK_EPOCH \($gloas) is not in the fork schedule with GLOAS_FORK_VERSION") else . end
  | {
      genesis_validators_root: $genesis.data.genesis_validators_root,
      genesis_fork_version: $gfv,
      forks: $fl
    }
  + (if $gloas != $far then {gloas_fork_epoch: ($gloas | tonumber)} else {} end)
  + {
      voluntary_exit_fork_version: $s.CAPELLA_FORK_VERSION,
      genesis_time: ($genesis.data.genesis_time | tonumber),
      seconds_per_slot: $sps,
      slots_per_epoch: ($s.SLOTS_PER_EPOCH | tonumber),
      max_epochs_ahead: $maxahead,
      exit_allowlist: (if $exits == "" then [] else ($exits | split(",") | map(tonumber)) end),
      fee_recipients: [$fee],
      gas_limit_min: $gasmin,
      gas_limit_max: $gasmax,
      registration_max_future_seconds: 3600,
      commit_ahead: {block_slots: $c[0], source_epochs: $c[1], target_epochs: $c[2]}
    }')"
printf '%s\n' "$chain" >"$OUT"
