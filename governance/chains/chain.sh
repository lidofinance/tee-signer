#!/usr/bin/env bash
# The runner's chain config for a public chain, built from a pinned copy of the
# chain's published config, and the checks that keep images and chains apart.
#
#   chain.sh build NAME [OUT]
#       Write the runner chain.json of NAME (default OUT: chains/NAME.json)
#       from chains/NAME.source.json. Offline. The policy fields come from the
#       "policy" object of the source file; MAX_EPOCHS_AHEAD, FEE_RECIPIENT,
#       GAS_LIMIT_MIN, GAS_LIMIT_MAX, EXIT_ALLOWLIST (validator indices, comma
#       separated; the signers refuse an exit of any other index) and
#       COMMIT_AHEAD (block,source,target) override them. Another policy gives
#       another file, so another image. Write such a file to OUT and pass it
#       as CHAIN_JSON to the image builds; it is still chain NAME.
#   chain.sh check-source NAME CONFIG_YAML GVR_FILE
#       Compare chains/NAME.source.json with the chain's own files, fetched by
#       you from the repo and commit the source file names (config.yaml and
#       genesis_validators_root.txt). Fails on any difference and on a fork in
#       the config that the source file does not list (a new fork was
#       scheduled). Then checks that chains/NAME.json is what `build` makes.
#   chain.sh check-beacon NAME [URL]
#       Compare chains/NAME.json with a beacon node of that chain: genesis,
#       spec and fork schedule. URL defaults to $BEACON_URL. The URL is passed
#       to curl on stdin, never on a command line, and printed as scheme and
#       host only, so a URL with credentials stays out of logs.
#   chain.sh identify FILE
#       Print the chain of a runner chain.json: hoodi, devnet (the local
#       Kurtosis devnet), testnet (governance/chains/chain.testnet.json, a test chain no
#       network runs), or exit 1 with the reason. A file with the genesis fork
#       version of a public chain counts as that chain only when every chain
#       field equals the pinned one.
#   chain.sh verify NAME FILE
#       Exit 0 only if FILE is a runner chain.json of chain NAME.
#
# Chain fields are genesis_validators_root, genesis_fork_version, forks,
# gloas_fork_epoch (absent when the chain has not scheduled Gloas),
# voluntary_exit_fork_version, genesis_time, seconds_per_slot and
# slots_per_epoch. seconds_per_slot is SECONDS_PER_SLOT, or SLOT_DURATION_MS /
# 1000 for a config that has only SLOT_DURATION_MS. The other fields are
# signer policy and may differ.
set -euo pipefail

CHAINS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FAR_FUTURE=18446744073709551615

die() { echo "chain: $*" >&2; exit 1; }
say() { echo "chain: $*" >&2; }

command -v jq >/dev/null || die "jq is needed"

# Genesis fork versions of networks this repo knows. Kurtosis uses 0x10000038
# for every devnet, so a devnet is told by that version only.
KNOWN_VERSIONS='{
  "0x00000000": "mainnet",
  "0x90000069": "sepolia",
  "0x01017000": "holesky",
  "0x10000910": "hoodi",
  "0x00000064": "gnosis",
  "0x0000006f": "chiado",
  "0x10000038": "devnet",
  "0x00000001": "testnet"
}'
# The chains this repo pins with a source file.
PINNED="hoodi"

source_file() {
  local f="$CHAINS_DIR/$1.source.json"
  [ -f "$f" ] || die "no $f (pinned chains: $PINNED)"
  printf '%s' "$f"
}

# chain_fields FILE: the chain fields of a runner chain.json, canonical JSON.
chain_fields() {
  jq -cS '{genesis_validators_root: (.genesis_validators_root | ascii_downcase),
    genesis_fork_version: (.genesis_fork_version | ascii_downcase),
    forks: [.forks[] | {epoch, version: (.version | ascii_downcase)}],
    gloas_fork_epoch,
    voluntary_exit_fork_version: (.voluntary_exit_fork_version | ascii_downcase),
    genesis_time, seconds_per_slot, slots_per_epoch}' "$1"
}

cmd_build() {
  local name="${1:?chain name}" out="${2:-}" src
  src="$(source_file "$name")"
  [ -n "$out" ] || out="$CHAINS_DIR/$name.json"
  local commit="${COMMIT_AHEAD:-}"
  jq --arg far "$FAR_FUTURE" \
    --arg maxahead "${MAX_EPOCHS_AHEAD:-}" --arg fee "${FEE_RECIPIENT:-}" \
    --arg gasmin "${GAS_LIMIT_MIN:-}" --arg gasmax "${GAS_LIMIT_MAX:-}" --arg commit "$commit"     --arg exits "${EXIT_ALLOWLIST:-}" '
    .config as $c
    | (.policy
       | if $maxahead != "" then .max_epochs_ahead = ($maxahead | tonumber) else . end
       | if $fee != "" then .fee_recipients = [$fee] else . end
       | if $gasmin != "" then .gas_limit_min = ($gasmin | tonumber) else . end
       | if $gasmax != "" then .gas_limit_max = ($gasmax | tonumber) else . end
       | if $exits != "" then .exit_allowlist = ($exits | split(",") | map(tonumber)) else . end
       | if $commit != "" then ($commit | split(",") | map(tonumber)) as $x
           | .commit_ahead = {block_slots: $x[0], source_epochs: $x[1], target_epochs: $x[2]} else . end) as $p
    | {
        genesis_validators_root: .genesis_validators_root,
        genesis_fork_version: $c.GENESIS_FORK_VERSION,
        forks: [ .forks[]
                 | select($c[. + "_FORK_EPOCH"] != $far)
                 | {epoch: ($c[. + "_FORK_EPOCH"] | tonumber), version: $c[. + "_FORK_VERSION"]} ]
               | sort_by(.epoch),
      }
      + (if (.forks | index("GLOAS")) and ($c.GLOAS_FORK_EPOCH // $far) != $far
         then {gloas_fork_epoch: ($c.GLOAS_FORK_EPOCH | tonumber)} else {} end)
      + {
        voluntary_exit_fork_version: $c.CAPELLA_FORK_VERSION,
        genesis_time: .genesis_time,
        seconds_per_slot: (if $c.SECONDS_PER_SLOT != null then ($c.SECONDS_PER_SLOT | tonumber)
                           else ($c.SLOT_DURATION_MS | tonumber) / 1000 end),
        slots_per_epoch: .slots_per_epoch,
        max_epochs_ahead: $p.max_epochs_ahead,
        exit_allowlist: $p.exit_allowlist,
        fee_recipients: $p.fee_recipients,
        gas_limit_min: $p.gas_limit_min,
        gas_limit_max: $p.gas_limit_max,
        registration_max_future_seconds: $p.registration_max_future_seconds,
        commit_ahead: $p.commit_ahead
      }' "$src" >"$out.tmp.$$"
  # Every fork the source lists must have a version and an epoch in the config.
  jq -e --slurpfile s "$src" '
    ($s[0].config) as $c
    | (.genesis_fork_version | test("^0x[0-9a-f]{8}$"))
      and (.genesis_validators_root | test("^0x[0-9a-f]{64}$"))
      and (.forks | length) > 0
      and (.seconds_per_slot | type == "number" and . > 0 and floor == .)
      and ([.forks[].version] | all(test("^0x[0-9a-f]{8}$")))
      and ($s[0].forks | all(($c[. + "_FORK_VERSION"] != null) and ($c[. + "_FORK_EPOCH"] != null)))
      and (if has("gloas_fork_epoch") then .gloas_fork_epoch as $g | [.forks[].epoch] | index($g) != null
           else true end)' \
    "$out.tmp.$$" >/dev/null || { rm -f "$out.tmp.$$"; die "$src: incomplete or malformed chain data"; }
  mv -f "$out.tmp.$$" "$out"
  say "wrote $out ($name, $(jq '.forks | length' "$out") forks, genesis $(jq -r .genesis_time "$out"))"
}

# yaml_value FILE KEY: the value of a top-level "KEY: value" line, without quotes.
yaml_values() {
  sed -nE 's/^([A-Z][A-Z0-9_]*):[[:space:]]*"?([^"#[:space:]]+)"?.*$/\1 \2/p' "$1"
}

cmd_check_source() {
  local name="${1:?chain name}" yaml="${2:?config.yaml of the chain}" gvrfile="${3:?genesis_validators_root.txt of the chain}"
  local src bad=0 key want got
  src="$(source_file "$name")"
  [ -f "$yaml" ] || die "no $yaml"
  [ -f "$gvrfile" ] || die "no $gvrfile"
  declare -A up=()
  while read -r key got; do up[$key]="$got"; done < <(yaml_values "$yaml")
  [ "${#up[@]}" -gt 0 ] || die "$yaml has no KEY: value lines"
  while IFS=$'\t' read -r key want; do
    got="${up[$key]:-<missing>}"
    if [ "$got" = "$want" ]; then
      echo "ok    $key $got"
    else
      echo "DIFF  $key: source file $want, $yaml $got"
      bad=1
    fi
  done < <(jq -r '.config | to_entries[] | [.key, .value] | @tsv' "$src")
  # A fork in the config that the source file does not list.
  local listed
  listed=" $(jq -r '.forks | join(" ")' "$src") "
  for key in "${!up[@]}"; do
    case "$key" in
      *_FORK_EPOCH)
        local fork="${key%_FORK_EPOCH}"
        case "$listed" in *" $fork "*) continue ;; esac
        if [ "${up[$key]}" = "$FAR_FUTURE" ]; then
          echo "ok    $key not scheduled ($FAR_FUTURE), left out"
        else
          echo "DIFF  $key ${up[$key]}: a fork the source file does not list"
          bad=1
        fi
        ;;
    esac
  done
  if [ "${up[PRESET_BASE]:-}" = mainnet ] && [ "$(jq -r .slots_per_epoch "$src")" = 32 ]; then
    echo "ok    SLOTS_PER_EPOCH 32 (mainnet preset)"
  else
    echo "DIFF  SLOTS_PER_EPOCH: preset ${up[PRESET_BASE]:-<missing>}, source file $(jq -r .slots_per_epoch "$src")"
    bad=1
  fi
  want="$(jq -r .genesis_validators_root "$src")"
  got="$(tr -d '[:space:]' <"$gvrfile" | tr 'A-F' 'a-f')"
  if [ "$got" = "$want" ]; then echo "ok    genesis_validators_root $got"; else echo "DIFF  genesis_validators_root: source file $want, $gvrfile $got"; bad=1; fi
  # The genesis time is not in config.yaml. For a chain that started at
  # MIN_GENESIS_TIME it is MIN_GENESIS_TIME + GENESIS_DELAY, which the README
  # of the chain states too. check-beacon compares it with a node.
  want="$(jq -r .genesis_time "$src")"
  got=$(( ${up[MIN_GENESIS_TIME]:-0} + ${up[GENESIS_DELAY]:-0} ))
  if [ "$got" = "$want" ]; then echo "ok    genesis_time $want = MIN_GENESIS_TIME + GENESIS_DELAY"; else echo "DIFF  genesis_time: source file $want, MIN_GENESIS_TIME + GENESIS_DELAY $got"; bad=1; fi
  local tmp
  tmp="$(mktemp)"
  cmd_build "$name" "$tmp" 2>/dev/null
  if cmp -s "$tmp" "$CHAINS_DIR/$name.json"; then
    echo "ok    $name.json is what chain.sh build makes from the source file"
  else
    echo "DIFF  $name.json differs from a fresh build (run: chain.sh build $name)"
    bad=1
  fi
  rm -f "$tmp"
  [ "$bad" = 0 ] || die "$name: the source file does not match $yaml"
  say "$name: the source file matches $yaml and $gvrfile"
}

# redact URL: scheme and host only.
redact() { sed -E 's#^([A-Za-z][A-Za-z0-9+.-]*://)([^/@]*@)?([^/?#]*).*#\1\3#' <<<"$1"; }

# beacon_get BASE PATH: GET, with the URL on stdin (curl -K -).
beacon_get() {
  local url="${1%/}/eth/v1/$2"
  url="${url//\\/\\\\}"
  url="${url//\"/\\\"}"
  printf 'url = "%s"\n' "$url" | curl -fsS --max-time 20 -K -
}

cmd_check_beacon() {
  local name="${1:?chain name}" base="${2:-${BEACON_URL:-}}" file bad=0
  [ -n "$base" ] || die "no beacon URL: pass it or set BEACON_URL"
  file="$CHAINS_DIR/$name.json"
  [ -f "$file" ] || die "no $file"
  local shown genesis spec sched
  shown="$(redact "$base")"
  genesis="$(beacon_get "$base" beacon/genesis)" || die "$shown: no answer for beacon/genesis"
  spec="$(beacon_get "$base" config/spec)" || die "$shown: no answer for config/spec"
  sched="$(beacon_get "$base" config/fork_schedule)" || die "$shown: no answer for config/fork_schedule"
  local -a checks=(
    "genesis_validators_root|$(jq -r '.genesis_validators_root | ascii_downcase' "$file")|$(jq -r '.data.genesis_validators_root | ascii_downcase' <<<"$genesis")"
    "genesis_time|$(jq -r .genesis_time "$file")|$(jq -r .data.genesis_time <<<"$genesis")"
    "genesis_fork_version|$(jq -r '.genesis_fork_version | ascii_downcase' "$file")|$(jq -r '.data.genesis_fork_version | ascii_downcase' <<<"$genesis")"
    "seconds_per_slot|$(jq -r .seconds_per_slot "$file")|$(jq -r 'if .data.SECONDS_PER_SLOT != null then .data.SECONDS_PER_SLOT else (.data.SLOT_DURATION_MS // "" | if . == "" then "<missing>" else tonumber / 1000 | tostring end) end' <<<"$spec")"
    "slots_per_epoch|$(jq -r .slots_per_epoch "$file")|$(jq -r .data.SLOTS_PER_EPOCH <<<"$spec")"
    "voluntary_exit_fork_version|$(jq -r '.voluntary_exit_fork_version | ascii_downcase' "$file")|$(jq -r '.data.CAPELLA_FORK_VERSION | ascii_downcase' <<<"$spec")"
    "gloas_fork_epoch|$(jq -r --arg far "$FAR_FUTURE" '.gloas_fork_epoch // $far | tostring' "$file")|$(jq -r --arg far "$FAR_FUTURE" '.data.GLOAS_FORK_EPOCH // $far | tostring' <<<"$spec")"
  )
  local src
  if src="$(source_file "$name" 2>/dev/null)"; then
    checks+=(
      "DEPOSIT_CHAIN_ID|$(jq -r .config.DEPOSIT_CHAIN_ID "$src")|$(jq -r .data.DEPOSIT_CHAIN_ID <<<"$spec")"
      "DEPOSIT_CONTRACT_ADDRESS|$(jq -r '.config.DEPOSIT_CONTRACT_ADDRESS | ascii_downcase' "$src")|$(jq -r '.data.DEPOSIT_CONTRACT_ADDRESS | ascii_downcase' <<<"$spec")"
    )
  fi
  # The fork schedule, genesis version left out, as the build does.
  local want_forks got_forks
  want_forks="$(jq -c '[.forks[] | {epoch: (.epoch | tostring), version: (.version | ascii_downcase)}]' "$file")"
  got_forks="$(jq -c --arg g "$(jq -r '.genesis_fork_version | ascii_downcase' "$file")" --arg far "$FAR_FUTURE" '
    [.data[] | select((.current_version | ascii_downcase) != $g) | select(.epoch != $far)
     | {epoch: .epoch, version: (.current_version | ascii_downcase)}] | sort_by(.epoch | tonumber)' <<<"$sched")"
  checks+=("fork_schedule|$want_forks|$got_forks")
  local c key want got
  for c in "${checks[@]}"; do
    IFS='|' read -r key want got <<<"$c"
    if [ "$want" = "$got" ]; then
      echo "ok    $key $want"
    else
      echo "DIFF  $key: $name.json $want, beacon node $got"
      bad=1
    fi
  done
  [ "$bad" = 0 ] || die "the beacon node at $shown is not on $name as pinned (or does not know its whole fork schedule)"
  say "the beacon node at $shown is on $name as pinned"
}

cmd_identify() {
  local file="${1:?runner chain.json}" gfv name
  [ -f "$file" ] || die "no $file"
  jq -e '.genesis_validators_root and .genesis_fork_version and .forks and .genesis_time and .seconds_per_slot and .slots_per_epoch' \
    "$file" >/dev/null 2>&1 || die "$file is not a runner chain config"
  gfv="$(jq -r '.genesis_fork_version | ascii_downcase' "$file")"
  name="$(jq -r --arg v "$gfv" '.[$v] // empty' <<<"$KNOWN_VERSIONS")"
  case "$name" in
    "") die "$file: genesis fork version $gfv is not a chain this repo knows" ;;
    devnet) ;;
    testnet)
      [ "$(chain_fields "$file")" = "$(chain_fields "$CHAINS_DIR/chain.testnet.json")" ] ||
        die "$file: genesis fork version $gfv but not the chain fields of governance/chains/chain.testnet.json"
      ;;
    *)
      case " $PINNED " in *" $name "*) ;; *) die "$file: $name, a public chain this repo does not pin" ;; esac
      [ -f "$CHAINS_DIR/$name.json" ] || die "no $CHAINS_DIR/$name.json"
      [ "$(chain_fields "$file")" = "$(chain_fields "$CHAINS_DIR/$name.json")" ] ||
        die "$file: genesis fork version of $name, but other chain fields than chains/$name.json"
      ;;
  esac
  echo "$name"
}

cmd_verify() {
  local name="${1:?chain name}" file="${2:?runner chain.json}" got
  got="$(cmd_identify "$file")" || exit 1
  [ "$got" = "$name" ] || die "$file is chain $got, not $name"
}

usage() {
  sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed -e '/^set -euo/d' -e 's/^# \{0,1\}//' >&2
  exit 2
}

cmd="${1:-}"
[ $# -gt 0 ] && shift
case "$cmd" in
  build) cmd_build "$@" ;;
  check-source) cmd_check_source "$@" ;;
  check-beacon) cmd_check_beacon "$@" ;;
  identify) cmd_identify "$@" ;;
  verify) cmd_verify "$@" ;;
  *) usage ;;
esac
