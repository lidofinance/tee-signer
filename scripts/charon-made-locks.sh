#!/usr/bin/env bash
# Makes three cluster locks with stock `charon create cluster` (the local
# image, no network, throwaway keys in a temp folder) and prints their paths,
# comma separated, for CHARON_LOCKS: tee-signer/charonlock and charonnode check
# that they recompute the hashes, signatures and node signatures of locks
# Charon made. The keys in that folder are test keys of no chain.
#
# Usage: charon-made-locks.sh IMAGE
set -euo pipefail
image="$1"
dir="$(mktemp -d /tmp/charon-made-locks-XXXXXX)"
chmod 777 "$dir"
run() {
  docker run --rm --network none --user "$(id -u):$(id -g)" -v "$dir:/out" "$image" create cluster "$@" >/dev/null 2>&1
}
addr=0x8943545177806ed17b9f23f0a21ee5948ecaa776
run --name a --nodes 3 --threshold 2 --num-validators 2 --compounding --withdrawal-addresses "$addr" \
  --fee-recipient-addresses "$addr" --network hoodi --cluster-dir /out/a
run --nodes 4 --threshold 3 --num-validators 1 --withdrawal-addresses 0x000000000000000000000000000000000000dead \
  --fee-recipient-addresses 0x1111111111111111111111111111111111111111 --network mainnet --cluster-dir /out/b
run --nodes 3 --num-validators 3 --compounding --deposit-amounts 32,256 --withdrawal-addresses "$addr" \
  --fee-recipient-addresses "$addr" --testnet-name t --testnet-fork-version 0x10000038 --testnet-chain-id 3151908 \
  --testnet-genesis-timestamp 1791885112 --cluster-dir /out/c
ls "$dir"/*/node0/cluster-lock.json | paste -sd, -
