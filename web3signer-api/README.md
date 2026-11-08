# web3signer-api

> **Pre-release.** Running on test networks; not yet for mainnet funds.
> Provided as is, without warranty. Interfaces and formats may change before
> the first release.

Parsing and checking of Web3Signer signing requests (EIP-3030): `signing` turns a request into a typed message and its signing root, checks `fork_info` against the pinned chain, and covers the Gloas types; `eth2` computes domains and roots. It came from the gateway and is the start of the module of the Web3Signer design: today it parses with go-eth2-client.

Module path `github.com/lidofinance/tee-signer/web3signer-api`, with its own `go.mod`. It uses other modules of this repo only through their public packages (`scripts/check-imports.sh`).

Test it on its own from the repo root: `scripts/test-modules.sh web3signer-api`.
