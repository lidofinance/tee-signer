# tee-signer

> **Early proof of concept.** Provided as is, without any warranty or guarantee.
> Not audited. Not for production or mainnet funds. Interfaces and formats will
> change without notice.

The runner: the program that runs inside the TEE. Package main at the module root wires a platform (chosen at build time by the tags `platform_aws`, `platform_azure`, `platform_gcp`, `platform_dev`), the setup, the clock, the mark log and the server. `server` handles the protocol (signing, imports, updates, exits, handover), `state` implements the storage and clock hooks of the C core with its restart protections, `record` is the clone guard, `attls` the attested mutual TLS, and `handover` the share handover between images (its order is `governance/handoverorder`).

The runner and its flows: [docs/runner.md](docs/runner.md). Build the binaries with `scripts/build-runner.sh` from the repo root.

Module path `github.com/lidofinance/tee-signer/tee-signer`, with its own `go.mod`. It uses other modules of this repo only through their public packages (`scripts/check-imports.sh`).

Test it on its own from the repo root: `scripts/test-modules.sh tee-signer`.
