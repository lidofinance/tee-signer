# platform

> **Early proof of concept.** Provided as is, without any warranty or guarantee.
> Not audited. Not for production or mainnet funds. Interfaces and formats will
> change without notice.

The hooks a runner needs from the secure environment (package `platform` at the module root: sealing, key release, store, attestation, clock), the shared AES-GCM sealer (`seal.go`), the setup loading at start (`setup`), the file store (`filestore`), JWT claim parsing shared by Azure and GCP (`jwtclaims`) and the dev platform (`dev`), which protects nothing and exists for tests and local runs.

Module path `github.com/lidofinance/tee-signer/platform`, with its own `go.mod`. It uses other modules of this repo only through their public packages (`scripts/check-imports.sh`).

Test it on its own from the repo root: `scripts/test-modules.sh platform`.
