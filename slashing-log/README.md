# slashing-log

> **Early proof of concept.** Provided as is, without any warranty or guarantee.
> Not audited. Not for production or mainnet funds. Interfaces and formats will
> change without notice.

The mark log (package `markstore` at the module root): the external, append-only record of the signing marks that lets a runner refuse to sign below what any copy of it signed before. Also the encrypted state copy on host storage (`statestore`), the shared store test suite (`logtest`) and the object store fake with fault injection (`wormfake`).

The watermark storage codec lives in `signer-protocol`. The log does not depend on the signing bindings or cgo.

The cloud object store clients live in the platform modules (`platform-aws/s3log`, `platform-gcp/gcslog`, `platform-azure/azlog`). Design: [docs/marklog.md](docs/marklog.md), [docs/durable-state.md](docs/durable-state.md).

Module path `github.com/lidofinance/tee-signer/slashing-log`, with its own `go.mod`. It uses other modules of this repo only through their public packages (`scripts/check-imports.sh`).

Test it on its own from the repo root: `scripts/test-modules.sh slashing-log`.
