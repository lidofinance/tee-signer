# tests

> **Early proof of concept.** Provided as is, without any warranty or guarantee.
> Not audited. Not for production or mainnet funds. Interfaces and formats will
> change without notice.

Tests across modules: `e2e` starts the built runner binaries (`scripts/build-runner.sh`) and the tools of `signer-admin` and `platform-aws` and runs the end-to-end flows, the handover release gate (`TestE2EHandoverGate`) included. `scripts/test.sh` runs it with the binaries it needs.

Module path `github.com/lidofinance/tee-signer/tests`, with its own `go.mod`. It uses other modules of this repo only through their public packages (`scripts/check-imports.sh`).

Test it on its own from the repo root: `scripts/test-modules.sh tests`.
