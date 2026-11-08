# tests

> **Pre-release.** Running on test networks; not yet for mainnet funds.
> Provided as is, without warranty. Interfaces and formats may change before
> the first release.

Tests across modules: `e2e` starts the built runner binaries (`scripts/build-runner.sh`) and the tools of `signer-admin` and `platform-aws` and runs the end-to-end flows. `scripts/test.sh` runs it with the binaries it needs.

Module path `github.com/lidofinance/tee-signer/tests`, with its own `go.mod`. It uses other modules of this repo only through their public packages (`scripts/check-imports.sh`).

Test it on its own from the repo root: `scripts/test-modules.sh tests`.
