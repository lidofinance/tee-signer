# devkit

> **Early proof of concept.** Provided as is, without any warranty or guarantee.
> Not audited. Not for production or mainnet funds. Interfaces and formats will
> change without notice.

Test helpers: `fuzzcheck` (no-panic and allocation oracles of the fuzz targets), `leakcheck` (goroutine leak check for TestMain) and `lockorder` (named mutexes; with the tag `lockcheck` a lock order inversion panics).

Only `lockorder` is linked into product builds, and there only as a plain mutex: the release gate (`scripts/release-gate.sh`) refuses its `check.go`, the tag `lockcheck` and every other devkit package in a release runner.

Module path `github.com/lidofinance/tee-signer/devkit`, with its own `go.mod`. It uses other modules of this repo only through their public packages (`scripts/check-imports.sh`).

Test it on its own from the repo root: `scripts/test-modules.sh devkit`.
