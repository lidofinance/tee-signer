# devkit

> **Early proof of concept.** Provided as is, without any warranty or guarantee.
> Not audited. Not for production or mainnet funds. Interfaces and formats will
> change without notice.

Test helpers: `fuzzcheck` (no-panic and allocation oracles of the fuzz targets) and `leakcheck` (goroutine leak check for TestMain).

No devkit package belongs in product builds. The runner and mark log use
`sync.Mutex` and `sync.RWMutex` directly. The import guard and release gate
reject production imports of devkit.

Module path `github.com/lidofinance/tee-signer/devkit`, with its own `go.mod`. It uses other modules of this repo only through their public packages (`scripts/check-imports.sh`).

Test it on its own from the repo root: `scripts/test-modules.sh devkit`.
