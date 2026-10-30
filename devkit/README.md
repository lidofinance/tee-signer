# devkit

> **Early proof of concept.** Provided as is, without any warranty or guarantee.
> Not audited. Not for production or mainnet funds. Interfaces and formats will
> change without notice.

Test helpers: `fuzzcheck` (no-panic and allocation oracles of the fuzz targets),
`leakcheck` (goroutine leak check for TestMain), `lockorder` (named lock order
checks under `-tags lockcheck`) and `cfuzz` (the shared C fuzz driver for systems
without libFuzzer).

No devkit package belongs in product builds. The runner and mark log use
plain `sync.Mutex` and `sync.RWMutex` in normal builds. Only files guarded by
`//go:build lockcheck` may import `lockorder`; the release gate rejects that tag
and all devkit dependencies.

Module path `github.com/lidofinance/tee-signer/devkit`, with its own `go.mod`. It uses other modules of this repo only through their public packages (`scripts/check-imports.sh`).

Test it on its own from the repo root: `scripts/test-modules.sh devkit`.
