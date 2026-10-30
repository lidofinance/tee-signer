# trusted-time

> **Early proof of concept.** Provided as is, without any warranty or guarantee.
> Not audited. Not for production or mainnet funds. Interfaces and formats will
> change without notice.

The runner clock (`clock`: system, HTTPS Date quorum, NTS) and the NTS client: a Rust crate (`rust/`, `signer-nts` with its `no_std` core `signer-nts-core`) behind a C ABI, and its Go binding (`nts`, build tag `nts`). `nts/ntstest` holds loopback NTS servers for tests.

The crates come from crates.io, pinned with their sha256 by `rust/Cargo.lock` and limited to the list in `rust/crates.allow`. `scripts/fetch-nts.sh` downloads them into `build/nts/cargo-home` (the first build needs a network once; `make clean` removes it). Before every build the crate archives are checked against the sha256 in the lock, on the host and again in the toolchain image of `toolchain/`, where `scripts/build-nts.sh` unpacks them into a cargo directory source and builds offline from it alone, without the registry index. Design and tests: [docs/nts.md](docs/nts.md).

Module path `github.com/lidofinance/tee-signer/trusted-time`, with its own `go.mod`. It uses other modules of this repo only through their public packages (`scripts/check-imports.sh`).

Test it on its own from the repo root: `scripts/test-modules.sh trusted-time`.
