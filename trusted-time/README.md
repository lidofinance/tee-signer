# trusted-time

> **Early proof of concept.** Provided as is, without any warranty or guarantee.
> Not audited. Not for production or mainnet funds. Interfaces and formats will
> change without notice.

The runner clock (`clock`: system, HTTPS Date quorum, NTS) and the NTS client: a Rust crate (`rust/`, `signer-nts` with its `no_std` core `signer-nts-core`) behind a C ABI, and its Go binding (`nts`, build tag `nts`). `nts/ntstest` holds loopback NTS servers for tests.

The crates are vendored in `third_party/nts-vendor` and pinned by `rust/Cargo.lock`, `rust/crates.allow` and `rust/vendor.sha256`; `scripts/build-nts.sh` builds offline in the toolchain image of `toolchain/` and refuses a vendored tree that differs. Design and tests: [docs/nts.md](docs/nts.md).

Module path `github.com/lidofinance/tee-signer/trusted-time`, with its own `go.mod`. It uses other modules of this repo only through their public packages (`scripts/check-imports.sh`).

Test it on its own from the repo root: `scripts/test-modules.sh trusted-time`.
