# trusted-time

> **Early proof of concept.** Provided as is, without any warranty or guarantee.
> Not audited. Not for production or mainnet funds. Interfaces and formats will
> change without notice.

The runner clock (`clock`: system, HTTPS Date quorum, NTS) and the NTS client (`nts`, build tag `nts`): NTS-KE, cookies and the AES-SIV extension fields come from `github.com/beevik/nts` over `github.com/beevik/ntp`; this module adds the pinned roots per operator, the sample measurement and the quorum of RFC 5905, and keeps the local clock on `CLOCK_MONOTONIC_RAW`. `nts/ntstest` holds loopback NTS servers for tests, with their own AES-SIV. Design and tests: [docs/nts.md](docs/nts.md).

Module path `github.com/lidofinance/tee-signer/trusted-time`, with its own `go.mod`. It uses other modules of this repo only through their public packages (`scripts/check-imports.sh`).

Test it on its own from the repo root: `scripts/test-modules.sh trusted-time`.
