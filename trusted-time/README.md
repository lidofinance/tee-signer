# trusted-time

> **Early proof of concept.** Provided as is, without any warranty or guarantee.
> Not audited. Not for production or mainnet funds. Interfaces and formats will
> change without notice.

The runner clock (`clock`: system, HTTPS Date quorum, NTS) and the NTS client, in two parts with the build tag `nts`: `ntscore`, the core in freestanding C with its cgo binding (NTS-KE records, the keys and cookies, the NTPv4 exchange with the NTS extension fields, AES-SIV-CMAC-256, the sample measurement, the quorum of RFC 5905, the drift and coarse checks, the time served), and `nts`, the Go wrapper that gives the core its host operations (random bytes, `CLOCK_MONOTONIC_RAW`, the TLS 1.3 session of NTS-KE with the pinned roots per operator, the sockets). The line between them is drawn for a trusted application: the wrapper is the network and can hand the core nothing it could not get from an attacker on the wire. `nts/ntstest` holds loopback NTS servers for tests, with their own AES-SIV. The boundary, the design and the tests, among them a hostile host under the fuzzer: [docs/nts.md](docs/nts.md).

Module path `github.com/lidofinance/tee-signer/trusted-time`, with its own `go.mod`. It uses other modules of this repo only through their public packages (`scripts/check-imports.sh`).

Test it on its own from the repo root: `scripts/test-modules.sh trusted-time` (the Go tests, the freestanding build and symbol check of the core, and a run under the sanitizers). `make -C trusted-time/ntscore check` builds the core alone.
