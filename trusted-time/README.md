# trusted-time

> **Pre-release.** Running on test networks; not yet for mainnet funds.
> Provided as is, without warranty. Interfaces and formats may change before
> the first release.

The runner clock (`clock`: system, HTTPS Date quorum, NTS) and the NTS client, in two parts with the build tag `nts`: `ntscore`, the core in freestanding C (`ntscore/c`) with its cgo binding (`ntscore/go`) (NTS-KE records, the keys and cookies, the NTPv4 exchange with the NTS extension fields, AES-SIV-CMAC-256, plain NTP for a setup that selects it, the sample measurement, the quorum of RFC 5905 under the majority rule, the drift and coarse checks, the time served), and `nts`, the Go wrapper that gives the core its host operations (random bytes, `CLOCK_MONOTONIC_RAW`, the TLS 1.3 session of NTS-KE with the pinned roots per operator, the sockets). The line between them is drawn for a trusted application: the wrapper is the network and can hand the core nothing it could not get from an attacker on the wire. `nts/ntstest` holds loopback NTS servers for tests, with their own AES-SIV, and `nts/ntstest/ntsworld` a virtual world of made-up operators for the clock's simulations. `ntscatalog` is the image's list of NTS servers (host, operator, pinned root files, Nitro route, a note on the operator's terms), kept in `ntscatalog/catalog.json` and embedded in the binary, with no build tag and no cgo. The boundary, the design and the tests, among them a hostile host under the fuzzer: [docs/nts.md](docs/nts.md).

Module path `github.com/lidofinance/tee-signer/trusted-time`, with its own `go.mod`. It uses other modules of this repo only through their public packages (`scripts/check-imports.sh`).

Test it on its own from the repo root: `scripts/test-modules.sh trusted-time` (the Go tests, the freestanding build and symbol check of the core, a run under the sanitizers, and the binding's tests against a core built without plain NTP). `make -C trusted-time/ntscore/c check` builds the core's archive alone and checks its symbols; the Go tests of `ntscore/go` link that archive (`scripts/build-core.sh`, `make core` at the root, builds it for every architecture).
