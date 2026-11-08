# signer-protocol

> **Pre-release.** Running on test networks; not yet for mainnet funds.
> Provided as is, without warranty. Interfaces and formats may change before
> the first release.

The wire protocol between a runner and its clients: the request and answer types (package `backend` at the module root), frame encoding (`wire`, `wire/admin`), transports (`transport`: TCP, Unix socket, vsock), the client connection (`remote`), sealed share import (`sealedimport`) and the constants of the chain a runner is built for (`buildchain`). Pure Go, no cgo.

The protocol is described in [docs/protocol.md](docs/protocol.md).

Module path `github.com/lidofinance/tee-signer/signer-protocol`, with its own `go.mod`. It uses other modules of this repo only through their public packages (`scripts/check-imports.sh`).

Test it on its own from the repo root: `scripts/test-modules.sh signer-protocol`.
