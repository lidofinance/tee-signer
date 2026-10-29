# signer-protocol

> **Early proof of concept.** Provided as is, without any warranty or guarantee.
> Not audited. Not for production or mainnet funds. Interfaces and formats will
> change without notice.

The wire protocol between a runner and its clients: the request and answer types (package `backend` at the module root), frame encoding (`wire`, `wire/admin`), transports (`transport`: TCP, Unix socket, vsock), the client connection (`remote`), sealed share import (`sealedimport`) and the build flavour constants (`buildflavor`). The fixed watermark storage codec (`watermark.go`) also lives here. Pure Go, no cgo.

The protocol is described in [docs/protocol.md](docs/protocol.md).

Module path `github.com/lidofinance/tee-signer/signer-protocol`, with its own `go.mod`. It uses other modules of this repo only through their public packages (`scripts/check-imports.sh`).

Test it on its own from the repo root: `scripts/test-modules.sh signer-protocol`.
