# governance

> **Early proof of concept.** Provided as is, without any warranty or guarantee.
> Not audited. Not for production or mainnet funds. Interfaces and formats will
> change without notice.

The setup and the approver rules: the setup format, approver sets, signed updates, time locks and signature contexts (`setupwire`), the build flavours (`flavor`), and the approved orders for handover (`handoverorder`), share import (`importorder`) and exits (`exitapproval`). The runner checks every one of these inside the TEE.

Chain configs the setups and image builds use are in [chains/](chains). The real-cloud test procedure of the generic images is [docs/setup-phase-cloud-test.md](docs/setup-phase-cloud-test.md).

Module path `github.com/lidofinance/tee-signer/governance`, with its own `go.mod`. It uses other modules of this repo only through their public packages (`scripts/check-imports.sh`).

Test it on its own from the repo root: `scripts/test-modules.sh governance`.
