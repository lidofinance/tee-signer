# signer-admin

> **Early proof of concept.** Provided as is, without any warranty or guarantee.
> Not audited. Not for production or mainnet funds. Interfaces and formats will
> change without notice.

Operator tools, outside the TEE: `signer-admin` (drafts and signs setup updates and orders, `approver` and its agents), `cluster` (setups of a signer group), the admin client (`remote/admin`), and the key lifecycle tools: `handover-source`, `handover-target`, `share-import`, `setup-tool`, `identity-check` and `proof-check`. `fakerunner` is a test runner for the tools.

The runner checks everything these tools send; none of them holds a validator key.

Module path `github.com/lidofinance/tee-signer/signer-admin`, with its own `go.mod`. It uses other modules of this repo only through their public packages (`scripts/check-imports.sh`).

Test it on its own from the repo root: `scripts/test-modules.sh signer-admin`.
