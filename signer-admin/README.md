# signer-admin

> **Early proof of concept.** Provided as is, without any warranty or guarantee.
> Not audited. Not for production or mainnet funds. Interfaces and formats will
> change without notice.

Operator tools, outside the TEE: `signer-admin` (drafts and signs setup updates and orders, `approver` and its agents), `cluster` (setups of a signer group), the admin client (`remote/admin`), and the key lifecycle tools: `handover-source`, `handover-target`, `share-import`, `setup-tool`, `identity-check` and `proof-check`. `fakerunner` is a test runner for the tools.

The runner checks everything these tools send; none of them holds a validator key.

`signer-admin setup` refuses a setup file whose only signer is on GCP: that signer would hold keys alone (1 of 1), which is unsafe there (Cloud KMS has no lock on the key release rule). `-allow-gcp-unsafe-single-key` accepts the risk in the setup of such a one-signer GCP file and prints a WARNING line (a file with more signers, or whose one signer is not on GCP, refuses the flag); so does the key `sealing_key_release.unsafe_single_key_accepted = true` in the signer's section, which `setup-tool encode` warns about too. On mainnet the setup also needs `sealing_key_release.no_lock_accepted = true`, or it is refused: without it the runner would not start. `signer-admin import-draft` drafts a 1 of 1 order to a GCP signer only with `-allow-gcp-unsafe-single-key`, and `show` prints the warning to each approver. Why, and what it means: [platform-gcp/deploy/README.md](../platform-gcp/deploy/README.md#setup), "Setup".

Module path `github.com/lidofinance/tee-signer/signer-admin`, with its own `go.mod`. It uses other modules of this repo only through their public packages (`scripts/check-imports.sh`).

Test it on its own from the repo root: `scripts/test-modules.sh signer-admin`.
