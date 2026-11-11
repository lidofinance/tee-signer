# governance

> **Pre-release.** Running on test networks; not yet for mainnet funds.
> Provided as is, without warranty. Interfaces and formats may change before
> the first release.

The setup and the approver rules: the setup format, approver sets, signed updates, time locks and signature contexts (`setupwire`), the chain of a runner's build (`runnerchain`), and the approved orders for share import (`importorder`). The runner checks every one of these inside the TEE. The human form of setups and updates (`setuptext`), the text that operators write and approvers read, is for the operator tools only: no runner links it (`scripts/check-deps.sh`, `scripts/check-imports.sh`).

Chain configs the setups and image builds use are in [chains/](chains). The real-cloud test procedure of the generic images is [docs/setup-phase-cloud-test.md](docs/setup-phase-cloud-test.md).

## Setup format changes

A runner image reads one setup format (`setupwire.FormatVersion`), now 6. Format 6 moved the deposit fields into `deposit_policy` (with a list of withdrawal credentials), added `time_policy`, `deposit_policy` and `exit_policy` to the locked group, `revoked_client_certs` and `time_servers` to the open group, and `project_number` to the GCP key release. CONFIG_UPDATE went to version 2, and the change rules (`setupwire.Update.Decide`, changes.go) pick a fast path or the wait per changed field. Format 5 had added `sealing_key_release.kms_key_creation_date`. Each format change means every setup is encoded again and approved again. Steps: [docs/upgrade.md](../docs/upgrade.md#a-new-setup-format), "A new setup format".

Module path `github.com/lidofinance/tee-signer/governance`, with its own `go.mod`. It uses other modules of this repo only through their public packages (`scripts/check-imports.sh`).

Test it on its own from the repo root: `scripts/test-modules.sh governance`.
