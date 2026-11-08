# platform-gcp

> **Pre-release.** Running on test networks; not yet for mainnet funds.
> Provided as is, without warranty. Interfaces and formats may change before
> the first release.

GCP Confidential Space: the platform (`gcp`: attestation token, workload identity federation, Cloud KMS) and the mark log on a Cloud Storage bucket with Bucket Lock and object versioning (`gcslog`). It ran in Confidential Space VMs on AMD SEV and on Intel TDX (`c3-standard-4`).

Deploy files: [deploy/](deploy/README.md).

**A signer that holds a key alone (1 of 1) is unsafe on GCP and refused unless its setup accepts the risk:** Cloud KMS has no lock on the key release rule, so anyone with IAM or KMS admin rights on the project, the pool or the key (folder and organization admins included) can rebind it and decrypt the sealing key outside any TEE, with no image to run: the sealed key in the state bucket, and with it the whole validator key, is then theirs. How to accept it, and what that means: [deploy/README.md](deploy/README.md#setup), "Setup".

Module path `github.com/lidofinance/tee-signer/platform-gcp`, with its own `go.mod`. It uses other modules of this repo only through their public packages (`scripts/check-imports.sh`).

Test it on its own from the repo root: `scripts/test-modules.sh platform-gcp`.
