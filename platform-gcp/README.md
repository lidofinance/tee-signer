# platform-gcp

> **Early proof of concept.** Provided as is, without any warranty or guarantee.
> Not audited. Not for production or mainnet funds. Interfaces and formats will
> change without notice.

GCP Confidential Space: the platform (`gcp`: attestation token, workload identity federation, Cloud KMS) and the mark log on a Cloud Storage bucket with Bucket Lock and object versioning (`gcslog`). The platform compiles and its tests pass, but it has not run in a Confidential Space VM yet.

Deploy files: [deploy/](deploy/README.md).

**A signer that holds a key alone (1 of 1) is unsafe on GCP and refused unless its setup accepts the risk:** Cloud KMS has no lock on the key release rule, so the project's owners can hand the sealing key, and with it the whole key, to any image. How to accept it, and what that means: [deploy/README.md](deploy/README.md#setup), "Setup".

Module path `github.com/lidofinance/tee-signer/platform-gcp`, with its own `go.mod`. It uses other modules of this repo only through their public packages (`scripts/check-imports.sh`).

Test it on its own from the repo root: `scripts/test-modules.sh platform-gcp`.
