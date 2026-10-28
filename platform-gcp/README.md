# platform-gcp

> **Early proof of concept.** Provided as is, without any warranty or guarantee.
> Not audited. Not for production or mainnet funds. Interfaces and formats will
> change without notice.

GCP Confidential Space: the platform (`gcp`: attestation token, workload identity federation, Cloud KMS) and the mark log on a Cloud Storage bucket with Bucket Lock and object versioning (`gcslog`). The platform compiles and its tests pass, but it has not run in a Confidential Space VM yet.

Deploy files: [deploy/](deploy/README.md).

Module path `github.com/lidofinance/tee-signer/platform-gcp`, with its own `go.mod`. It uses other modules of this repo only through their public packages (`scripts/check-imports.sh`).

Test it on its own from the repo root: `scripts/test-modules.sh platform-gcp`.
