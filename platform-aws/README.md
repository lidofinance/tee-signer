# platform-aws

> **Early proof of concept.** Provided as is, without any warranty or guarantee.
> Not audited. Not for production or mainnet funds. Interfaces and formats will
> change without notice.

AWS Nitro Enclaves: the platform (`nitro`: NSM attestation, KMS key release bound to PCRs, vsock), the mark log on S3 with Object Lock (`s3log`), and the parent instance side, which is not trusted: the host agent (`hostagent`, `cmd/hostagent`), the TCP to vsock forwarder (`forward`, `cmd/forwarder`) and the NTP relay (`udprelay`, `cmd/udprelay`).

Deploy files (Terraform, enclave image, KMS key policy, nitro-cli build): [deploy/](deploy/README.md).

Module path `github.com/lidofinance/tee-signer/platform-aws`, with its own `go.mod`. It uses other modules of this repo only through their public packages (`scripts/check-imports.sh`).

Test it on its own from the repo root: `scripts/test-modules.sh platform-aws`.
