# platform-azure

> **Pre-release.** Running on test networks; not yet for mainnet funds.
> Provided as is, without warranty. Interfaces and formats may change before
> the first release.

Azure confidential containers (SEV-SNP): the platform (`azure`: SNP report, MAA token, Key Vault secure key release) and the mark log in a Blob Storage container under a locked time-based retention policy (`azlog`).

Deploy files (image, ACI template, key release policy): [deploy/](deploy/README.md).

Module path `github.com/lidofinance/tee-signer/platform-azure`, with its own `go.mod`. It uses other modules of this repo only through their public packages (`scripts/check-imports.sh`).

Test it on its own from the repo root: `scripts/test-modules.sh platform-azure`.
