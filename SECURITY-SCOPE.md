# Security scope

The audit scope of the first version is the code that runs inside the TEE
of the AWS runner: the release build `runner-aws` (build tags
`platform_aws,nts`), which runs in a Nitro enclave, the one tool that
handles a plaintext key share, with the attestation check it relies on,
and the code that shows approvers what they sign. The table lists that
code in priority order. Audit time goes to the top rows first.

`scripts/loc.sh scope` counts the code lines of each row and names any
file `runner-aws` links that no row covers. Rows 1 to 13 count the files
`runner-aws` links, row 14 the files `share-import` links that rows 1 to
13 do not, and row 15 its two files.

## In scope

| # | Code | Why |
|---|---|---|
| 1 | [signer-core](signer-core): the C core (`src/`, `include/`), its Go binding `core`, and `threshold` | Signs, and refuses slashable messages (EIP-3076 watermarks, policy). The core sets the restart floor itself on every validator load. What it assumes of its host and what it checks itself: [docs/boundary.md](signer-core/docs/boundary.md). |
| 2 | [markformat](markformat) | Encodes and decodes the stored watermark record (C codec and Go binding). The runner reads it back after a restart. |
| 3 | `tee-signer/attls` | The runner's mutual TLS and the client roles. Every byte a client sends comes through it. A leaf under an admin CA never gets the signing role. |
| 4 | [slashing-log](slashing-log) and `tee-signer/state` | The mark log, and the core's storage and clock hooks. They stop a restarted, rolled back or cloned runner from signing below its marks, and they read storage the host controls. |
| 5 | `slashing-log/statestore` and `platform-aws/s3log` | The copy of the runner's state outside the host, and the mark log on S3 with Object Lock and its own request signing. |
| 6 | `platform-aws/nitro` | Attestation, the KMS key release bound to the image measurements, and the key lock check with its strict key policy parse. |
| 7 | `tee-signer/server` | The protocol handler: signing, share import (one share, or a batch under one mark log record), setup updates, sealing, and the connection limits (`limits.go`). Only the admin role signs voluntary exits. |
| 8 | [trusted-time](trusted-time): `clock`, `nts` and the Rust NTS core (`rust/`) | The runner's clock. The NTS client parses answers from the network. |
| 9 | `governance/setupwire`, `governance/importorder` and `governance/runnerchain` | The setup, approver signatures, updates, time locks and import orders the runner checks, and the chains each build may run on. |
| 10 | [tee-signer](tee-signer), the root package, and the enclave image `platform-aws/deploy/enclave/Dockerfile` | Starts the runner: reads its flags and wires the platform, setup, clock, mark log and server. It refuses a setup for a chain its build may not run on; the mainnet build runs only on mainnet, by genesis fork version and genesis validators root. The Dockerfile is the measured image: its ENTRYPOINT flags, among them the coarse-time URLs, `-nts-wait` and `-nts-max-bound`, go into PCR0. `scripts/nitro-eif.sh` and `scripts/eif-check.sh` build and check the image reproducibly; the audit does not cover them. |
| 11 | [signer-protocol](signer-protocol) | Decodes every frame a client sends, and holds the build constants package. |
| 12 | [platform](platform): `platform` and `platform/setup` | The sealing and key release interface, the mainnet key rule, and the setup loading. |
| 13 | `platform-aws/hostagent/agentclient`, `platform-aws/hostagent/agentwire` and `platform-aws/udprelay/relayclient` | The enclave side of the links to the parent instance. They parse what the parent sends, which the enclave does not trust. |
| 14 | `signer-admin/cmd/share-import`; `signer-admin/remote/admin`, whose `ImportShareSealedWith` asks for the nonce and IDENTITY, checks the attestation, seals the share and sends it; `signer-protocol/remote`, which binds the runner's TLS key to the attested identity (TLS key hash, nonce in the user data); and in [attestation-verify](attestation-verify) the root package, `azureid` and `runnerclient` (with `verify` and `internal/optset`) | `share-import` runs on the operator machine, outside the TEE. It reads a plaintext key share and seals it to the runner's attested import key; the runner cannot check that step. It trusts the runner's key only after the attestation-verify check, so a wrong check could seal a plaintext share to a key that is not the runner's. The other packages it links are in rows 1 to 13. The GCP and dev verifiers (`gcp.go`, `runnerclient/verify/gcp_cs.go`, `runnerclient/verify/dev.go`) are not audited. |
| 15 | What the approver sees and signs: the printer of `governance/setuptext` (`format.go`) and the `show` and `sign` commands of `signer-admin` (`cmd/signer-admin/sign.go`) | Approver signatures allow images, client CAs, approver changes and import orders. `show` prints a draft, its diff against the active values and the hash of the signing message; `sign -expect-sha256` signs only the draft with that hash. If the printer drops or misprints a field, approvers sign what they did not see. `format.go` also holds the name tables the parser uses. `sign.go` also holds helpers that `draft` and `assemble` call; the small ones in `cluster.go` (`hex8`, `fullHex`, `when`, `fprintf`) are not counted. The parser (`parse.go`) and the other commands are not audited. |

### Time and key release

Both are in scope. The core trusts the clock its host gives it: the time
sets the slot rule, the clock horizon and the restart floor (see "Remaining
trust" in the boundary page). Time locks and certificate expiry use it too.
The key release decides which image gets the sealing key, and with it every
key share the runner holds.

The Rust core is the NTS implementation of the first version. The C NTS
core and the Go NTS client are drafts and not part of this scope. The
HTTPS-date signing clock is gone; the NTS clock still takes HTTPS Date
readings as a coarse check, in `trusted-time/clock` (row 8).

### The mainnet key lock

The deploy templates are examples, including the KMS key policy template in
`platform-aws/deploy`. The gate on mainnet is the runner itself: before it
makes or opens the sealing key, `platform-aws/nitro` reads the key policy,
and the runner does not start unless the policy is locked
(`platform.CheckKeyRule`). That check is in scope (rows 6 and 12).

The lock binds the account's own admins, not AWS. AWS documents that the
owner of a key no principal can manage must contact AWS Support to regain
access. So the lock holds against the account root user only as far as AWS
Support refuses such a request. The runner sees a changed policy only at
its next start. `platform-aws/deploy/README.md` lists the account controls
that cover this.

## Platform firmware

The cloud provider runs and patches the host firmware and microcode: the
Nitro system on AWS, and the SEV-SNP and TDX firmware on Azure and GCP. The
verifiers do not check a minimum TCB version. During a firmware
vulnerability, stop the affected runner until the provider patches it. With
a threshold across clouds, each runner holds one share. A minimum TCB check
for self-hosted runners is tracked in #113.

## Kept in the project, not audited

[platform-azure](platform-azure) and [platform-gcp](platform-gcp) stay in
the project and keep their runners, but this audit does not cover their
code. The Azure platform is kept on purpose.

## Out of scope

- The relays on the parent instance: `platform-aws/hostagent`,
  `platform-aws/udprelay` and `platform-aws/forward`, and their programs in
  `platform-aws/cmd` (`hostagent`, `udprelay`, `forwarder`).
- The rest of [attestation-verify](attestation-verify): the GCP and dev
  verifiers and the `cmd/attest-verify` tool.
- [signer-admin](signer-admin) and the other tools, except `share-import`
  (row 14) and `show` and `sign` with the setuptext printer (row 15), and
  [web3signer-api](web3signer-api).
- [tooling](tooling): monitoring helpers that run outside the TEE, such as
  the HEALTH exporter.
- The deploy files (`platform-*/deploy`), except the enclave Dockerfile
  (row 10).
- The build and release scripts (the release gate, `check-deps.sh`, the
  image scripts). They run in CI.
- Third-party code: the vendored blst and the Rust crates, pinned by
  version and hash.
- Tests and test helpers: [tests](tests), [devkit](devkit), `_test.go`
  files, `platform/dev`, `signer-core/software`, `slashing-log/logtest`,
  `slashing-log/wormfake`, `trusted-time/nts/ntstest`,
  `signer-admin/fakerunner`.
- The debug builds (tag `debugimport`). They take plaintext imports and are
  not release images.

## Removed from main

Main no longer has these, so they are not in scope: the handover between
runners (draft #98), exit approvals (draft #99; the runner signs a
voluntary exit for the admin role only), the DynamoDB clone guard (the mark
log replaced it), the HTTPS-date signing clock, the platform clocks
(`token-iat`, `maa-iat`, `nsm`), the device source alarm and the
`peer_attestation_hosts` setup field.

## Changing the scope

The scope changes only through a PR that changes this file, with the
reason. Code that `runner-aws` starts to link is in scope until such a PR
says otherwise.
