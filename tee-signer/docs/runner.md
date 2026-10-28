# The runner

The runner is the program inside the TEE. It holds one share of each
validator key of a threshold cluster, applies EIP-3076 slashing protection
and the signing policy, and returns partial signatures. Signing and
slashing protection are the portable C signer core (`signer-core`,
`signer-core/README.md`); the runner wraps it in Go with one platform per
cloud: AWS Nitro Enclaves, GCP Confidential Space and Azure confidential
containers, plus a dev platform for local tests. Clients reach it over the
wire protocol (`signer-protocol/docs/protocol.md`) inside mutual TLS bound to
its attested identity.

## Build flavours and binaries

### One runner per cloud

The platforms are build-time plugins. `tee-signer/main.go` imports no
platform package. Each platform registers itself in a file guarded by a
build tag (`tee-signer/platform_aws.go` and its siblings), and a binary holds
the platforms of the tags it was built with:

| Tag | `-platform` | What else the tag brings |
| --- | --- | --- |
| `platform_aws` | `nitro` | the AWS SDK (KMS, request signing), the NSM and CBOR code, vsock (`signer-protocol/transport/vsock.go`), the DynamoDB record store (`tee-signer/record/dynamodb.go`), the host agent client |
| `platform_azure` | `azure` | nothing outside the standard library |
| `platform_gcp` | `gcp` | nothing outside the standard library |
| `platform_dev` | `dev` | nothing outside the standard library |
| `nts` | | the NTS clock (`trusted-time`), which the cloud runners use |
| `debugimport` | | plaintext `IMPORT_SHARE`, `-allow-import`, and the fake-hardware options of the Azure and Nitro tests. Never in an image. |
| `testnet` | | the testnet flavour (below) |

Every binary also holds the embedded root certificates
(`golang.org/x/crypto/x509roots/fallback`), because the images have no CA
bundle.

`scripts/build-runner.sh` builds these binaries for x86_64 and aarch64:

| Binary | Tags | Used for |
| --- | --- | --- |
| `runner-azure` | `platform_azure,nts` | the Azure image (`platform-azure/deploy/build-image.sh`) |
| `runner-aws` | `platform_aws,nts` | the Nitro EIF (`scripts/nitro-eif.sh`) |
| `runner-gcp` | `platform_gcp,nts` | the GCP image (`platform-gcp/deploy/build-image.sh`) |
| `runner-dev` | `platform_dev` | local tests that need no plaintext import |
| `runner-dev-debugimport` | `platform_dev,debugimport` | local tests that load shares in plain text |
| `runner-azure-debugimport` | `platform_azure,debugimport,nts` | tests: the Azure runner with a fake SNP report and metadata service |
| `runner-aws-debugimport` | `platform_aws,platform_dev,debugimport,nts` | tests: the Nitro runner with a fake NSM; it has the dev platform too, for the vsock tests |
| `runner-gcp-debugimport` | `platform_gcp,debugimport,nts` | tests: the GCP runner with STS, IAM credentials and Cloud KMS at a test URL |

A binary refuses a platform it does not hold and names the tag that builds
it. A binary built with no platform tag refuses to start. Without
`-platform`, the only platform of the binary runs (dev, if it has several).

`scripts/check-deps.sh` fails if a build links a package of another cloud,
or a third-party module that is not on the allow list of its own cloud. In
the Azure, GCP and dev builds that list holds the embedded roots only. It
also reads the binaries (`go version -m`): their tags and linked modules
must be the expected ones. `build-runner.sh` runs it.

### Default and testnet flavour

`IMAGE_FLAVOR=default` (the default) or `IMAGE_FLAVOR=testnet` picks the
flavour of every runner and image build. A testnet build has the `testnet`
tag, governance time locks in minutes, the version suffix `+testnet` in
HEALTH, a TLS certificate name of its own (`governance/flavor`), and the
`-allow-unlisted-image` override of the image check. Clients refuse a
testnet runner unless their settings allow it. The binaries of a testnet
build carry `-testnet` in their names.

The release gate (`scripts/release-gate.sh`) checks every default-flavour
binary and its dependencies against a forbid list: no approver reset, no
testnet role or override, no debug or test-only code. `build-runner.sh`
runs it on every binary, and `scripts/test.sh` runs its self-test.

`SIGNER_BUILD_OVERLAY_DIR` names a folder outside this repo whose `hooks.sh`
adds files to a testnet build; a default build refuses it.

### Plaintext import

Plaintext share import (`IMPORT_SHARE`, `-allow-import`) exists only in the
debug builds (`debugimport`). The release builds, which every image uses,
do not compile that code: they have no `-allow-import` flag and answer
`IMPORT_SHARE` as an unknown message type. Shares reach a release runner
sealed to its attested key (see "Sealed share import") or through key
generation.

## Build and test

Ubuntu 22.04 or 24.04, x86_64 or arm64, Go 1.27.3 or newer (for
`crypto/hpke`), Docker for the image builds. `make help` lists the targets.
From the repo root:

```sh
make deps          # apt: build tools, cross compilers, qemu-user
make build         # every runner binary and the host tools, with the release gate and dependency check
make test          # build and every local test (scripts/test.sh)
make test-modules  # gofmt, vet and unit tests of every Go module
make e2e           # end-to-end tests against the built runners
make release-gate  # the release gate: self-test, tree check, every runner build
```

| Script | Does |
| --- | --- |
| `deps.sh` | apt: build tools, cross gcc for the other arch, qemu-user, qemu-user-static (for the arm64 EIF), openssl, jq. Checks Go and Docker. |
| `fetch.sh` | blst (and aws-nitro-enclaves-cli for the EIF) into `third_party/`, pinned by commit |
| `build-core.sh` | copies signer-core's `include/` and `src/` into `build/core-src/`, builds `libsigner_core.a` and `libblst.a` per arch |
| `build-runner.sh` | the static runners above and the Nitro parent-side programs, checked with `file`, the dependency check and the release gate |
| `check-deps.sh` | the dependency check (above) |
| `check-imports.sh` | module boundaries: a module uses another only through its public packages |
| `check-forbidden.sh` | names and markers no file of the tree may hold |
| `test.sh` | every local test: guards, release gate, chains, module tests, e2e on the native and the arm64 runners, signer-core's suites, fuzz replay |
| `test-modules.sh` | gofmt, vet and unit tests of every Go module, under the race detector |
| `upstream-tests.sh` | signer-core's own suites (unit, ssz_static, bls/sign, EIP-3076) against the library `build-core.sh` built |
| `chain-test.sh` | the tests of `governance/chains/chain.sh` and of the chain checks of the image builds and the deploy steps, offline |
| `nitro-cli-image.sh` | nitro-cli built from source inside Docker, with `platform-aws/deploy/nitro-cli/target-arch.patch` applied |
| `nitro-eif.sh` | the generic enclave image from `runner-aws`, for x86_64 or, through qemu, arm64 (`ARCH=aarch64`): `nitro-cli build-enclave` twice, PCR check, rendered KMS policy, then `eif-check.sh` |
| `eif-check.sh` | reads an EIF: arch flag, kernel header, the runner and its inputs in the ramdisk, PCR0/1/2 recomputed without nitro-cli |
| `generic-images.sh` | `build`: the three generic images (Nitro arm64, Azure with its CCE policy, GCP) and their measurements in `build/generic/fingerprints.txt`; `check`: a build against a recorded list |
| `make-test-ca.sh` | test PKI for client certificates: root, intermediate, one short-lived client certificate per role |
| `kms-policy.sh` | PCR3 for a parent role ARN, KMS policy with PCR0/1/2/3, self-test against AWS's PCR3 example |
| `tf-validate.sh` | `terraform validate` of `platform-aws/deploy/main.tf` in the pinned Terraform image |
| `runner-size.sh` | a table of the Go code each runner build links and its size |

`third_party/`, `build/` and `logs/` are git-ignored.

## Configuration

```sh
runner -platform dev|nitro|gcp|azure -setup platform|file:PATH -listen tcp:...,unix:...,vsock:any:7100 \
       -record none [-clock ...] [-persist-repeat-root] [-state-dir DIR]
runner -platform dev -config chain.json -listen ... [-tls-client-ca ca.pem] [-mark-store ...] \
       [-record none|file:DIR|dynamodb:table=T,region=R -record-key NODE]
```

### Setup

With `-setup` the runner reads the signer's setup before it builds the
platform, decodes it with `governance/setupwire`, refuses one for another
platform, and takes from it the chain config, the client CA, `max_keys`,
the mark log (required) and state copy, the signer name and the platform
options. The images run this way; they are the same for every operator.
The setup format is in `attestation-verify/docs/attestation-statement.md`.

| Platform | `-setup platform` reads | Deploy step |
| --- | --- | --- |
| nitro | SETUP from the host agent, vsock 3:7101, before any KMS call | `platform-aws/deploy/parent-run.sh` (`hostagent -setup FILE`) |
| azure | `SIGNER_SETUP`, base64, a wildcard rule of the CCE policy | `platform-azure/deploy/deploy.sh group-deploy` (`signerSetup`) |
| gcp | the instance metadata attribute `signer-setup`, base64 | `platform-gcp/deploy/deploy.sh vm-create` |
| dev | `SIGNER_SETUP`, or `-setup file:PATH` | local runners |

- IDENTITY carries setup_hash, the mark log's config state per group and
  the approver set hash; ATTEST and HEALTH carry them too
  (`signer-protocol/docs/protocol.md`). The mark log, the state copy, the
  stored shares and every key-release call are bound to setup_hash, so a
  runner with another setup opens nothing of this one.
- On Nitro the proxy routes follow from the setup's region and mark bucket
  over a fixed vsock port map, and `{region}` in the coarse-time URLs takes
  the setup's region.
- With `-setup` the runner refuses the flags the setup replaces (`-config`,
  `-tls-client-ca`, `-max-validators`, `-mark-store`, `-mark-signer`,
  `-state-store`, `-floor-margin`), the recovery flags (`-mark-create`,
  `-state-create`, `-record-create`), the DynamoDB guard, and a
  `-platform-opt` the setup sets.
- A release build hands its shares over under an approver-signed handover
  order (HANDOVER_ORDER, HANDOVER) and takes them as a handover target
  (IMPORT_HANDOVER; `signer-protocol/docs/protocol.md`, "Handover"). A
  runner without a setup, or a debug build, answers the three UNSUPPORTED.
- `signer-admin` makes setups from the human form and checks them;
  `signer-admin/cmd/setup-tool` checks a setup against a platform and a
  chain and prints a chain config's lines.
- `signer-admin/cmd/handover-source` and `signer-admin/cmd/handover-target`
  are the two halves of the handover tool. `handover-target identity`
  reserves the target for the order, reads and checks its IDENTITY and
  writes it with the published part of its setup; `handover-source` sends
  HANDOVER to the source and writes the sealed pages; `handover-target
  import` passes them on, a few requests at a time, skipping what the
  target holds. `TestE2EHandoverGate` (tests/e2e) runs both halves across
  three images.

Without `-setup` the runner takes its values from flags. The e2e tests and
local runners start it that way.

### Image check

With a setup the runner checks its own image against the setup's
`allowed_image_measurements` in force (`signer-protocol/docs/protocol.md`,
"Image check"). It takes its image from the evidence its key release sent
(GCP image digest, Azure CCE policy hash, Nitro PCR0 to PCR2), runs the
check before any share is unsealed, and again on every request that signs,
hands over or imports. An image the list does not name stays up with its
shares sealed and answers HEALTH (`image`), keys, attestation and
CONFIG_UPDATE only. A default build cannot turn the check off; a testnet
build has `-allow-unlisted-image`.

### Start-up refusals

Before the platform starts, the runner refuses: `-allow-import` on any
platform but `dev` (debug build); a TCP listener without a client CA on
`gcp` or `azure`; a TCP or vsock listener without one on `nitro`; a plain
vsock listener in a release build; a CA file that holds a private key; no
`-record` choice on a cloud platform (`none` must be explicit); a floor
margin below `max_epochs_ahead + 1`; a platform the binary was not built
with; and a binary built with no platform tag.

Every cloud image bakes its flags into the measured image. On Azure the
flags are the container's `command`, which the CCE policy measures. The host
cannot pass arguments to an enclave, and must not be able to: a host that
chose the KMS key could have shares sealed under a key it controls.

### Chains

The images hold no chain: the chain config is in each signer's setup, and
the runner puts setup_hash, which covers it, in its attested identity. The
deploy steps name the chain in `CHAIN` and refuse a setup of another chain
(`setup-tool check -chain`).

| Chain | `CHAIN` | Chain config |
| --- | --- | --- |
| Hoodi, the public testnet | `hoodi` | `governance/chains/hoodi.json` |
| a local test chain | `devnet` | `CHAIN_JSON` from `platform-azure/deploy/chain-from-devnet.sh` |
| the test chain of the tests | `testnet` | `governance/chains/chain.testnet.json` |

A setup holds one fork per epoch. Where a chain config lists several forks
at one epoch, the last is the one in force, and the setup holds that one
(`setup-tool chain-lines`).

`governance/chains/chain.sh` does the chain work:

- `build hoodi` writes `hoodi.json` from `hoodi.source.json`, a pinned copy
  of the values in Hoodi's published config (eth-clients/hoodi at commit
  `ef8998901c1350f41a0bcc0a2a8d4baad973abcf`): fork versions and epochs,
  genesis time, genesis validators root, slot timing, deposit chain id and
  `gloas_fork_epoch`, which the runner needs to sign the Gloas kinds 6 to 8.
  The signer policy fields come from the `policy` object of the same file,
  or from `FEE_RECIPIENT`, `GAS_LIMIT_MIN`, `GAS_LIMIT_MAX`,
  `EXIT_ALLOWLIST`, `MAX_EPOCHS_AHEAD` and `COMMIT_AHEAD`. The committed file
  allows no exit.
- `check-source hoodi config.yaml genesis_validators_root.txt` compares the
  source file with the two files of the chain's repo, fetched by you, and
  fails on a difference or on a fork the source does not list. Run it again
  when the chain schedules a fork.
- `check-beacon hoodi [URL]` compares `hoodi.json` with a beacon node
  (genesis, spec, fork schedule). The URL goes to curl on stdin and is
  printed as scheme and host only.
- `identify FILE` and `verify NAME FILE` tell the chain of a chain config.

The image builds take no chain and refuse `CHAIN` and `CHAIN_JSON`. The
deploy steps that hand over a setup (`platform-azure/deploy/deploy.sh
group-deploy`, `platform-gcp/deploy/deploy.sh vm-create`) need `CHAIN`; on
AWS run `setup-tool check -platform nitro -chain` before
`platform-aws/deploy/parent-run.sh`.

## Backend interface

```go
type Backend interface {
    PublicKeys(ctx) ([]ValidatorKey, error)
    Sign(ctx, SignRequest) (Signature, error)          // *RefusedError on slashing/policy refusal
    Attest(ctx, nonce []byte) (*Attestation, error)    // platform document binding nonce + runner identity
    Health(ctx) (*Health, error)
    ImportShare(ctx, ImportShareRequest) (ValidatorKey, error) // plaintext share: debug runner build, dev only
    Close() error
}
```

`remote.Client` (`signer-protocol/remote`) adds `Identity(ctx, nonce)` (the
runner's per-boot import key and TLS key, attested), `ImportShareSealed`
and the options `WithTLS` and `WithTLSKeyPin`. Callers outside tests build
their client with `attestation-verify/runnerclient`, not with these options
directly.

`SignRequest.Message` is one of `*AttestationData`, `*BeaconBlockHeader`,
`*VoluntaryExit`, `*ValidatorRegistration`, or `*RootMessage` (Web3Signer
RANDAO_REVEAL, AGGREGATION_SLOT, AGGREGATE_AND_PROOF, SYNC_COMMITTEE_*
types as object root and domain). For root messages the runner recomputes
the domain from its own chain config and refuses a mismatch, and the C
core accepts only the six non-slashable domain types, so this path cannot
sign a block, vote, exit or registration. Every other message comes with
`SignRequest.Domain`, the domain the caller computed; the runner refuses it
with `DOMAIN_MISMATCH` when its chain config and fork schedule give the
message another one (`signer-protocol/docs/protocol.md`, "SIGN kinds").

Aggregates and contributions are the exception to "the signer checks what
it signs". They reach the runner as a root, so the runner never sees the
object and each such signature is unverified. The same holds for the bare
roots of a selection proof, a sync committee message and a sync selection
proof (root types 2, 4, 5); the typed kinds carry those whole. The setup's
`allow_unverified_nonslashable_signing` (the chain config's
`allow_unverified_nonslashable` without a setup) decides. Off, the runner
signs no aggregate or contribution at all. On, it signs them after the
domain check and the clock horizon, logs each one ("signed unverified",
with root type, epoch and key) and counts it in
`Health.unverified_signatures`; `Health.allow_unverified_nonslashable`
reports the switch. The risk: anyone holding a runner client certificate
can get aggregate and contribution signatures on any root. These cannot
slash and move no funds; a bad aggregate under the validator's name can
cost peer score. RANDAO reveals, selection proofs and sync committee
messages are not affected by the switch.

Two implementations: `remote.New("tcp:host:port" | "unix:/path" |
"vsock:cid:port")` and `software.New(cfg, ...)` (`signer-core/software`,
dev only). `remote` is pure Go; `software` and `signer-core/core` use cgo
and need `scripts/build-core.sh` first. Both run the same C core, so
refusals are identical. Errors carry the core's status code
(`SC_ERR_SLASH_TARGET`, `SC_ERR_POLICY_EXIT`, ...), see
`signer-protocol/errors.go`.

## Platforms

| | Attestation | Sealing | Store | Clock |
| --- | --- | --- | --- | --- |
| dev | unsigned JSON | AES-GCM, fixed public key | files | system (and a test offset) |
| nitro | NSM document via `/dev/nsm` | KMS data key with `Recipient` (PCR policy), CMS unwrap | host agent over vsock | NTS (NTS-KE via vsock-proxy, NTP via `udprelay`); also system, `nsm`, https-date |
| gcp | launcher token, `eat_nonce`, audience `signer-runner-identity` (never the STS one) | Cloud KMS through Workload Identity Federation | files on a disk | NTS; also system, `token-iat`, https-date |
| azure | MAA token over an SNP report the runner requests itself, runtime data the JSON object `backend.MAARuntimeData` | Key Vault release of an RSA key in process, with a fresh wrapping key and the MAA token as target | files | NTS; also system, `maa-iat`, https-date |

These are the `Sealer`, `Store`, `Clock` and `Attester` of `platform`. The
Azure platform talks to the SNP device, MAA and Key Vault itself, in
process, with the standard library only, and nothing but its own port
listens in the group (`platform-azure/deploy/README.md`).

## Provers and verifiers

Attestation has two halves that have to fit. A prover in the TEE makes the
proof. A verifier on the client side checks it. The signer core and the
client's signing code know neither: they use the backend interface and get
partial signatures. A new platform is one prover plus one verifier.

### The contract

- Prove one statement: this measured code, on this kind of hardware, holds
  this TLS key and this HPKE import key. The runner answers IDENTITY with
  its setup state, its per-boot import key and the hash of its TLS key. The
  prover puts `backend.IdentityUserData(nonce, identity)`, a SHA-256 over
  those and the client's nonce, into the platform document. The verifier
  recomputes that value from the identity, checks the document against the
  platform's root, the expected measurement, the debug flag and the age,
  and `attestation-verify/runnerclient` accepts the connection only if the
  TLS key of the handshake is the key the verified identity names.
- Seal to the device. The prover's `Sealer` protects the runner's data key
  so that only the same measured code on the same platform can open it.
  Shares arrive sealed (HPKE) to the import key in the verified identity.
- Give a trusted clock, or say that it has none. The restart rule needs
  time. Where the host could move the platform clock, the runner uses the
  NTS clock (`trusted-time/docs/nts.md`): several NTS operators, a quorum
  with an error bound, signing refused above the bound. A quorum of HTTPS
  `Date` headers (`-clock https-date`) is the other option.
- Treat the store as hostile. The host can read it, delete it and roll it
  back.

### Verifiers

`attestation-verify/runnerclient` builds the client of every tool that
talks to a runner. The setting `attestation.verifier` names the verifier;
there is no default and no way to skip the check.

| Verifier | What it checks |
| --- | --- |
| `dev` | the unsigned document binds nonce and identity; local runners only |
| `azure-maa` | MAA token: provider key set, issuer, hostdata (CCE policy hash), runtime data, debug flag, VMPL, compliance status |
| `aws-nitro` | `attestation-verify/nitro.go`: NSM document, chain to the pinned AWS Nitro root, PCR0 to PCR2 (more optional), debug mode, nonce, user data |
| `gcp-cs` | `attestation-verify/gcp.go`: Confidential Space token, issuer key set (or a pinned one), audience, image digest, hardware model, debug status, nonce. For a three-cloud cluster (Azure on AMD SEV-SNP, AWS Nitro, GCP) set `gcp_hwmodels` to `GCP_INTEL_TDX` only, so one chip family never holds two shares |

The settings of each verifier are in `attestation-verify/README.md`. The
network entry of an AWS signer is a forwarder on the parent instance
(`platform-aws/cmd/forwarder`, plain bytes, no TLS), which is untrusted like
any network part (`platform-aws/deploy/README.md`, "Network entry").

### Adding a platform

1. The prover: a module `platform-<name>` with `New(platform.Options)`
   that fills `Sealer`, `Store`, `Clock` and `Attester`, registered in a
   file `tee-signer/platform_<name>.go` that a build tag guards (copy
   `platform_azure.go`), with its start-up refusals. Add the build to
   `RUNNER_BINS` and `runner_tags` in `scripts/common.sh`, and its package
   and the third-party modules it may use to `scripts/check-deps.sh`.
2. The verifier: code in `attestation-verify` that checks the platform
   document for an identity, and its name in
   `attestation-verify/runnerclient` (settings, config checks, the call).
3. Tests like the ones of `azure-maa`: config refusals, a fake provider,
   and an end-to-end test with the real runner binary.

The wire protocol does not change.

## Restart rule and the clock

With trusted time a node needs no rollback-proof storage for the restart
case, because on every restart it refuses anything at or below
`current_epoch + 1`.

`tee-signer/state`. When a validator is loaded (at start, or on import),
the runner reads the clock epoch `E` and folds this watermark into the
core's slashing state: block slots up to the last slot of `E+m`,
attestation targets `<= E+m`, and sources `< E+m`, where the margin `m` is
`max_epochs_ahead + 1` (2 with the default policy). The runner refuses to
start with a smaller margin. Persisted commit-ahead marks, the clone
guard's record and the mark log add further floors; the loaded watermark
is the field-wise maximum. Every floor bounds sources as well as targets.

Why the margin is `max_epochs_ahead + 1`: the core signs up to
`clock_epoch + max_epochs_ahead`, so anything below that lets a vote
signed ahead escape the floor, and the extra epoch absorbs a restart
reading that is up to one epoch behind the last reading before the
restart. `TestFloorBrokenBySubSecondSkewAtRestart` shows the failure with
`m = max_epochs_ahead`. Why the floor bounds sources: without it, a vote
signed before a restart can be surrounded by a later vote with a lower
source.

The rule trusts the clock in both directions: a host that moves the clock
forward, collects a vote for a future target and restarts the runner with
the right time gets a second vote (`TestE2EClockSkewBreaksFloor`). The
system clock of none of the three TEEs is trusted time, so the cloud
runners use the NTS clock, and the mark log covers the rollback cases the
floor cannot.

The anchored clocks (`-clock https-date`, and the platform clocks `nsm`,
`maa-iat` and `token-iat`) read every 15 s (`-clock-interval`) and add the
local monotonic time since the last reading, at most 75 s
(`-clock-max-advance`, default 5 intervals). They never return a lower
time than before. A host that speeds up the local timer gains at most
75 s per reading, far below one epoch and the floor margin, and the next
reading ends it. At the fifth missed reading in a row the clock fails and
the signer refuses (`-clock-max-age`, default 5 intervals), so a blocked
network stops signing instead of freezing time.

Cost per restart: votes for targets `E`, `E+1` and `E+2` and proposals in
those epochs are refused. Non-slashable types are not affected by the
floor.

## Clone guard

`tee-signer/record`, `-record` and `-record-key`. A host that starts two
runners from one image and feeds both the same sealed share would get two
independent slashing states. The guard is an external record per node
that only moves forward through conditional writes on a version number:

- At start the runner reads the record and writes `version+1` with a
  random owner ID (claim). The epoch in the record is the highest epoch
  the previous owner may have signed for; the runner refuses everything
  at or below it.
- Before the core raises a commit-ahead watermark past the epoch the
  record covers, the runner writes `version+1` with the new epoch. If the
  version moved, another instance has claimed the record, and this runner
  refuses every new slashable signature (`SC_ERR_STORAGE`). If the store
  is unreachable, the runner refuses to sign until it is back.
- Values are sealed with the platform sealer and bound to key and
  version. A missing record on a node that holds shares stops the start
  (`-record-create` overrides).

Stores: `file:DIR` (flock, for tests on one host) and
`dynamodb:table=...,region=...` (conditional `PutItem`). The mark log does
the clone guard's job, so the images run `-record none` (explicit; the
runner refuses a cloud start without a choice).

## Mark log

`slashing-log` (`slashing-log/docs/marklog.md`). The core keeps one device
mark for all validators, and every raise of it is a signed, chained record
in an append-only log that nobody can rewrite: S3 with Object Lock in
compliance mode, Cloud Storage with a locked retention policy, Blob Storage
with a locked time-based retention policy. The runner writes the record
before it signs past the old mark, raises the mark for the next epoch
ahead of time (`-mark-raise-slot`), reads the newest valid record at start
and refuses to start when it cannot. The restart floor then keeps only its
target and block bounds, so a restart while the chain does not finalize
loses only the floor's margin. The clients of the three stores are our
own (SigV4 for S3, the JSON API for GCS, the Blob REST API for Azure), each
in its own platform build.

## State copy and handover

`slashing-log/statestore` (`slashing-log/docs/durable-state.md`). On Azure
and GCP the runner's local state is gone after a restart without its disk,
and a sealed share has no other copy. The runner keeps the sealed shares
and the wrapped sealing key in the object store as well (encrypted under
the platform's key release, under `state/` in the mark log's locked
bucket) and restores them before it claims the log. HANDOVER under an
approvers' order moves the shares and the mark from the runner of one image
to the runner of the next, whose new key release cannot open the old state
(`signer-protocol/docs/protocol.md`, "Handover").

## Sealed share import

`signer-protocol/sealedimport`, messages IDENTITY and IMPORT_SHARE_SEALED.
The runner makes an HPKE key pair at start (KEM ML-KEM-768 + X25519, the
X-Wing hybrid, from Go's standard `crypto/hpke`; KDF HKDF-SHA256; AEAD
AES-256-GCM) and binds the public key into its attestation user data. The
dealer checks the document, seals the share with the request header as
associated data, and sends it. With a setup, an import needs an import
order that k approvers in force signed. `signer-admin/cmd/share-import`
is the dealer tool (share from a file or stdin, never argv). It checks the
identity with the verifier you name: `-verifier dev`, `-verifier azure-maa
-maa-host HOST -cce-policy-sha256 HASH`, `-verifier aws-nitro -nitro-pcr
0=HEX -nitro-pcr 1=HEX -nitro-pcr 2=HEX` or `-verifier gcp-cs
-gcp-image-digest sha256:HEX -gcp-audience NAME -gcp-hwmodel MODEL`.

## Mutual TLS

The client CA (from the setup, or `-tls-client-ca`) wraps every TCP and
vsock listener in TLS 1.3 with a required client certificate from that CA.
The validity dates of the client certificate are checked against the
runner's trusted clock, not the system clock, so client certificates can be
short-lived: the image pins the CA only. The runner's certificate is
self-signed with a key made in the TEE at start; its SPKI hash is part of
the attested identity, and `remote.WithTLS` checks, right after the
handshake, that the attested identity names the key it just saw. A relay
with its own certificate and a valid client certificate is refused
(`TestE2EMutualTLS`). On AWS the parent instance is not trusted and
forwards bytes into the enclave, so TLS ends inside the enclave
(`platform-aws/deploy/README.md`, "Network entry", which also has the
suggested root and intermediate pattern for client certificates). Client
roles (signing, attest-only, admin) come from the certificate chain
(`signer-protocol/docs/protocol.md`).

## Exact repeats

The C core decides (`sc_repeat_roots`): an attestation or block whose
signing root equals the validator's last one of that kind is signed again
without the slashing check (same message, same signing root, deterministic
BLS, so the same signature). Policy checks still run. Other messages at
that target or slot are still refused, and so is a repeat of an older
message.

`-persist-repeat-root` (off by default) seals the validator's last roots
(AAD `signer-repeat-roots-v1|<pubkey>`) before each new attestation or
block and writes them to the platform store, so a validator client retry
after a restart signs. Off, the roots live in RAM and the floor refuses
the repeat after a restart. Off is the default because each attestation
would otherwise wait for the write of its roots; safety does not need them.

## Building and verifying an image

Each cloud image is built twice and the two results must be equal; the
measurement then goes into the setup's `allowed_image_measurements` and
the key-release policy.

- Nitro: `scripts/nitro-eif.sh` builds the EIF without Nitro hardware
  (nitro-cli from source in Docker). PCR0/1/2 repeat across rebuilds with
  `SOURCE_DATE_EPOCH=0`, `rewrite-timestamp=true` and no provenance
  attestations in the image build. An arm64 (Graviton) EIF builds on x86_64
  through qemu-user (`ARCH=aarch64`, `platform-aws/deploy/README.md`).
  `scripts/eif-check.sh` recomputes the PCRs from the EIF.
  `scripts/kms-policy.sh` renders the KMS policy with PCR0 to PCR3.
- Azure: `platform-azure/deploy/build-image.sh` builds the image and
  computes its CCE policy hash; the image digest does not depend on the
  builder's umask (`platform-azure/deploy/README.md`).
- GCP: `platform-gcp/deploy/build-image.sh` builds the image; the WIF
  provider condition pins its digest (`platform-gcp/deploy/README.md`).
- `scripts/generic-images.sh build` builds all three and writes their
  measurements; `check` compares a build with a recorded list.

A verifier recomputes the same measurements from the same commit and
compares them with the setup's list and the key-release policy before it
approves an update that allows the image.

## Operating rules

- An image starts with its shares sealed and signs nothing while its own
  measurement is not on the signer's `allowed_image_measurements` in force.
  Before a new image runs on a signer, that list must name it: a locked
  update, or a new setup that lists it and takes the shares by handover.
- A cloud start needs an explicit `-record` choice; the images run
  `-record none` with the mark log.
- Release images have no plaintext import: shares go in sealed, by
  handover.
- Keep the mark log bucket's retention lock; the runner refuses to start
  when it cannot read its newest valid record.
- Clients must name a verifier and its expected values; there is no
  setting that skips the attestation check.

## Sources

- KMS `Decrypt` `Recipient` and `CiphertextForRecipient`: https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html
- KMS PCR condition keys, deny without attestation: https://docs.aws.amazon.com/kms/latest/developerguide/conditions-nitro-enclave.html
- CMS format of `CiphertextForRecipient` (AWS C SDK parser): https://github.com/aws/aws-nitro-enclaves-sdk-c/blob/main/source/cms.c
- Confidential Space token claims (`eat_nonce`, `iat`): https://docs.cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims
- Launch policy labels: https://docs.cloud.google.com/confidential-computing/confidential-space/docs/reference/launch-policies
- WIF provider and attribute condition: https://codelabs.developers.google.com/codelabs/confidential-space
- VM create flags: https://docs.cloud.google.com/confidential-computing/confidential-space/docs/deploy-workloads
- Secure key release protocol, which `platform-azure/azure` implements in process: https://github.com/microsoft/confidential-sidecar-containers/blob/main/cmd/skr/README.md
- SKR release policy claims: https://github.com/microsoft/confidential-sidecar-containers/blob/main/examples/skr/aci/README.md
- `az keyvault key create --exportable --policy --immutable`: https://learn.microsoft.com/en-us/cli/azure/keyvault/key?view=azure-cli-latest
- ACI confidential ARM fields: https://learn.microsoft.com/en-us/azure/container-instances/container-instances-tutorial-deploy-confidential-containers-cce-arm
- vsock-proxy and allocator formats: the aws-nitro-enclaves-cli source tree
