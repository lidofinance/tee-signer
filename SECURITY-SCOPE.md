# Security scope

Not all of this repo can get the same depth of security review. This file
draws the line: each module is either PERIMETER or PERIPHERY. Deep review,
fuzzing and audit time go to the perimeter first.

**PERIMETER.** Code that runs inside the TEE and guards the keys or slashing
safety, or decides what untrusted input may reach them. A bug here can leak
a key, sign a slashable message or accept forged governance. Untrusted
input must not get past it.

**PERIPHERY.** Code that runs outside the TEE, or only in tests. It is
untrusted by design: the perimeter checks everything it sends. A bug here
may stop signing, but it must not break key custody or slashing safety. If
safety depends on a check that exists only in the periphery, that is a
perimeter bug.

## Modules

| Module | Zone | Why |
|---|---|---|
| [signer-core](signer-core) | PERIMETER | Signs, and refuses slashable messages (EIP-3076 watermarks, policy) inside the TEE. |
| [signer-protocol](signer-protocol) | PERIMETER | Decodes every frame a client sends to the runner. |
| [governance](governance) | PERIMETER | The runner checks setups, approver signatures, rotations, time locks and orders with it. |
| [tee-signer](tee-signer) | PERIMETER | The runner itself: key shares, signing, imports, key generation, handover. |
| [slashing-log](slashing-log) | PERIMETER | The mark log stops a restarted, rolled back or cloned runner from signing below its marks; it reads storage the host controls. |
| [platform](platform) | PERIMETER | The sealing and key release interface and the setup loading of the runner. |
| [platform-aws](platform-aws) | PERIMETER | Attestation, KMS key release and the S3 mark log inside the enclave. |
| [platform-azure](platform-azure) | PERIMETER | SNP and MAA attestation, Key Vault key release and the Blob mark log inside the TEE. |
| [platform-gcp](platform-gcp) | PERIMETER | Attestation token, Cloud KMS and the Cloud Storage mark log inside the TEE. |
| [attestation-verify](attestation-verify) | PERIMETER | Runners check their key generation and handover peers with it, inside the TEE. |
| [trusted-time](trusted-time) | PERIMETER | Time decides time locks, certificate expiry and the exit ledger; the NTS client parses network answers. |
| [signer-admin](signer-admin) | PERIPHERY | Operator tools outside the TEE; the runner checks the approver signatures on what they send. |
| [web3signer-api](web3signer-api) | PERIPHERY | Parses validator client requests in front of the runner. It moves to the perimeter if it ever parses inside the TEE. |
| [devkit](devkit) | PERIPHERY | Test helpers. |
| [tests](tests) | PERIPHERY | Tests only. |

Parts of a perimeter module that are periphery:

- `platform/dev`: the dev platform (`dev.New`) protects nothing and runs
  only with `-platform dev`. Its AES-GCM sealer (`dev.NewGCMSealer`) is the
  exception: the three cloud platforms seal with it, so it is perimeter code.
- `platform-aws/hostagent` (its server side), `platform-aws/forward`,
  `platform-aws/udprelay` (its relay side) and `platform-aws/cmd/*` run on
  the parent instance, which is not trusted.
- `slashing-log/logtest`, `slashing-log/wormfake`, `trusted-time/nts/ntstest`,
  `signer-core/software`, and the `cmd/attest-verify` tool of
  attestation-verify.
- `devkit/lockorder` is the reverse case: a periphery package that every
  runner links, as a plain mutex. The release gate refuses its lock order
  check in a release build.

## What runs in an image

The perimeter of a release is the code its runner binary links, which
depends on the build: the platform tag (one cloud per image), the peer tags
(key generation and the handover source side are only in peer builds) and
the tag `nts`. The release gate (`scripts/release-gate.sh`) and the
dependency check (`scripts/check-deps.sh`) keep everything else out. To
see what a build links, run `scripts/loc.sh builds`; `scripts/loc.sh zones`
sums the modules by zone. A first release can start with a smaller
perimeter, for example one platform, or no key generation, and add the rest
later.

## Changing a zone

A module changes zone only through a PR that changes this file, with the
reason. New modules start as PERIMETER until such a PR says otherwise.
