# Runner wire protocol, version 1

The remote backend (`signer-protocol/remote`, in the Dirk process) and the runner
(`runner/`, inside the TEE) talk over one stream: TCP, a unix socket or
vsock. On GCP and Azure the TCP stream, and on AWS the vsock stream, runs
inside mutual TLS 1.3 (see "Channel binding" below). The reference code is
`signer-protocol/wire/wire.go`;
its tests encode and decode every message and compare the bytes. The fuzz targets in `signer-protocol/wire`
and `governance/handoverorder` (`fuzz_test.go`, `go test -fuzz=FuzzX`) check that
no decoder panics and that what decodes encodes back to the same bytes.

IDENTITY and ATTEST carry a version byte, 1: the request ends with it, and
the answer starts with it and carries the setup state. A runner answers a
request of another version with `UNSUPPORTED`. The identity inside the
handover messages starts with the same version byte.

## Framing

```
frame = length:u32  body             length = len(body), 6 .. 1048576
body  = version:u8  type:u8  id:u32  payload
```

- Protocol integers are big endian. SSZ containers inside payloads keep
  their SSZ little-endian encoding.
- `version` is 1. A reader refuses any other value.
- The client picks `id` (it counts up). A response carries the same `id`
  and `type | 0x80`.
- One request is in flight per connection. The runner serves connections
  in parallel and serializes signing inside the core. It reads the next
  frame of a connection only after it wrote the answer to the last one,
  and it sends nothing but answers.
- A frame over 1 MiB, a short frame, a wrong version or any read error
  closes the connection without an answer.
- The runner does not refuse a request type with bit 0x80 set: it answers
  it like any type it does not serve (`UNSUPPORTED`).
- Connection limits (ATTEST-BUDGET-01, `tee-signer/server/limits.go`, each a
  runner flag). At most 256 connections are open at once (`-max-conns`),
  TLS handshakes included; more are closed at once. At most 32 TLS
  handshakes run at once (`-max-handshakes`), and a peer has 10 seconds
  for one. A frame must arrive within 30 seconds of its first byte. Each
  frame may hold its first 64 KiB freely; the bytes past that count
  against 64 MiB for all frames together (`-max-inflight-mib`), and a
  frame that would go over closes its connection. So SIGN, HEALTH,
  IDENTITY and ATTEST never wait on that cap; large imports and handover
  pages may. There is no idle timeout between frames by default
  (`-idle-timeout`, 0): a client pool that does not dial again when it
  finds a connection closed would fail a request on each idle one.
- A request that panics in the runner gets no answer: its connection
  closes (SHH-03). If the request changes state (any type but HEALTH,
  PUBLIC_KEYS, ATTEST and IDENTITY), the runner then answers every other
  request `NOT_READY` until it restarts, and HEALTH reports `ready` false
  and `request_panic` with the request type and the panic. A panic in one of those four only closes its
  connection. A panic that leaves a lock of the server held for 5 minutes
  stops the runner, and its supervisor starts it again.

## Responses

```
ok    = status:u16 (= 0)  body
error = status:u16 (!= 0) detail_len:u16 detail (UTF-8, at most 1024 bytes)
```

Status codes 0 to 27 are the signer core's `sc_status` values
(`include/signer_core.h` of signer-core, see `core/README.md`); the runner
also uses some of them for its own refusals. Codes from 1000 come from the
runner. `signer-protocol/errors.go` holds the list. An error that is not a
refusal goes out as `INTERNAL` with its Go error text. The runner cuts
`detail` at byte 1024, which can split a UTF-8 sequence.

The retry column says what the code means for a client as the runner
behaves today: "no" means the same request gets the same answer, "later"
means the same request may pass once the runner's state or clock moves on,
"maybe" means it depends on the cause in `detail`. No code says more than
that; a client that needs to tell causes apart reads `detail`.

| Code | Name | Meaning | Retry |
| --- | --- | --- | --- |
| 0 | `SC_OK` | done | |
| 1 | `SC_ERR_ARG` | the core refused an argument; also a config update whose values the core refuses (policy, slot times) | no |
| 2 | `SC_ERR_NOMEM` | the core is out of memory | maybe |
| 3 | `SC_ERR_DECODE` | the core could not decode the message | no |
| 4 | `SC_ERR_BAD_KEY` | a share or key does not check out: a sealed share for another runner or boot, a header changed in transit, a share that does not match `share_pubkey`, a HANDOVER target whose attestation fails | no; a sealed import needs a fresh IDENTITY and a new seal |
| 5 | `SC_ERR_DUPLICATE` | the validator is loaded already | no |
| 6 | `SC_ERR_UNKNOWN_VALIDATOR` | no share of this validator is loaded | no |
| 7 | `SC_ERR_STORAGE` | overloaded: the runner handed over and signs nothing (for good); an import whose maxima did not reach the core (until a restart); the mark log has no `log_id` yet; the body of a config update in force is unreadable (until that update is sent again); a mark log or share write failed | maybe |
| 8 | `SC_ERR_CLOCK` | no trusted time (the NTS clock lacks a quorum, or the clock is not trusted for a config update or a handover) | later |
| 9 to 12 | `SC_ERR_SLASH_BLOCK`, `_SOURCE`, `_TARGET`, `_SOURCE_GT_TARGET` | slashing protection refused | no |
| 13 | `SC_ERR_POLICY_FUTURE` | the message's epoch is past the clock horizon | no (only once the clock catches up) |
| 14 to 20 | `SC_ERR_POLICY_EXIT`, `_FEE_RECIPIENT`, `_GAS_LIMIT`, `_TIMESTAMP`, `_PUBKEY`, `_INDEX`, `_DOMAIN` | policy refused; `_DOMAIN` also for root types 2 to 6 without `allow_unverified_nonslashable` | no (until a config update) |
| 21 | `SC_ERR_POLICY_FORK` | Gloas: a message before the Gloas fork, Gloas not in the chain config, or an aggregate form that does not fit the fork | no |
| 22 | `SC_ERR_POLICY_BUILDER` | Gloas: an envelope of another builder | no |
| 23 | `SC_ERR_POLICY_ENVELOPE` | Gloas: an envelope not for the last block this validator signed | no |
| 24 | `SC_ERR_EQUIVOCATION` | Gloas: a second PTC vote or envelope for a slot at or below the last one signed | no |
| 25 | `SC_ERR_SELECTION_PROOF` | kinds 9 and 10: the selection proof does not verify under the validator key | no |
| 26 | `SC_ERR_SCHEDULE` | a fork schedule update changes an epoch the signer may sign before it applies (`sc_signer_set_schedule`); CONFIG_UPDATE returns it, no SIGN does | no |
| 27 | `SC_ERR_POLICY_BUILDER_AUTH` | kind 14: the root of the BuilderRequestAuth data is not on `builder_request_auth_roots` (an empty list refuses all) | no (until a locked config update) |
| 1000 | `BAD_REQUEST` | the payload does not parse, or the kind of a typed SIGN is unknown; also a well-formed CONFIG_UPDATE or HANDOVER message the runner refuses (reason in `detail`) | no |
| 1001 | `UNSUPPORTED` | a message type this runner does not serve (unknown, another build, a flag that turns it off, a runner without a setup); an ATTEST or IDENTITY request of another version; an unknown root message type | no |
| 1002 | `INTERNAL` | anything else | maybe |
| 1003 | `DOMAIN_MISMATCH` | the request's domain (a typed kind's, or a root message's) differs from the one the runner computes | no |
| 1004 | `NOT_READY` | the runner is not serving yet (CONFIG_UPDATE before its core exists), a handover import is in progress, the operator key is not loaded, or the image check refuses (`detail` starts with `image check:`, see "Image check") | later |
| 1005 | `PLATFORM` | a sealing, store or attestation hook failed | maybe |
| 1006 | `FORBIDDEN` | the client certificate's role does not allow this message (see "Client roles") | no |
| 1007 | `RATE_LIMITED` | an attest-only client certificate had its fresh attestations of the minute (see "Client roles"); `detail` says how many seconds to wait | later |

`backend.Status.IsSlashing` covers 9 to 12 and 24; `IsPolicy` covers 13
to 23, 25 and 1003. Codes 26 and 27 are in neither (see "Open items").

A refusal caused by the restart floor carries
`(at or below restart floor epoch N)` in `detail`.

## Messages

| Type | Name | Request payload | OK body |
| --- | --- | --- | --- |
| 0x01 | HEALTH | empty | JSON of `backend.Health`; `setup` holds the setup state, `key_lock` the key rule lock and `single_key` the single-key acceptance ("Key rule lock"), `image` the image check ("Image check"), all unattested |
| 0x02 | PUBLIC_KEYS | empty | `count:u32` then `count` x key |
| 0x03 | SIGN | `pubkey[48] kind:u8 domain[32] message`; kind 5: `pubkey[48] kind:u8 message` | `signature[96]` |
| 0x04 | ATTEST | `nonce_len:u16 nonce version:u8` (nonce at most 1024 bytes, version 3) | `version:u8 setup_state attestation`, see below |
| 0x05 | IMPORT_SHARE | see below (debug build, dev platform only) | key |
| 0x06 | IDENTITY | `nonce_len:u16 nonce version:u8` (version 3) | identity, see below |
| 0x07 | IMPORT_SHARE_SEALED | see below | key |
| 0x09 | APPROVE_EXIT | a signed exit approval (governance/exitapproval) | empty |
| 0x08 | CONFIG_UPDATE | the signed update, see below (a runner with a setup) | `version:u8 outcome:u8 setup_state` |
| 0x31 | HANDOVER_ORDER | the signed handover order (`governance/handoverorder`) | `outcome:u8 status:u8 hash[32] arrived:u64 act_at:u64 not_after:u64 why_len:u16 why` |
| 0x32 | HANDOVER | `version:u8(1) nonce_len:u16 nonce identity_len:u32 identity policy_len:u32 policy order_len:u32 order start:u32` | `version:u8(1) mark[26] total:u32 origin_proof count:u16 (len:u16 share)* carry_len:u32 carry`, at most 256 shares; see `tee-signer/handover` message.go and carry.go |
| 0x33 | IMPORT_HANDOVER | `version:u8(1) flags:u8 order_len:u32 order page_len:u32 page` | `version:u8(1) count:u16 (outcome:u8)* held:u32 total:u32 done:u8 generated:u32 imported:u32` |

A `mark` is `has_block:u8 block_slot:u64 has_attestation:u8 source_epoch:u64
target_epoch:u64`. PUBLIC_KEYS has no paging: one frame holds at most
10,082 keys (see "Open items").

The handover messages live in `tee-signer/handover`. HANDOVER_ORDER and
HANDOVER are the source side, IMPORT_HANDOVER the target side of a
handover between two runners with setups (see "Handover" below). A release
build with a setup and the mark log serves all three. Other
runners answer `UNSUPPORTED`.

Type numbers: 0x01 to 0x09 are taken, the next free one is 0x0a. Key
generation takes 0x20 to 0x28, the handover 0x31 to 0x33. A response
type is the request type with 0x80 set, so request types stay below 0x80.

After a handover the runner answers HEALTH, PUBLIC_KEYS, ATTEST, IDENTITY
and the two handover source messages (0x31 and 0x32) as usual, and every
other message with `SC_ERR_STORAGE`.

`key = pubkey[48] share_pubkey[48] index:u64`. `pubkey` is the validator's
on-chain key; `share_pubkey` the key of the share this runner holds;
`index` is `2^64-1` when unbound.

### SIGN kinds

| Kind | Message | Bytes |
| --- | --- | --- |
| 1 | AttestationData, SSZ | 128 |
| 2 | BeaconBlockHeader, SSZ (signing root equals the block's) | 112 |
| 3 | VoluntaryExit, SSZ | 16 |
| 4 | ValidatorRegistrationV1 (builder-specs), SSZ | 84 |
| 5 | root message: `type:u8 epoch:u64 object_root[32] domain[32]` | 73 |
| 6 | Gloas PayloadAttestationData (PTC vote), SSZ | 42 |
| 7 | Gloas self-built ExecutionPayloadEnvelope in signer-core's layout (`sc_encode_payload_envelope`: the fixed fields, and the variable payload fields and the execution requests as their roots) | 532 |
| 8 | Gloas ProposerPreferences, SSZ | 76 |
| 9 | AggregateAndProof: `form:u8` (0 phase0, 1 Electra, 2 Gloas) then the SSZ | 2 to 16,730 |
| 10 | ContributionAndProof, SSZ (264 bytes mainnet, 249 minimal) | as the preset says |
| 11 | selection proof: `slot:u64` (little endian) | 8 |
| 12 | sync committee message: `slot:u64 beacon_block_root[32]` | 40 |
| 13 | SyncAggregatorSelectionData, SSZ | 16 |
| 14 | BuilderRequestAuth (builder-specs gloas), SSZ: `offset:u32` (12) `slot:u64` data | 12 to 4,108 |

The bytes are those of the message. Every kind but 5 has the caller's
domain in front of the message: the domain the client signs under, as
Dirk's typed calls carry it. The runner computes the domain the message
gets from its own chain config and fork schedule (the fork version of the
message's epoch; exits the exit fork version, registrations the builder
domain) and refuses another one with `DOMAIN_MISMATCH` before the core
signs or writes anything, as the OP-TEE TA does. With a caller on another
fork, or a runner that missed a fork update, the request gets a refusal
instead of a signature that is invalid on chain. The root message (kind 5)
keeps its domain inside.

A kind outside 1 to 14 gets `BAD_REQUEST` ("no SSZ encoding"), as does a
message of the wrong length; the decoder refuses it before the core sees
it. A root message of an unknown type gets `UNSUPPORTED` from the core.
The integers of kinds 11 to 13 are little endian (SSZ), the epoch of kind
5 big endian.

Kinds 6 to 8 need `gloas_fork_epoch` in the chain config (the chain's
`GLOAS_FORK_EPOCH`, the epoch of one of its forks); without it, or for an
epoch before it, the core refuses them (`SC_ERR_POLICY_FORK`). The core
computes each root itself (the envelope with progressive merkleization)
and applies the rules in `signer-core/README.md`, "Gloas". After the Gloas
fork the aggregate root changes (a progressive Attestation); kind 9 with
form 2 covers it, and the core refuses form 2 before the Gloas fork epoch
and forms 0 and 1 from it on (`SC_ERR_POLICY_FORK`).

Kinds 9 to 13 carry the whole message. The core (`sc_sign_aggregate_and_proof`
and the calls next to it in `signer_core.h`) decodes it, computes the object
root and the signing root itself, uses the domain of the fork in force at
the slot's epoch and refuses a slot past the clock horizon. For aggregates
and contributions it also checks that `aggregator_index` is the key's bound
index (`SC_ERR_POLICY_INDEX`) and that the selection proof verifies under
the validator (group) key over the slot's selection data
(`SC_ERR_SELECTION_PROOF`, 25). These kinds sign whatever
`allow_unverified_nonslashable` says: they are verified. The sizes use the
chain config's `preset` (`mainnet` or `minimal`; absent: minimal for 8 slots
an epoch, else mainnet). The OP-TEE trusted app signs the same messages with
the same core calls (`SIGN_TYPED` kinds 6 to 11 and 16).

Kind 14 signs a BuilderRequestAuth, the Gloas builder API's
authentication to one builder: data agreed with that builder (at most 4,096
bytes) and the proposal slot. The domain is DOMAIN_BUILDER_REQUEST_AUTH
(`0x0B000001`) with the genesis fork version and a zero root, as for builder
registrations; the root is that of a plain Container of two fields, as in
builder-specs gloas (go-eth2-client v0.30.1 hashes a ProgressiveContainer
and gets another root). It is not slashable, so no slashing state is read or written. The
core (`sc_sign_builder_request_auth`) refuses it before the Gloas fork epoch
(`SC_ERR_POLICY_FORK`), past the clock horizon, and unless the
hash_tree_root of its data (as `ByteList[4096]`) is on the signer's
`builder_request_auth_roots` (`SC_ERR_POLICY_BUILDER_AUTH`). The list is the locked config field
`allowed_builder_request_auth_data_roots` of the setup (format 4); a locked config
update changes it. Web3Signer
type: `BUILDER_REQUEST_AUTH`.

Root message types (Web3Signer names):

| Type | Web3Signer type | Domain type |
| --- | --- | --- |
| 1 | RANDAO_REVEAL | 0x02000000 |
| 2 | AGGREGATION_SLOT | 0x05000000 |
| 3 | AGGREGATE_AND_PROOF, AGGREGATE_AND_PROOF_V2 | 0x06000000 |
| 4 | SYNC_COMMITTEE_MESSAGE | 0x07000000 |
| 5 | SYNC_COMMITTEE_SELECTION_PROOF | 0x08000000 |
| 6 | SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF | 0x09000000 |

The runner recomputes the domain from the type, the epoch and its own
chain config. It refuses a mismatch (`DOMAIN_MISMATCH`), refuses an epoch
past the clock horizon, and for RANDAO requires
`object_root = hash_tree_root(epoch)`. No root message can carry a
proposer, attester, exit, deposit or builder domain, so the generic path
cannot bypass slashing protection or the exit allowlist.

Root messages are the generic path: Dirk's generic `Sign` from a stock client
(Vouch) when Dirk cannot find the typed message behind a root. The Dirk
fork's adapter sends typed requests as kinds 9 to 13. Types 2 to 6 (all
but RANDAO: selection proof, aggregate, sync committee message, sync
selection proof, contribution) are signed only when the chain config sets
`allow_unverified_nonslashable: true`; otherwise they get `POLICY_DOMAIN`
(20). On this path the runner sees only the root, so these signatures are
unverified. HEALTH reports the switch
(`allow_unverified_nonslashable`) and the count since start
(`unverified_signatures`).

Web3Signer BLOCK and BLOCK_V2 map to kind 2: the caller sends the block
header. Not covered: DEPOSIT, and BLS_TO_EXECUTION_CHANGE (signed by the
withdrawal key, not the validator key).

Exact repeats: a SIGN for an attestation (kind 1) or block (kind 2) whose
signing root equals the last one the runner signed for that validator
gets the same signature again, so a validator client's retry works. The
C core decides (`sc_repeat_roots`): the checks before it still run (the
proposer index of a block, source not above target for an attestation,
the clock and the epoch horizon), then the core signs the same root
again (BLS is deterministic, so the signature is the same) without the
slashing check and without a watermark or record write. Anything else at that target or
slot is refused by the slashing rules, and so is a repeat of an older
message. The roots live in RAM, so the restart floor refuses the first
repeat after a restart.

### Setup state

IDENTITY, ATTEST and HEALTH carry the runner's setup state
(`backend.SetupState`, `research/setup-phase.md` section 4 of the PoC
repo, and `attestation-verify/docs/attestation-statement.md` for v3 byte by byte). Its
encoding has a fixed size of 353 bytes:

```
setup_hash[32]
locked: version:u64 hash[32] pending_version:u64 pending_hash[32] pending_effective_at:u64
open:   version:u64 hash[32] pending_version:u64 pending_hash[32] pending_effective_at:u64
approver_set_hash[32]
order_kind:u8 order_hash[32] order_act_at:u64
key_release_hash[32]
key_origin: generated_keys:u32 imported_keys:u32 keygen_orders_hash[32]
```

- `setup_hash`: SHA-256 over the context `signer-setup-v1`, `policy_root`
  and `platform_commitment` (setup format 1, `attestation-verify/docs/attestation-statement.md`).
  A runner without a setup (the flag path of tests and local runners) puts the SHA-256 of its `-config` file here and zeros in the
  rest.
- Per group, the state in force: the active version and the hash of the
  update that set it (for version 0, the hash of that group in the setup),
  and the pending update's version, hash and effective activation time
  (Unix seconds), or zeros. It is the newest mark log record's state, with
  every pending update past its effective time shown as active (and a
  pending open update that a rotation dropped gone), whether or not a
  record says so yet. A pending update is all zero or has a version above
  the active one; a reader refuses anything else.
- `approver_set_hash`: over approvals_needed and the approver keys in order (context
  `signer-approver-set-v1`), of the locked group in force. Zero when the
  runner cannot read the body of that update.
- The pending order (kind 1 handover), its hash and act time, or
  zeros. Kind 1 is a source's handover order (from its arrival on, also
  after the tombstone) or a target's handover import in progress (act
  time: the import's start). Kind 2 was the DKG order of earlier builds;
  this build takes none, so it does not occur.
- `key_release_hash` (context `signer-key-release-v1`): the AWS runner's
  KMS key metadata and key policy, or the Azure runner's Key Vault release
  policy and flags, read once at start. Zero on GCP and dev, and when the
  read failed (the runner logs why).
- The key origin: of the loaded keys, how many were made in the key
  generation of an earlier build (this build makes none; a handed-over
  share keeps its origin) and how many were imported, and the hash of the
  DKG orders of the generated ones (context `signer-keygen-orders-v1`;
  zero without a generated key). Each share's sealed record says where it
  came from.

HEALTH carries the same values as JSON (`setup`), unattested, and
`config_hash`, equal to `setup.setup_hash`.

### Key rule lock

The rule of the key that releases the sealing key is the Azure Key Vault
key's release policy or the AWS KMS key policy. The runner reads it at
start, inside the TEE, before it releases any key, from the same answer
that gives `key_release_hash`. It decides whether anyone can still change
the rule:

| Platform | Locked when |
|---|---|
| Azure | `release_policy.immutable` is true |
| AWS | origin `AWS_KMS`, not multi-Region, no Allow statement of the key policy grants `kms:PutKeyPolicy`, `kms:CreateGrant`, `kms:ImportKeyMaterial`, `kms:ReplicateKey`, `kms:CreateAlias`, `kms:UpdateAlias` or `kms:DeleteAlias` to any principal, by name, wildcard (`kms:*`, `*`, `kms:Put*`) or `NotAction` (conditions do not count), every Allow of `kms:Decrypt`, `kms:GenerateDataKey`, `kms:GenerateDataKeyPair`, `kms:ReEncryptFrom` or `kms:ReEncryptTo` has `StringEquals` or `StringEqualsIgnoreCase` tests of `kms:RecipientAttestation:PCR0`, `PCR1` and `PCR2`, so it names one image (PCR3 or PCR8 alone does not); every `kms:RecipientAttestation:*` condition of an Allow, under any operator, has a key `PCR0` to `PCR31` or `ImageSha384` and only literal values of 96 hex digits (a policy variable such as `${aws:PrincipalTag/x}` fails), and no all-zero `PCR0`, `PCR1`, `PCR2` or `ImageSha384`, the values of a debug-mode enclave; any other Allow of `kms:Encrypt` has `StringEquals` on `kms:EncryptionContext:purpose` with the one value `record-creds`, so nobody outside the enclave plants a sealing or mark log key; and the key has no grants (`ListGrants`, every page): a grant is outside the key policy, stays in force after the lock, and cannot require the enclave as recipient. Grants that AWS services make count too, so the key serves no other service. A policy that passes but whose grants the runner cannot read is `unread`. After `DescribeKey` the runner names the key by its ARN in every call, so a `kms_key_id` given as an alias is resolved once per start |
| GCP, dev | no lock exists |

On Azure the runner releases exactly the key version whose release
policy it read (`<name>/<version>` of the Get Key answer) and checks that
the released key's public half is that version's. A mainnet setup's `kid`
names the version.

On mainnet (the setup's `genesis_fork_version` is mainnet's,
`setupwire.IsMainnet`, the test of the threshold rule) the runner refuses
to start when the rule is not locked or when it cannot read the rule
(no read grant). The error starts with `mainnet:` and comes before the
key release, so nothing is sealed or opened. GCP has no lock: a GCP runner
starts on mainnet only when its setup says
`sealing_key_release.no_lock_accepted = true`; HEALTH's `key_lock_why`
then says that the setup accepts it. The dev platform has no key release
service and no real attestation, so it never starts on mainnet: the start error begins `mainnet: the dev
platform has no real attestation`, and on other chains HEALTH's
`key_lock_why` says the dev platform is refused on mainnet. On other
chains the runner starts; a failed read leaves
`key_release_hash` zero and logs a warning.

A GCP signer holds a key alone only with a second, separate acceptance:
an import order with t = n = 1 is refused on GCP on every chain, with or
without `no_lock_accepted`, unless the setup says
`sealing_key_release.unsafe_single_key_accepted = true`
(`setupwire.CheckThresholdOn`). The refusal says why and how to accept.
Why it is unsafe (`setupwire.UnsafeSingleKeyWarning`): a 1 of 1 signer
holds the whole validator key, and on GCP the rule that releases the
sealing key is the IAM bindings of the Workload Identity pool and the KMS
key. Anyone with IAM or KMS admin rights on the project, the pool or the
key (folder and organization admins included) can change them at any
time, with no attestation in the way, and the attacker need not run an
image: a changed binding lets any principal, the admin's own account
included, decrypt the sealing key outside any TEE, open the sealed key
from the state bucket and sign a slashable pair. In a t-of-n split the
same change yields one share; with 1 of 1 it yields the key. The
protection is the project's IAM governance and the watchdog, not the TEE.
`signer-admin setup -allow-gcp-unsafe-single-key` writes the acceptance
into the setup of a one-signer GCP cluster (the key in the signer's
section does the same, and is the way for a file with more signers),
refuses a file with one GCP signer without it, and prints a WARNING line
for every setup that carries it; on mainnet such a setup also needs
`no_lock_accepted`, or its runner would not start, so `signer-admin
setup` refuses it without. The human form carries the warning above the
key; a GCP runner logs it at start and at every 1 of 1 import.
`signer-admin import-draft` drafts a 1 of 1 order to a GCP signer only
with `-allow-gcp-unsafe-single-key` and prints the WARNING line, and
`show` of that order prints it to each approver before `sign`. The setup
has no single-node mode of its own; t = n = 1 in an import order is the
single-node trigger. On the other platforms a single-node signer is not a
split, so the mainnet overlap rule (2t - n >= 2) does not apply to it; it
applies to every real split. Tests: TestThresholdOnGCP,
TestUnsafeSingleKeyAccepted (setupwire), TestImportSingleNode,
TestHealthSingleKey (tee-signer/server),
TestSetupSingleSignerOnEveryPlatform, TestSetupAllowGCPSingleFlagScope,
TestSetupMainnetGCPSingleNeedsNoLockAccepted, TestImportDraftSingleGCP
(signer-admin).

HEALTH reports the result as `key_lock`: `locked`, `not_locked`, `none`
(GCP, dev) or `unread`, and the reason as `key_lock_why`. Next to them
`single_key` says whether the signer holds a key alone where that is
unsafe: on GCP `accepted` (the setup says
`sealing_key_release.unsafe_single_key_accepted`) or `refused`, and `n/a`
on the other platforms. Runners without a setup leave all three out. The
setup state above does not carry them: its layout is the statement the
circuits prove, and IDENTITY shares its version byte with ATTEST. So
`key_lock` is not attested, and neither is `single_key`: the acceptance
sits in the private part of the setup, which a verifier sees only as
`platform_commitment`. The prover reads `key_lock` on the connection whose
IDENTITY it verified and pushes it along with the proof; the watchdog shows "key rule
locked: yes, no, not possible (GCP) or unread" per signer and warns on no
or unread for a mainnet cluster. A zero `key_release_hash` in the proof
counts as unread whatever HEALTH says.

### Image check

The cloud's key rule decides which image gets the sealing key. The
approvers decide which images may run: `allowed_image_measurements` of the
locked group. A runner with a setup holds itself to the approvers' list
(`tee-signer/server/imagegate.go`, `tee-signer/imagecheck.go`), so an image the
key rule lets in but the list does not name holds the sealed keys without
using them.

Its own image comes from the evidence its key release sent, recorded by
the platform as it builds that evidence (`platform.ImageSeen`), never from
a flag, the setup or the host:

| Platform | Evidence | Image (`setupwire.ImageKind`) |
| --- | --- | --- |
| GCP | the launcher token sent to STS, whose image digest the WIF condition pins | `submods.container.image_digest`, `sha256:` and 64 hex digits (kind gcp) |
| Azure | the MAA token sent to Key Vault, whose hostdata the release policy pins | `x-ms-sevsnpvm-hostdata`, the CCE policy hash (kind azure) |
| AWS Nitro | the NSM document KMS takes as recipient | PCR0, PCR1 and PCR2, 48 bytes each, in that order (kind nitro) |
| dev | none | no image kind: the check does not apply |

The runner reads these tokens and documents without the signature check,
as it does for its clocks: they come from the launcher socket, MAA over
TLS for its own SNP report, and `/dev/nsm`. Evidence that names no image,
or two key release calls that name two images, leave the image unknown.

The list it compares with is the one in force: the newest mark log
record's locked group, with every pending update past its effective time
active (the `Updates` view that also feeds the core and the handover orders, with
effective times from `setupwire.EffectiveActivation`). A pending update
that adds the image counts only from its effective time, which is at least
the images minimum (7 days, 7 minutes in a testnet build) after it
arrived. An entry of another kind with the same bytes does not match.

The start order:

1. Key release, in the platform constructor. It has to come first: only
   the key release opens the mark log's records, and the setup's version 0
   alone is not the list in force.
2. The mark log claim and the config updates.
3. The check, before any stored share is unsealed. If it refuses, the
   shares stay sealed in the store and none enters the core, also when a
   later update lists the image: then a restart loads them (state
   `restart_needed`).
4. Every request but HEALTH, PUBLIC_KEYS, ATTEST, IDENTITY and
   CONFIG_UPDATE runs the check again: SIGN, APPROVE_EXIT, the imports,
   and every handover message get
   `NOT_READY` with `image check:` and the reason. A locked update that
   drops the image stops the runner at that update's effective time.

A runner that fails the check stays up rather than exiting. An exit would
restart in a loop, each pass a key release and a mark log claim record in
a locked log, and a watchdog would see only a gap. Up, it answers HEALTH
with the reason, ATTEST with its attested image, and CONFIG_UPDATE, the
approvers' way to list it. The claim of step 2 writes a record that takes
the log over (same mark, same config state) before the check runs; the
host can start any image the key rule admits with that effect, so it
gives an unlisted image no new power.

What "allowed" means on each path:

- A signer's first start (a fresh setup, an empty mark log): the list is
  version 0 of the setup's locked group. A setup must list the image it
  runs; an empty list allows no cloud image.
- A handover target: its setup's version 0 is the source's config in
  force, which lists the target's image (the source checks the order's
  target image against it). So a target passes on the same list.
- The in-place swap: the new image must be on the list in force before it
  starts, so the allowed-images update goes first and waits out the images
  minimum.
- The flag path (no setup) has no list and no check; its key release is
  not bound to any setup_hash, so it opens nothing a setup sealed.

HEALTH reports `image`: `state` (`allowed`, `not_allowed`,
`restart_needed`, `unknown`, `override`, `not_applicable`), the runner's
`kind` and `measurement` (hex), the `locked_version` whose list it read,
and `why`. `ready` is false while the check refuses. The start log line
`runner started` carries `image_check`, and every change of the state is
logged once (an error line when it refuses).

A testnet build (`-tags testnet`) takes `-allow-unlisted-image`: it serves
an image the list does not name, logs a warning at start and reports state
`override`. It does not cover an unknown image. A default build has no
such flag: `server.NewImageGate` refuses an override in a default build,
`tee-signer/imagecheck_test.go` and `tests/e2e` `TestE2EImageCheckNoOverrideInReleaseBuilds`
check that no default build takes the flag, and `scripts/build-runner.sh`
fails when a default-flavour binary holds its name.

### ATTEST body

```
version:u8 (3)  setup_state
platform_len:u8 platform  format_len:u8 format
user_data_len:u16 user_data  doc_len:u32 document
```

```
user_data = sha256(u16 len(ctx) || "signer-runner-attest-v1" || u16 len(nonce) || nonce
                   || setup_state || sha256(sorted pubkey||share_pubkey))
```

`backend.AttestUserData` computes it, `backend.KeysHash` the last part. A
client takes the keys from PUBLIC_KEYS.
The platform binds `user_data` into its document: NSM `user_data` (Nitro),
the token `eat_nonce` as hex (GCP), SNP report data through MAA runtime
data (Azure: the runtime data is the JSON object
`{"signer-runner-identity":"<hex of user_data>"}` from
`backend.MAARuntimeData`, and the report data is its sha256 followed by 32
zero bytes). The dev platform returns unsigned JSON.

### IMPORT_SHARE (test shortcut, debug build and dev platform only)

```
pubkey[48] secret[32] index:u64 flags:u8 block_slot:u64 source_epoch:u64 target_epoch:u64
```

`secret` is the share as a big-endian scalar, in plaintext. `flags` bit 0
and bit 1 say whether the EIP-3076 maxima for blocks and attestations
follow; the runner imports them before any signing. Only the runner's
debug build (`go build -tags debugimport`) has this message: it accepts it
only with `-allow-import`, and refuses to start with that flag on any
platform but `dev`. The release build, which the cloud images use, has no
`-allow-import` flag and answers IMPORT_SHARE like an unknown type
(`UNSUPPORTED`, "message type IMPORT_SHARE").

### IDENTITY body

```
version:u8 (3)  setup_state  kem:u16 kdf:u16 aead:u16  import_key_len:u16 import_key
tls_key_hash_len:u8 tls_key_hash  attestation (as in ATTEST, from platform_len on)
```

The runner makes both keys at start, inside the TEE, and keeps the private
halves in memory: `import_key` is an HPKE public key (RFC 9180 suite
`0x647a/0x0001/0x0002`: ML-KEM-768 + X25519 hybrid, HKDF-SHA256,
AES-256-GCM, from Go's `crypto/hpke`), and `tls_key_hash` is the sha256
of the DER SubjectPublicKeyInfo of its TLS certificate (empty without
TLS). The attestation document binds

```
user_data = sha256(u16 len(ctx) || "signer-runner-identity-v1" || u16 len(nonce) || nonce
                   || setup_state
                   || u16 kem || u16 kdf || u16 aead || u16 len(import_key) || import_key
                   || u16 len(tls_key_hash) || tls_key_hash)
```

It is one 32-byte hash, so the Nitro `user_data`, the Azure report data
and the GCP nonce bind it. `backend.IdentityUserData` computes
it; both context names are entries of the registry in `governance/setupwire`.

A client recomputes `user_data` from the fields and its nonce, then checks
the document (platform signature and measurements) binds it.
`remote.DevVerifier` does the last step for the dev platform's unsigned
document only. `attestation-verify/identity` (`Config.Verify`, same signature as
`remote.VerifyFunc`) does it for Nitro, Confidential Space and MAA
documents. The Dirk fork's cloud adapter, its `cloud-import` tool and
`share-import` do not call either directly. They build their client with
`attestation-verify/runnerclient`, which offers four verifiers by name: `dev`
(`remote.DevVerifier`), `azure-maa` (`attest.VerifyMAA` through
`attestation-verify/azureid`), `aws-nitro` (`attest.VerifyNitro` through
`attestation-verify/identity`) and `gcp-cs` (`attest.VerifyConfidentialSpace` through
`attestation-verify/identity`). No setting turns the check off.

### IMPORT_SHARE_SEALED

```
pubkey[48] share_pubkey[48] index:u64 flags:u8 block_slot:u64 source_epoch:u64 target_epoch:u64
sealed_len:u16 sealed            sealed = enc_len:u16 enc ciphertext
[order_len:u32 order             a signed import order (governance/importorder)
 [t:u8 n:u8 share_index:u8 commitments[48*t]]]   the split the share comes from
```

A runner with a setup takes the share only under an import order: k
approvers in force sign it (`signer-import-order-v1` over the body), it
names this runner's `cluster_id`, chain and `setup_sha256`, a `not_after`
the trusted clock has not reached, the split (`t`, `n`, this signer's share
index) and, for each validator, the hash of its public commitments
(`signer-import-commitments-v1`). Without an order, or with one that does
not verify or does not name the validator, the answer is `FORBIDDEN`. A
runner without a setup (the flag path) has no approvers and takes the share
without an order. With the order the request carries the split: `t`,
`n`, the share index and the validator's `t` public commitments (Feldman,
commitment 0 the validator key). The runner checks that they are the
order's (the commitments by their hash), that `2t > n`, that commitment 0
is `pubkey` and that `share_pubkey` is the commitments' value at the share
index; otherwise
`SC_ERR_BAD_KEY`. A share that is not a point of the validator's
polynomial, or a share of a split without a majority threshold, is not
stored. The order travels in the request; the runner keeps nothing of
it. `governance/importorder/testdata/vector.txt` is a test vector
(body, hash, signed order).

The dealer fetches IDENTITY with a fresh nonce, verifies it, and seals the
32-byte share with HPKE base mode to `import_key`: info
`"signer-share-import-v1"`, associated data = the 129-byte header above
(everything before `sealed_len`). The runner opens it with this boot's
private key, checks that the share's public key equals `share_pubkey`,
then seals it under the platform sealer like any share. A blob sealed
for another runner or another boot, or a header changed in transit, fails
with `SC_ERR_BAD_KEY`. `-sealed-import=false` turns the message off.
`signer-admin/cmd/share-import` is the dealer tool; it reads the share from a
file or stdin and takes the verifier settings of `attestation-verify/runnerclient`
(`-verifier dev|azure-maa|aws-nitro|gcp-cs`, and the settings of the
verifier, see `attest/README.md`). The Dirk fork's `cloud-import` does the
same with the same settings.

### APPROVE_EXIT

A runner with a setup signs a voluntary exit only under the OP-TEE trusted
app's exit rules (issue #4 F4): `exit_approvals_needed` approvers in force
sign an exit approval in the TA's layout (152 bytes: magic `SIGPEXA1`,
genesis validators root, validator key, index, exit epoch, effective
balance, `not_after`, nonce; Ed25519 over `signer-ta-exit-approval-v1`),
followed by `sig_count:u8 {position:u8 signature[64]}`. The runner checks
the chain, the signatures, `not_after` (at most 7 days ahead of the trusted
clock), that the nonce was not used today and that the stated balance is
between 1 Gwei and `max_effective_balance`, then holds it in memory (8 at
most). A voluntary exit signs only if a held approval names its key, index
and epoch and the day's stake (`exit_stake_cap_per_day`) has room for
`max_effective_balance`: every exit counts that much, whatever balance the
approval states and the credentials prefix
(VSEXIT-02; the runner cannot check a stated balance). The exit (key,
index, epoch, stake, the approval's nonce) goes into a mark log record
before it is signed, so a rollback of the host's local state does not
free the day's cap; every later record carries the day's exits. The same
exit (same key, index and epoch) signs again that day without counting. `exit_allowed_validators` stays the core's check. A restart
drops held approvals, as in the TA. A runner without a setup answers
UNSUPPORTED.

### Approver signatures: direct and hashed

Each approver signature (config update, handover order,
import order, exit approval) has two forms, and the runner takes either
per signature in the same `position:u8 signature[64]` slot:

- direct: Ed25519 over the kind's context and the body, as above;
- hashed: Ed25519 over 32 bytes, the SHA-256 of the kind's hash context
  and the SHA-256 of the direct message,
  `SHA-256(CtxXHash.Message(SHA-256(CtxX.Message(body))))`. An OpenPGP card
  signs this message for any body, also an import order of 1,024
  validators (see "Hardware approver keys").

| Kind | Direct context | Hashed context |
| --- | --- | --- |
| config update (over the header) | `signer-config-update-v1` | `signer-config-update-hash-v1` |
| handover order | `signer-handover-order-v1` | `signer-handover-order-hash-v1` |
| import order | `signer-import-order-v1` | `signer-import-order-hash-v1` |
| exit approval | `signer-ta-exit-approval-v1` | `signer-ta-exit-approval-hash-v1` |

The direct message starts with its context, and the hashed one is SHA-256
over an input that starts with its hash context, so a signature of one
form or kind passes for another only through a SHA-256 collision. The
`-hash-v1` contexts of the first build signed the hash context and the
32 bytes without the outer SHA-256, 58 to 65 bytes, which gpg's scdaemon
does not pass to a card; `-hash-v2` replaces them, and a runner takes no
v1 signature. The TA does not take the hashed exit approval yet; one
hashed approval serves the cloud runners only. `signer-admin sign
-hashed` makes the hashed form; `show` prints both messages so an
approver can compare them over a second channel.

### Hardware approver keys

An approver key can live on a YubiKey, in its OpenPGP applet. The tool
names it `openpgp:KEYGRIP` and signs through the gpg-agent of the machine
it runs on (`signer-admin/approver/openpgp.go`). The setup's `approvers =` line
holds the card key's Ed25519 public key, as for a key file.

What the card signs. `signer-admin sign` hands gpg-agent the 32-byte
hashed message as a SHA-256 digest (`SETHASH --hash=sha256`, `PKSIGN`).
The agent wraps it in SHA-256's DigestInfo, scdaemon strips that again and
sends the card the bare 32 bytes, and the card makes an Ed25519 signature
with those 32 bytes as the message. GnuPG makes every OpenPGP EdDSA
signature the same way, over a hash of the signed data. So the card's
signature is a plain Ed25519 signature over the hashed message, and the
runner checks it with the code that checks a key file's. scdaemon passes
a card 20, 28, 32, 48 or 64 bytes only (`scd/app-openpgp.c`, `do_sign`),
so a card key signs the hashed form only, and `sign` picks that form for
it. Sources: GnuPG 2.4 `agent/command.c` (`cmd_sethash`),
`agent/divert-scd.c` (`divert_pksign`), `scd/app-openpgp.c` (`do_sign`),
`agent/pksign.c` (`do_encode_eddsa`), RFC 9580 section 5.2.4.

The card must be:

- a YubiKey 5 with firmware 5.2.3 or later, the first with Ed25519 in the
  OpenPGP applet (`ykman info` prints the firmware);
- holding an Ed25519 key in the signature slot: `gpg --card-status` shows
  `Key attributes ...: ed25519` first. Generate it on the card
  (`gpg --card-edit`, `admin`, `key-attr`, ECC, Curve 25519, then
  `generate` or `addkey` for a subkey) or move a key there with
  `keytocard`. A Curve25519 key is an encryption key and is refused;
- set to touch for every signature: `ykman openpgp keys set-touch sig on`
  (`fixed` cannot be undone without a reset; `cached` lets 15 seconds of
  signatures go without a touch). Set it after the key is generated: a
  new key resets the policy to off.

The OpenPGP applet has one signature slot. If that slot also signs git
commits, an approval and a commit signature come from one key; the
hashes keep them apart, but each touch then means one of two things. A
YubiKey used for approvals only avoids that.

Reading the public key needs no card:

```
gpg --with-keygrip --list-keys FINGERPRINT    # Keygrip of the [S] subkey
signer-admin approver-key -key openpgp:KEYGRIP
gpg --export FINGERPRINT > approver.pgp       # or from a file someone sent
signer-admin approver-key -openpgp approver.pgp [-fingerprint SUBKEY]
```

Both print `approvers = 0x...`. The first reads the public key gpg-agent
keeps for a card key; the second reads the exported key's Ed25519 keys
and picks the one signing subkey. It reads the key flags but does not
check the self-signatures, so take the export from a trusted source.

Signing:

```
signer-admin show import.bin                  # note the hashed form's 32 bytes and the direct form's sha256
signer-admin sign -key openpgp:KEYGRIP -expect-sha256 HEX import.bin
```

`show` reads the file once and prints every value and hash from those
bytes. `-expect-sha256` takes the direct form's sha256 that `show`
printed, and `sign` refuses a file whose signing message is another, so a
draft changed after the review is not signed.

When the agent asks for the PIN (once per its PIN cache), the prompt
shows the 32 bytes the card is about to sign; they must match what `show`
printed. Then the card blinks for the touch. The tool
checks the signature under the public key before it writes it. gpg-agent
must run where `signer-admin` runs and see the card: on Linux through
pcscd, in WSL through `usbipd` attaching the YubiKey (which takes it away
from Windows for that time).

### CONFIG_UPDATE

A runner with a setup takes approver-signed config updates
(`research/setup-phase.md` sections 6 to 9 of the PoC repo; code in
`tee-signer/server/config.go`).

```
request = update                           1 .. 65536 bytes, governance/setupwire's 'U' layout
answer  = version:u8 (3)  outcome:u8  setup_state
```

- `update` is the signed update as `signer-admin` makes it: the body
  (`cluster_id`, chain hash, group, version, `prev_hash`, `activate_at`, the
  full new group and a salt for each of its leaves), the approvers'
  signatures by position over the header (the body's fields with the root
  of the new group's salted leaves in place of the values) and, for a
  rotation, a signature by every key of the new set. The runner decodes it
  with the shared strict decoder.
- `outcome` 1: the update is its group's pending update now. With no wait
  it may be in force already. `outcome` 2: the same update was the group's
  pending or active update already. The runner wrote its body again if no
  readable copy was left. Sending an update twice does no harm.
- `setup_state` is the state in force after the update (see "Setup
  state"), unattested. IDENTITY attests the same values.

Any client with a client certificate that is not attest-only may send it
(an attest-only one gets `FORBIDDEN`); the signatures carry the authority.
A runner without a setup answers `UNSUPPORTED`. The runner checks, in
order (the status of each refusal in brackets):

1. The decoder: layout, counts within caps, approver key rules (2 to 8
   keys, no duplicates, no small-order or non-canonical keys, k at least 2
   and above n/2), time lock at most 30 days, withdrawal credentials, gas
   limits.
2. `cluster_id` and the chain hash are the setup's.
3. The clock is trusted and answers: the NTS clock with a quorum
   (`SC_ERR_CLOCK` otherwise). The dev platform takes its untrusted clock.
   The clock comes before the version checks because it decides which
   pending update is in force already.
4. No handover import is in progress, and the core exists (`NOT_READY`
   otherwise). The group's pending or active update sent again skips to
   its signatures (pending) or straight to the body write (active), and
   answers `outcome` 2.
5. `version` is above the group's active and pending versions, at most
   2^32 above the higher one. `prev_hash` is the hash of the group's
   active update (version 0: the setup's group hash). (`BAD_REQUEST`)
6. The runner knows the approver set in force and, for an `open` update,
   the open values in force: their update bodies are readable
   (`SC_ERR_STORAGE` otherwise, until that body is sent again).
7. At least k distinct approvers of the set in force signed, every
   signature verifies, and for a rotation every key of the new set signed.
   A pending rotation's new set counts for nothing. (`BAD_REQUEST`)
8. The wait W: for `locked` the time lock in force (the image default of
   48 hours when the group names none), at least the image's minimum of 7
   days when the allowed-images list gains an entry; for `open` 0.
   `activate_at` is at most now + W + 30 days. Sums saturate.
   (`BAD_REQUEST`)
9. The core takes the values, and its status goes out as it is: the
   signing policy and the slot time rule for `locked` (`SC_ERR_ARG`,
   `SC_ERR_SCHEDULE`), the fork rule for `open` (`SC_ERR_SCHEDULE`; an
   `open` update while an earlier one is stuck in the core gets
   `SC_ERR_STORAGE`): every epoch whose fork version or Gloas state
   changes must lie above epoch(effective time) +
   `max_sign_epochs_ahead_of_clock` + 1, the epoch the largest under the
   slot times in force and those of a pending `locked` update. A `locked`
   update with new slot times is refused when a pending `open` update would
   not keep clear under them.
10. The runner writes the body to the mark log, then a record with the
    update pending, then answers. A failed write is `SC_ERR_STORAGE` and
    leaves nothing pending.

Steps 1 and 2 refuse with `BAD_REQUEST`, step 3 with `SC_ERR_CLOCK`. The
reason is in `detail`. A client tells a malformed update from a
well-formed one the runner refuses only by that text.

The update is in force at its effective time: the later of `activate_at`
and its arrival + W. A higher version in the same group replaces the
pending update, with a wait from its own arrival. To cancel, approvers
send the active values under a higher version. When a rotation comes into
force, the pending open update goes: the old set signed it.

The runner reads the config in force from the newest record and the
clock, not from a record that says an update is active. Past the effective
time the new values sign, whether or not the record that shows them has
landed; the runner writes that record within a second or two. At a restart
the update bodies come from the mark log. A locked update's values switch
in the core at the effective time. An open update goes into the core when
it arrives: the fork rule makes that sign the same as a switch at the
effective time.

If the body of an update in force is unreadable (after a restart), SIGN
answers `SC_ERR_STORAGE` and HEALTH says not ready. While the approver set
in force is unknown, every update is refused; while the open values in
force are unknown, every open update. Sending the same update again writes
its body back and the runner signs again. For the update in force the
runner then checks only that the body has the hash the record names: its
signers may have rotated away since.

### Handover

A handover moves every share and the slashing mark of one runner (the
source) to a runner of a new image (the target), under an order that k
approvers in force signed. The source's setup and the target's are
different setups of one cluster: the setup puts the image's rules into
`setup_hash`, so a new image needs a new setup, and a new setup starts with
an empty mark log. The source side is `tee-signer/server/handover_source.go`,
the target side `handover_import.go`; the encodings are in
`governance/handoverorder` and `tee-signer/handover` (`message.go`,
`import.go`, `carry.go`). All four messages need the admin role. Every release
build with a setup and the mark log has both sides, and no image may go
out without them (release gate, below).

The operator's steps, with the tools of this tree:

1. A target setup: the source's setup with `handover_generation` one
   higher, the same `cluster_id`, chain and safety values, version 0 of
   both groups equal to the source's config in force, its own salts,
   `max_keys`, `slashing_log_min_lock_days`, stores and platform part. If
   the target's image is new, an allowed-images update on the source
   first.
2. The order (`signer-admin handover-draft`, then the approvers' signatures)
   goes to the source in HANDOVER_ORDER.
3. The target starts with no keys. `handover-target identity -order`
   pushes the order to the target, which reserves itself for it (below),
   then reads its IDENTITY for a fresh nonce over a connection pinned
   to its `setup_sha256` and writes the identity file with the published
   setup (`setupwire.Published`: the public part with every salt, and
   `platform_commitment`; never the private part).
4. Once the order acts, `handover-source -go` sends HANDOVER and writes
   the pages; `handover-target import` passes them to the target in
   IMPORT_HANDOVER.

HANDOVER_ORDER on the target. An order that names the runner as its
target reserves it: the runner checks the order as the first import
request does (its target `setup_hash`, cluster, chain, k signatures of the
approvers in force) and that it is empty, at version 0 of both groups with
nothing pending, and writes the order into its import slot. From then on
it takes no config update, no other order and no share but the order's,
also after a restart, and its IDENTITY shows the order. So the IDENTITY
answer the source checks stays true until the import, though the tool,
not the source, chose its nonce. The same order again reports the
reservation. It ends with the import; a target whose order is abandoned is
replaced.

HANDOVER_ORDER. The source checks the order's cluster, chain and source
`setup_hash`, k signatures of the approvers in force, the target image on
`allowed_image_measurements` in force, and a verifier for the target's
settings built into this runner (the dev verifier on the dev platform
only; on a runner limited to its peer hosts, key set hosts among them). It
records the order in the order slot of the mark log's state with its act
time: arrival on the trusted clock plus the change delay in force, at
least the images minimum (7 days, 7 minutes in a testnet build; the dev
platform waits the change delay only). `not_after` must lie after the act
time. A second order is refused while one is pending or active; an
expired or void one (approvals or image no longer in force) can be
replaced. The same order again answers its state and keeps its time.
At `not_after` the order leaves the slot by itself: IDENTITY no longer
shows it, and the next record
(the config sync writes one) holds the empty slot. The same order is then
refused as expired. After the tombstone the order stays in the slot.

HANDOVER. Before anything changes, the source checks:

- the order is its pending order, past its act time, before `not_after`,
  still signed by k approvers in force, its target image still allowed;
- no config update is pending on the source;
- the target's published setup rebuilds `policy_root` from its leaves and
  salts, and `setup_hash` = H(`policy_root`, `platform_commitment`) is the
  order's target and the one the target's identity carries;
- the target's attestation verifies with the order's settings over the
  IDENTITY user data, so its measurement is the order's image;
- the target's public part equals the source's values leaf by leaf:
  `cluster_id`, chain, safety, `handover_generation` + 1, and version 0
  of both groups equal to the source's config in force;
- the target's state: version 0 of both groups with its published group
  hashes, nothing pending, its setup's approver set, no key (key origin 0
  and 0), reserved for this order (the order in its slot), and `max_keys`
  at least the source's share count, checked again on the shares read
  under the share lock.

Then the source stops signing, reads every stored share once, checks that
they are its loaded keys, and writes the tombstone that names the target
into the mark log (under the lock of config writes, and only if the config
in force is still the one checked). Only then does it seal the first page.
From the tombstone on, also after a restart, the source signs nothing,
takes no other order, and answers HANDOVER for that target only, with
the same mark: one target per tombstone. A target that restarted mid-import
has a new import key; the source seals the same shares to it again.

What a page carries, besides the shares sealed with HPKE to the target's
attested import key:

- the mark before the tombstone, as each share's interchange maxima. The
  target raises its own log to it before it stores a share, and a fresh
  target log takes its vote history from it;
- each share's key origin (generated in the key generation of an earlier
  build, with its DKG order hash, or imported), from the share's sealed
  record, signed with the source's origin key, whose attestation over the
  order hash the page carries;
- the carry, which every page has: the key set the source hands over (how
  many shares, and `KeysHash` of their pubkey and share pubkey pairs) and
  the day's exits of the source's mark log (validator key, stake and
  approval nonce). The target writes the exits into its mark log before
  its import ends, so the day's cap and used nonces hold across the
  handover.

```
carry = version:u8(1) total:u32 keys_hash[32] has_exits:u8
        [day:u64 stake:u64 count:u16 (pubkey[48] validator_index:u64 exit_epoch:u64 stake:u64 nonce[32])*]
```

Each share's HPKE associated data covers its header (the mark and the
origin) and the carry's hash (`signer-handover-carry-v1`). Nobody can
change or drop the mark, the origin or the carry without the share failing
to open. The config needs no carry: the target's version 0 is the source's
config in force, which the source compared leaf by leaf, and old updates
of the source do not chain onto the target's version 0 (`prev_hash`).

IMPORT_HANDOVER. The target checks the order (its own `setup_hash`, cluster
and chain, k approvers in force), finds itself empty at version 0 on the
first request and writes the order into the slot: it signs nothing and
takes no other share or update until every share is in, also
after a restart. Every request of one process carries the same mark. It
checks the origin proof and signatures (or counts every share as imported
on request), opens each share, stores it after raising its log, and clears
the slot when it holds exactly the carry's key set. Only a request in which a share
opened under the carry ends the import: the page's total alone is not
authenticated, and a page whose total is not its carry's does not decode.
It then signs above the mark, after its restart floor. One share per
validator is stored at a time, and a page that names a validator twice
does not decode.

A source keeps the sealed body of its pending order in the state copy. A
source whose host lost it anyway reads the slot as an import and signs
nothing until the order is pushed again, which restores the body on the
hash the slot holds, before any check under the config in force: an order
that a rotation or an image removal voided since comes back too, as void.
It never takes an import for its own order.

Release gate. `tests/e2e` `TestE2EHandoverGate` runs a dev release
runner N that hands over to N+1 of the same tree, which hands over to N+2,
with signing above the mark after each step and the source refusing
everything after its tombstone. It runs in the default e2e set
(`scripts/test.sh` fails unless it passed), and `scripts/handover-gate.sh`
runs it on the dev release build of each flavour, default and testnet
(`go test -tags testnet`, a test chain), and writes
`build/handover-gate.stamp` with the source id of the tree once both
passed. The Azure, GCP and Nitro image builds refuse to start unless the
stamp matches the sources (`require_handover_gate` in `scripts/common.sh`).
There is no override.

### Client roles

Every connection has a client role, and the role table below is the only
grant: a message type a role may not send gets `FORBIDDEN` before the
runner reads its payload, before the handed-over check, and a refused
IMPORT_SHARE or IMPORT_SHARE_SEALED payload is wiped. A type missing from
the table (an unknown one, or a new message nobody added) is `FORBIDDEN`
for every role (research/admin-tool.md of the PoC repo, section 4).

A TLS client's role comes from its verified certificate chain
(`runner/attls.RoleOf`), in this order:

1. Attest-only: the leaf, or any CA certificate of a verified chain, lists
   `1.2.840.113556.1.8000.2554.49247.57036.45844.17649.38356.1811430.10320378.1`
   (`backend.AttestOnlyClientOID`). A mark that restricts may come from
   anywhere: a CA marked attest-only makes every certificate below it
   attest-only.
2. Admin: some verified chain is exactly leaf, intermediate and root. The
   leaf lists
   `1.2.840.113556.1.8000.2554.49247.57036.45844.17649.38356.1811430.10320378.2`
   (`backend.AdminClientOID`), the intermediate lists it too and has
   `pathlen:0`, and the root is self-signed (a CA certificate of
   `allowed_client_ca` that is itself an intermediate does not count). A
   leaf signed straight by the root is never admin, nor is a marked leaf
   under an unmarked intermediate, nor a marked CA below another
   intermediate. So a key that reaches only the signing intermediate cannot
   mint an admin certificate, whatever path length that intermediate
   allows (ATTEST-ROLES-02).
3. Admin-root-direct, testnet builds only (`buildflavor.AdminRootDirect`):
   the leaf lists the admin mark and the root signed it directly. It has the
   admin rights. It is meant for a test chain whose pinned client root has
   `pathlen:0`, so no admin intermediate can exist under it. There, whoever
   holds the root key can make admin certificates. Default builds never give this role.
4. Signing: anything else.

The chain an admin certificate needs, under the root in
`allowed_client_ca`:

```
root CA            no role mark, key offline
├─ admin CA        clientAuth + AdminClientOID, pathlen:0, key offline
│   └─ admin leaf  clientAuth + AdminClientOID
├─ signing CA      clientAuth (issues the Dirk fork's certificates)
│   └─ signing leaf
└─ attest CA       clientAuth + AttestOnlyClientOID (optional)
    └─ attest leaf
```

Every certificate of the chain must allow `clientAuth` (or list no
extended key usage); Go's verifier refuses the handshake otherwise.

The runner checks the chain's dates against its trusted clock, never the
system clock (ATTEST-ROLES-03): in the handshake, and again before every
request on the connection. Once the trusted clock passes the earliest
`NotAfter` of the verified chains, the next request gets `FORBIDDEN` and
the connection closes (ATTEST-ROLES-01). A client reconnects with a valid
certificate.

While the trusted clock gives no reading, the runner answers `HEALTH` and
nothing else, so a watchdog or a client can see why: `clock_unix` is 0 and
`ready` is false. Every other request gets `FORBIDDEN` and the connection
closes. A handshake then still verifies the chain (signatures, key usages,
path lengths) but not its dates, and the connection may send `HEALTH`
only. Once the clock has a reading again, the next request on such a
connection first checks the chain with its dates, as a handshake would: a
chain outside its dates gets `FORBIDDEN` and the connection closes, a valid
one gets its role. A clock that fails in the middle of a handshake still
fails that handshake; the client connects again.

A
connection without TLS (a unix socket, or a dev runner without a client
CA) is a local client: the admin row and SIGN. Release builds refuse a
unix listener off the dev platform, and every network listener off dev
has mutual TLS.

| Type | Message | Signing | Attest-only | Admin |
| --- | --- | --- | --- | --- |
| 0x01 | HEALTH | yes | yes | yes |
| 0x02 | PUBLIC_KEYS | yes | yes | yes |
| 0x03 | SIGN | yes | no | no |
| 0x04 | ATTEST | no | yes, limited | yes |
| 0x06 | IDENTITY | yes, limited | yes, limited | yes |
| 0x05 | IMPORT_SHARE (debug builds) | no | no | yes |
| 0x07 | IMPORT_SHARE_SEALED | no | no | yes |
| 0x08 | CONFIG_UPDATE | no | no | yes |
| 0x09 | APPROVE_EXIT | no | no | yes |
| 0x31 to 0x33 | HANDOVER_ORDER, HANDOVER, IMPORT_HANDOVER | no | no | yes |
| any other | | no | no | no |

An admin certificate cannot SIGN, so a stolen one makes no signature.
PUBLIC_KEYS is open to attest-only clients because a verifier of an ATTEST
answer needs the keys for `keys_hash`.

"Limited" counts fresh attestations: an ATTEST or IDENTITY answer for a
nonce this certificate had no answer to in the last minute, for the same
message type and the same state. A repeat within the minute, while the
setup state and the keys stand, gets the same answer again and does not
count; a failed attestation counts, it called the platform. The limits,
image constants, in any minute:

- an attest-only certificate: 4 (`backend.AttestOnlyPerMinute`; signer
  change 8 of research/attestation-prover.md), ATTEST and IDENTITY
  together. The connection's own IDENTITY counts too (the dashboard's
  proof check makes two a minute);
- a signing certificate: 32 IDENTITY (`server.SigningIdentityPerMinute`,
  twice the Dirk fork's pool of 16 connections, each of which asks for
  IDENTITY when it is made);
- all non-admin certificates together: 128
  (`server.NonAdminFreshPerMinute`), so many signing certificates cannot
  add up to an attestation flood.

More get `RATE_LIMITED`, with the seconds until the next one. Admin and
local clients have no limit.

A runner without a setup refuses VOLUNTARY_EXIT off the dev platform: it
has no exit approvals and no daily stake cap.

**Role probe.** `signer-admin probe` (signer-admin/cmd/signer-admin) finds out
whether admin messages from a certificate pass, and changes nothing. It
sends a message of type 0x7f, which no runner serves: the role table
answers `FORBIDDEN` for every role. Then CONFIG_UPDATE with an empty
payload: `FORBIDDEN` means the certificate lacks the admin role;
`BAD_REQUEST` (the empty payload does not decode) means it passed and the
runner has a setup; `UNSUPPORTED` means it passed and the runner has no
setup.

`scripts/make-test-ca.sh` issues a test PKI with one chain per role:
`client.pem` (signing), `attest-client.pem`, `admin-client.pem` under
`admin-ca.pem`, and `root-admin-client.pem`, an admin-marked leaf straight
under the root that the runner treats as signing.
`signer-admin issue-client-cert` issues certificates of a role from an
existing CA key.

### Channel binding (GCP, Azure, AWS)

With `-tls-client-ca`, every TCP and vsock listener is TLS 1.3 with a
required client certificate from that CA (baked into the image). The
client certificate's validity dates are checked against the runner's
platform clock, not the system clock. The server
certificate is self-signed in the TEE, so clients do not check it against
a CA: `remote.WithTLS` completes the handshake, sends IDENTITY with a
fresh nonce over the new channel, and accepts the connection only if
`tls_key_hash` equals the key the handshake presented and the verifier
accepts the document. A relay that terminates TLS with its own key fails
that check even with a valid client certificate. `remote.WithTLSKeyPin`
pins a known key instead or as well.

The server certificate names the runner's chain: a non-critical
extension `backend.RunnerChainOID` (the admin OID's arc, last arc 3)
holds the setup's genesis fork version as an OCTET STRING of 4 bytes.
`attestation-verify/runnerclient` refuses, in the handshake, a runner whose value is
mainnet's unless its attestation settings say `mainnet`, and a runner of
another chain if they do. The settings decide the client's mainnet rules
(`key_release_sha256` for `azure-maa` and `aws-nitro`), and IDENTITY
does not name the chain, so without the mark a setting left out would fail
open. The mark is readable by anyone who starts a handshake, like the
flavour in the subject. A certificate without the mark leaves the decision
to the setting alone. The next IDENTITY version should carry the chain in
the attested fields.

`attestation-verify/runnerclient` does this for the Dirk fork and the import tools,
on every new connection: handshake with the client certificate, IDENTITY,
the verifier (`dev`, `azure-maa`, `aws-nitro` or `gcp-cs`), and the comparison of the verified
identity's `tls_key_hash` with the handshake key. That comparison is the
key pin, taken from the verified identity. A runner makes a new TLS key and
a new identity at every start, so the client repeats the steps after a
reconnect and does not keep the pin. An optional `tls_key_pin` setting
adds a fixed pin for one run of a runner.

After a timeout or an I/O error the client closes the connection and never
uses it again. The next request dials a new one, with all the steps above.
That dial runs in its own context, bounded by the client timeout, and not in
the context of the request that starts it. The Dirk fork's callers stop
waiting as soon as a threshold of the other signers has answered, usually
before a new dial to a cloud signer is done, so a dial tied to the request
would never finish. A request whose context has ended before its turn is not
sent, and a request that is on the wire runs to its deadline, so the
connection stays in step.

The `azure-maa` verifier checks, in `attest.VerifyMAA`: the RS256
signature against the key set of the configured attestation provider
(`https://<maa_host>/.well-known/openid-configuration`, then `jwks_uri`),
the issuer (`https://<maa_host>`), the time claims, TEE type `sevsnpvm`,
the compliance status (`azure-compliant-uvm` unless configured), debug off,
VMPL 0, `x-ms-sevsnpvm-hostdata` equal to the configured CCE policy
hash, and the report data: SHA-256 of the runtime data
(`backend.MAARuntimeData`) followed by 32 zero bytes, which binds the token
to this identity and the client's nonce.

The `aws-nitro` verifier checks, in `attest.VerifyNitro`: the chain from the
signing certificate to the pinned AWS Nitro Enclaves root, the ES384
signature, PCR0 to PCR2 (and any other PCR configured) against the expected
values, debug mode (all three zero, refused), the nonce and the `user_data`
(`backend.IdentityUserData`), which bind the document to this identity and
the client's nonce.

The `gcp-cs` verifier checks, in `attest.VerifyConfidentialSpace`: the RS256
signature against the issuer's key set (or a pinned set), the issuer, the
configured audience (never the STS audience), `swname`, `secboot`, `dbgstat`,
STABLE support, the hardware model, the image digest, optionally the service
account, and `eat_nonce`, which carries the hex of `user_data`.

On AWS the runner listens on vsock inside the enclave. The parent instance
forwards traffic into the enclave and is not trusted, so the vsock listener
serves the same mutual TLS, with a key made inside the enclave, and the
identity carries its hash like on GCP and Azure. The nitro platform refuses
to start without `-tls-client-ca`, and a release build refuses a plain vsock
listener on any platform. The client reaches the runner over TCP, through a
plain forwarder on the parent that copies bytes (`platform-aws/cmd/forwarder`)
and never ends TLS. The binding above then holds: a forwarder that ends TLS
with its own key is refused (`platform-aws/deploy/README.md`, "Network entry").

## Example

HEALTH request with id 1: `00000006 01 01 00000001` (10 bytes on the wire).

## Open items

Places where the code does something this spec would not choose. This
document describes the code as it is.

1. `backend.Status.IsPolicy` leaves out 27 (`SC_ERR_POLICY_BUILDER_AUTH`).
   A client that sorts refusals with it, as the Dirk fork's cloud adapter
   does (`refusal` in `backends/cloudremote`), reports a kind 14 refusal
   as a plain failure (FAILED), not as a policy refusal (DENIED).
   `SC_ERR_SCHEDULE` (26) is in no class either, but no SIGN returns it.
2. An unknown typed SIGN kind gets `BAD_REQUEST`, an unknown root message
   type `UNSUPPORTED`. One code for both would be cleaner.
3. PUBLIC_KEYS has no paging. Past 10,082 keys the answer is larger than a
   frame: `WriteFrame` fails, the runner logs it and closes the connection
   without an answer.
4. `detail` (1024 bytes) and the `why` of handover order states
   (512 bytes) are cut at a byte count, which can split a UTF-8 sequence.
5. A request type with bit 0x80 set is not refused as such.
6. IMPORT_SHARE and IMPORT_SHARE_SEALED take flags 0 with maxima that are
   not zero and drop the maxima. Only all-zero maxima should pass with
   flags 0.
7. Status codes are overloaded (`SC_ERR_STORAGE`, `BAD_REQUEST` and
   `UNSUPPORTED` each cover several causes, see the table), so a client
   can only tell causes apart by the `detail` text.
