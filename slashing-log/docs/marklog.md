# Mark log

The runner's slashing mark, kept in a locked, append-only log outside the
host's reach (`slashing-log`, `-mark-store`). A peer mark quorum is a
separate design that this does not build.

## What is stored

One device mark for all validators of the runner (the core's
`SC_MARKS_PER_DEVICE`): the highest block slot, source epoch and target
epoch the runner may have signed. Every raise of the mark is one record,
one object:

    marks/<setup_hash hex>/<signer>/<version, 20 digits>

The path holds `setup_hash`, so a new setup always finds an empty log. A
runner on the flag path without a setup writes `marks/<signer>/<version>`
with a zero setup hash. The start-order item removes that path.

Every record carries the full config state, so no record needs an earlier
one for the config. Records expire oldest first, and the newest one is
enough.

| Field | Bytes | Meaning |
| --- | --- | --- |
| magic | 6 | `SMARK1`: `SMARK` and the format version, 1 |
| setup hash | 32 | `setup_hash` of the signer's setup |
| signer | 1 + up to 128 | the signer's name (`signer_name`) |
| version | 8 | the version the name carries |
| previous version | 8 | the record before it (0 for the first) |
| previous hash | 32 | sha256 of the record before it |
| log ID | 32 | sha256 of the log's first record; zero in the first record itself |
| owner | 16 | random per runner process |
| key blob | 2 + up to 1024 | the seed of the signing key, wrapped by the platform's key release |
| mark | 32 | the core's watermark encoding |
| time | 8 | unix seconds from the trusted clock (the host clock on the flag path); the age check reads it |
| locked group | 53, or 113 with a pending update | see below |
| open group | 53, or 113 with a pending update | see below |
| pending order | 1, or 42 | presence byte, then kind (1 handover, the only kind; a reader refuses any other), hash, act time (phase 2) |
| target | 1, or 33 | presence byte, then the `setup_hash` a tombstone hands over to |
| exits | 1, or 19 + 104 per exit | presence byte, then the day (8), the stake counted that day in Gwei (8), the number of exits (2, up to 200), and per exit the validator key (48), index (8), exit epoch (8), stake (8) and the approval's nonce (32) |
| source gate | 1, or 9 | presence byte, then the source floor epoch (see "Source gate") |
| signature | 64 | Ed25519 over the context `signer-mark-v1` and the fields above |

Each group is the active version (8), the hash of the update that set it
(32; for version 0 the setup's group hash), the active body's copy number
(4) and the time that copy was written (8). A presence byte follows. With
a pending update come its version (8), hash (32), effective activation
time (8), copy number (4) and copy time (8). Version 0 has no body, so its
copy number and time are zero.

The reader refuses any record that does not read back to the same bytes:
a presence byte other than 0 or 1, trailing bytes, a log ID that is zero
in a later record or set in a first one, a target on a record that is not
a tombstone, a pending update at or below the active version, a body past
version 0 without a copy, or an order of an unknown kind.

Fail-closed reader rule. A record the reader refuses is skipped, unless
it sits at or above the newest valid record and its start (magic `SMARK`
and a digit of 1 or more, setup hash, signer, version, previous version,
previous hash, log ID, owner, key blob) names this setup, signer and
version with a key blob the runner's key release opens. Then a runner
under this key release wrote it, most likely a newer image with a field
this one does not know (a digit above 1), and the runner refuses to start
(`markstore.ErrUnreadable`). Skipping it would fall back to the mark below
it, and the runner could sign votes around the newer image's marks or
miss the day's exits it counted. Every later record format keeps that
start and the magic's form. A digit of 0 is no record.

### Source gate

A log with no vote at start (fresh, or lost and set up again) cannot
bound vote sources: the device mark holds source 0. With the restart
floor on, the runner then refuses votes with a source below the floor
epoch for every validator without imported vote history of its own
(issue #5 R2, RBRLOG-02, SSI-HISTORY-01). The floor epoch goes into the
records as the source gate, so a restart keeps it, also after a cover
write has set the mark's attestation flag with source 0. A restart drops
the gate once the log's source reaches the floor. Which validator has its
own history is in its sealed share record (`history`), set when an import
with attestation maxima stored it.

The gate covers only votes cast before the log started. A validator that
comes in later without vote history may have voted elsewhere since, so
its import sets a source floor of its own: the restart floor epoch of the
clock at the import (SLBOUND-01). The share record keeps it
(`source_floor`), and a restart sets it again. The validator signs no
vote with a source below the higher of the two floors, also after the
log's gate has dropped. Any validator added while the runner runs, with
vote history or without, may also have proposed elsewhere: the core
starts it from the device mark, whose block bound holds only what keys
here signed. So the core takes the restart floor's block and target
bounds with the key, in the same step that loads it. The key signs no
block or PTC vote up to the last slot of the floor epoch and no vote
with a target up to it (a restart floors every key again).

A record is about 420 bytes on the dev platform, 60 more for each
pending update, and 150 to 250 more with a cloud KMS ciphertext in the
key blob.

The log ID is the sha256 of the log's first record. Every later record
carries it, and a record that links to a predecessor with another log ID
stops the start. The runner seals stored shares under it (see "Shares"
below).

### Update bodies

The runner stores a config update (`CONFIG_UPDATE`) as
received, signatures included, before the record that
names it:

    config/<setup_hash hex>/<locked|open>/<version, 20 digits>/<copy>

The runner writes copy 1. If that name holds another object, it skips to
the next copy number, up to 16 in a row. A copy counts only by its
content: the reader decodes it and compares its hash with the hash the
record names. The record keeps the newest copy number and its time. When
that copy is older than half the retention, the runner writes copy n+1
and then a record that names it, so a body never expires while the
runner runs.

## Record keys

Each runner process makes its own Ed25519 signing key at Claim: a random
32-byte seed from the platform's key release (`platform.Keys`), bound to
the context `signer-mark-key-v1`, the `setup_hash` and the signer name.
A blob made for one setup or signer does not open for another. The
wrapped seed goes into every record the
process writes. A reader opens the key blob with the key release, checks
the signature with the key inside, and drops the record if the blob does
not open. Nothing about the keys is in the state directory, so a runner
that comes back without its state (ACI, a Confidential Space VM) reads its
log the same way: the restart needs no operator step for the mark.

| | Key release the runner gets | `platform.Keys` |
| --- | --- | --- |
| AWS Nitro | KMS `GenerateDataKey` and `Decrypt` with the enclave's attestation as recipient; the key policy allows them for the measured PCRs only. No key material leaves KMS except to the enclave. | `GenerateDataKey` with the encryption context `{signer-key: <aad, hex>, signer-setup: <setup_hash, hex>}`, `Decrypt` with the same context. The key policy lets the admin role `kms:Encrypt` only with exactly `{purpose: record-creds}` (`platform-aws/deploy/main.tf`), so no one outside the enclave can make a key blob. |
| GCP Confidential Space | Cloud KMS `encrypt` and `decrypt` through the federated token of WIF, whose provider condition pins the image digest. An oracle, no key material. | random seed, KMS `encrypt` with `signer-runner gcp key wrap v1`, setup_hash and the aad as additional authenticated data, `decrypt` with it. Encrypt and decrypt are one role (`cryptoKeyEncrypterDecrypter`). |
| Azure ACI | the exportable RSA key itself, released by Key Vault against an MAA token whose host data matches the key's release policy (the CCE policy hash). | AES-256-GCM under HKDF-SHA256(the released key's private exponent, info `signer-runner azure key wrap v1` and setup_hash). Derived, not stored. |
| dev | nothing (public key) | AES-GCM under a public key made from `-platform-opt measurement=...` (a stand-in for the image measurement in tests) and setup_hash |

Why a wrapped key per record and not a key derived from key release (one
key for all processes): derivation needs key material, and only Azure
releases any; AWS and GCP give a wrap and unwrap operation, and their
symmetric encrypt is randomized. A wrapped key in a separate object would
need its own name rules and could expire before the records; inside the
record it lives as long as the record does.

What a key blob that opens proves: it was made by a holder of the key
release for this aad, which is the attested runner of this image and
position (the position, `-mark-signer`, is in the measurement on all three
clouds and in the aad), or whoever controls key release (see below). A
runner of another image gets no key release at all (Azure, GCP: Key Vault
and STS refuse it; AWS: KMS refuses its PCRs). A runner whose key release
is a different one (another Azure key version, another KMS key) cannot open
the blobs: to it, the log holds objects but no valid record, and it refuses
to start.

Only a definite "does not open" makes a record invalid: KMS
`InvalidCiphertextException` or `IncorrectKeyException`, a Cloud KMS 400, a
failed AES-GCM open. Any other error of the key release (KMS out of reach,
access denied, throttling) stops the start, so a record that could not be
checked is never taken for an invalid one; skipping the newest record would
roll the mark back.

## Rules

- Write before sign. The core calls `store_device_mark` before it signs
  past the committed mark; the runner returns only once the record is
  durable (a conditional create: S3 `If-None-Match: *`, GCS
  `ifGenerationMatch=0`, Azure `If-None-Match: *`). A lost reply is read
  back: the runner's own record means success.
- Raise ahead. At slot 24 of epoch E (three quarters in, `-mark-raise-slot`)
  the runner raises the mark for E+1 (`sc_signer_cover_epoch`), so the
  write happens with about 1.5 minutes to spare. A vote with a new source
  still writes at that vote (the source bound is the highest source
  signed; raising it ahead would refuse later votes with a lower source).
  So while the chain finalizes there are up to two writes an epoch, one
  while it does not.
- Lock check. At every start, before the claim, the runner reads the
  store's lock over its own TLS and credentials (`markstore.CheckLock`).
  S3 must have Object Lock in compliance mode, GCS a locked retention
  policy, Azure a locked container immutability policy. The retention
  must be at least the setup's `slashing_log_min_lock_days`. Otherwise the
  runner stops. The file log of the dev platform has no lock, and the
  dev platform skips the check.
- Shares, listed once. The runner lists its stored shares once, before
  the claim. The claim learns from that list whether the node holds
  shares, and the runner loads only that list. A share that a later
  listing shows is never loaded.
- Start. The runner lists every object (every version, on S3 and GCS),
  verifies each, takes the highest valid version and checks the chain:
  no valid record between it and the record it names, and that record,
  if still there, hashes to the link and carries the same log ID. Then it
  writes a claim record (same mark and config state, its own owner ID,
  its own key). Any error, the store or the key release unreachable
  included, stops the start: a runner that cannot read its log does not
  sign.
- Age check. When the newest record is older than half of
  `slashing_log_min_lock_days` on the trusted clock, update bodies may have
  expired, and the runner stops. That signer needs a new setup and a share
  re-import. So `slashing_log_min_lock_days` bounds how long a signer may stay
  stopped: half of it.
- First start. An empty log and no shares listed: the claim record is
  record 1, with the setup's first config state (version 0 of both
  groups), and its hash is the log ID. An empty log with shares listed
  stops the start.
- Bodies at start. The claim reads one copy of every update body the
  newest record names. A body with no readable copy does not stop the
  start; the runner refuses to sign once its config in force needs that
  body. Sending the same update again writes a new copy and restores it.
- Keep alive. While the runner runs, `Refresh` writes a new copy of every
  body older than half the retention, and a record when it wrote a copy or
  when the newest record is older than the retention / 8 (at most a day).
  A runner with a setup calls it every hour (`RefreshLoop`).
- Nothing valid. A log with objects under record names but no valid record
  stops the start, with or without shares: those may be records whose keys
  this key release cannot open, and starting over would drop their mark.
  An empty log stops the start of a node that holds shares. `-mark-create`
  overrides both on the flag path; setup images have no override.
- Restart with lost state. The state directory held the sealed shares, the
  sealing key's wrapped blob and the hint. With the state copy
  (`-state-store`, `slashing-log/docs/durable-state.md`) the platform restores the
  sealing key and the shares before the claim; the hint is not in the copy,
  so the claim compares nothing. Without the copy the runner makes a new
  sealing key, holds no share, reads the log as above and claims it, and the
  operator imports the shares again (sealed import to the new boot key, as
  after any new deployment). Either way the runner signs from the log's
  mark: the source bound comes from the log, the floor adds its target and
  block bounds. A share imported again without vote history (no EIP-3076
  attestation maxima) also gets its own source floor, the restart floor
  epoch at the import. Its first vote then waits about margin + 2 epochs:
  the source must reach the floor and stay below the clock epoch.
  `tests/e2e` `TestE2EMarkLogLostState*`,
  `TestE2EDurableState*` and `attestation-verify/runnerclient`
  `TestE2EAzureRunnerMarkLogLostState`, `TestE2EAzureRunnerDurableAndHandover`
  run this on each platform build.
- Merge. A record holds the merge of the mark before it and the new one, so
  the log's mark never goes down. An import with interchange maxima (an
  EIP-3076 import, or a handover's mark) raises the log before
  the share is stored.
- Tombstone. A handover (`slashing-log/docs/durable-state.md`) ends the log
  with a record whose bounds are all 2^64-1. Nothing appends after it, and a
  runner that reads it writes no claim and refuses every slashable message.
  A runner with a setup hands over to one named target only: the tombstone
  carries the target's `setup_hash` (`HandOverTo`), and a second target is
  refused. Phase 1 images hand over to no one.
- Hint. After each write the runner keeps the version and hash it wrote,
  sealed in the platform store under the context `signer-mark-hint-v1`,
  the `setup_hash` and the signer. At start a hint above the newest record in
  the log (records hidden, a stale listing) or a different record at the
  hint's version stops the start. The host can roll the hint back, not
  forward, so it can only make the hint say less.
- Clone. A second instance (from the same sealed state, or a second group
  or VM of the same image) claims the log with its own record. The first
  instance's next write then finds its name taken by a valid record of
  another owner: from then on it signs nothing new (`ErrLost`, refusals
  with `SC_ERR_STORAGE`). Names stay write-once, so two live instances
  conflict on create.
- Store down while running. The core keeps signing inside the committed
  mark and refuses what lies above it until a write succeeds again.
- Restart floor. With the log the floor keeps only its target and block
  bounds; the source bound comes from the log. That removes the floor's
  stall while the chain does not finalize: in the fuzzer's 200 epochs of
  non-finality (`nonfinal200`) the `cloud` profile lost a mean of 74 and
  at most 99 epochs per key after each restart, the `cloud-ext` profile
  (the mark log) 3 and 3 (the floor's margin), with no validator miss.
- Objects that are not records under future names (anyone with write
  access can create new names) cost the writer a skip each, up to 16 in a
  row; readers ignore them. A copy of an old record under a new name does
  not verify there (the version inside differs from the name).

## Shares

A stored share is sealed under the AAD `signer-share-v1`, the
`setup_hash`, the log ID and the validator key (`markstore.ShareAAD`). A
runner with a setup stores and loads no share until its claim has given it
a log ID.

This closes the case of setup-phase review E. A host keeps
the signer stopped past the retention, deletes the expired records and
hides the shares at the listing. The runner then finds an empty log and no
shares, so it starts over with the setup's first config. The new log has
another log ID, so no share from before ever opens in it, even if the host
shows the shares again later. Verifiers that pin a minimum config version
refuse to import into it.

## Config state API

Config updates (`tee-signer/server/config.go`, CONFIG_UPDATE in
[protocol.md](../../signer-protocol/docs/protocol.md)) build on these calls of `markstore.MarkLog`:

| Call | What it does |
| --- | --- |
| `State()` | the config state of the newest record, read or written |
| `PutBody(ctx, raw)` | stores a signed `CONFIG_UPDATE` as received, before the record that names it; returns its group, version and hash; the same update again writes nothing |
| `SetState(ctx, st)` | appends a record with the log's mark and state `st`: a new pending update, one that became active, one replaced or dropped; every body `st` names must be in the log; an active version never goes down |
| `Body(group, version)` | the stored update, for `CONFIG_STATE` and the effective config; `ErrBodyMissing` without a readable copy |
| `LogID()` | the log ID, for the share AAD |
| `Refresh(ctx)`, `RefreshLoop(ctx, every)` | the body copies and keep-alive records |
| `HandOverTo(ctx, target)`, `HandedOverTo()` | the tombstone that names its target (phase 2) |

`markstore` checks the shape of a state, not the rules of section 6
(signatures, waits, supersede). `tee-signer/server/config.go` checks those,
writes the body before the record that names an update pending, and
writes the record that shows an update in force once its effective time
has passed.

## The stores

| | AWS | GCP | Azure |
| --- | --- | --- | --- |
| Store | S3 bucket, versioning on, Object Lock default retention in compliance mode | Cloud Storage bucket with a locked retention policy (Bucket Lock) | Blob Storage container with a locked time-based retention policy |
| What the admin cannot do | delete or overwrite a locked version ("can't be overwritten or deleted by any user, including the root user") | delete or replace a retained object; reduce or remove the locked policy | modify or delete a locked blob ("not even by users with account administrative privileges") |
| What the admin can do | add versions and delete markers (the reader lists every version) | create new names | create new names |
| Client | `platform-aws/s3log`, SigV4 of our own, `platform_aws` | `platform-gcp/gcslog`, JSON API, `platform_gcp` | `platform-azure/azlog`, Blob REST, `platform_azure` |
| Credentials | the enclave's record credentials (an IAM key the enclave holds, as for DynamoDB) | the workload's federated token (Confidential Space, WIF; the same as for KMS) | the container group's managed identity, resource `https://storage.azure.com/` |
| Lock check reads | `GET /?object-lock` (GetObjectLockConfiguration); needs `s3:GetBucketObjectLockConfiguration` | `GET /storage/v1/b/B?fields=retentionPolicy`; needs `storage.buckets.get` | the management plane's immutability policy of the container; needs a token for `https://management.azure.com/`, the subscription and the resource group, and read access to the policy |
| `-mark-store` | `s3:bucket=B,region=R[,endpoint=URL]` | `gcs:bucket=B[,endpoint=URL]` | `azblob:account=A,container=C[,endpoint=URL][,subscription=S,resource_group=G[,arm_endpoint=URL]]` |

`file:DIR` is a write-once file log for tests and the dev platform; the
host can delete its files, so it tests the format and the rules, not the
lock. `check-deps.sh` keeps each client in its own cloud's build.

The Azure data plane says only whether a container has a policy
(`x-ms-has-immutability-policy`), not its state or its period. So the
Azure lock check reads the management plane, and fails closed without the
subscription, the resource group and the token. An Azure store in a setup
names `subscription` and `resource_group` next to `account` and
`container`; the runner puts them into the store spec, and the platform
gives the managed identity's token for `https://management.azure.com/`.
The identity needs read access to the container's immutability policy:
Reader on the container scope (`platform-azure/deploy/deploy.sh store-role N`).
The account name is unique across Azure, so a wrong subscription or group
in the setup finds no policy (404), and the check fails closed.

### Bearer tokens

GCS and Azure requests carry an OAuth bearer token. `markstore.TokenCache`
keeps one per token source: the mark log's store, the Azure lock check and
the state copy each have their own. It fetches a token on the first
request and refreshes it in the background, so a request does not wait
for the token exchange.

A GCP token comes without an expiry here, so the cache assumes an hour
from the fetch. It refreshes from 30 minutes on and fetches again at 50
minutes. Azure IMDS gives `expires_on`, and the cache goes by it. IMDS
caches tokens and can hand out one with minutes left, so an hour from the
fetch is wrong there. The cache:

- refreshes at the earlier of 30 minutes after the fetch and 10 minutes
  before the expiry;
- never hands out a token within 2 minutes of its expiry; the request
  waits for a fetch instead;
- asks again after 1, 2 and 4 s when IMDS gives a token with under 5
  minutes left, and takes the last one if it still has over 2 minutes;
- runs one fetch at a time; requests that waited take its token.

On a 401 the Azure client drops the token, fetches a fresh one and sends
the request once more. A second 401 is the error. The error text names
the code, the `AuthenticationErrorDetail` and the `WWW-Authenticate`
header, which say why Azure refused the token.

Retention bounds how long a signer may stay stopped: the age check stops
a runner whose newest record is older than half of `slashing_log_min_lock_days`.
For production, set it to at least the signer's planned life. A compliance
mode bucket cannot be emptied before its retention ends, so a long
retention keeps a test bucket for that long.

## Any m of n, boards and clouds

Each signer keeps its own mark in its own rollback-proof place: a board
in RPMB (the TA's signer state), a cloud runner in its locked log. Nothing
in the mark log depends on the number of signers or on the threshold, so a
cluster of any m of n, of boards, cloud runners or both, needs no change.
What protects the cluster is that every signer refuses on its own: in the
hostile-routing case of the research note (m-1 signers rolled back, one
honest signer that missed the first vote), each rolled-back signer still
holds its true mark.

## What it does not cover

- An admin who also controls key release (the AWS KMS key policy, the GCP
  WIF provider and the KMS key's IAM, the Azure key's release policy) can
  decrypt the sealed share, make key blobs and forge records. The store
  resists the admin exactly as far as key release does (research note,
  section 2.2). On GCP the KMS key and the bucket grant their roles to the
  WIF pool's principal set only (`platform-gcp/deploy/README.md`), not to
  the service account the VM runs as.
- A new key release. The record keys open only under the key release that
  made them. On Azure each image gets a new Key Vault key version (the
  release policy pins the CCE policy hash), so a new image cannot open the
  old image's log: it gets a new `-mark-signer`, and the old runner hands
  over its shares and its mark (`slashing-log/docs/durable-state.md`), or the operator
  imports the shares again as for a new deployment. On AWS and GCP the KMS
  key stays and the policy or WIF condition moves to the new image, which
  then reads the old log.
- A signer down longer than half the retention period: the age check
  stops it, and it needs a new setup and a re-import.
- S3's default retention is a bucket setting. An admin with
  `s3:PutBucketObjectLockConfiguration` can lower it after the start's
  check, and records written after that get the shorter retention. GCS and
  Azure lock the policy itself.
- Real cloud stores: the tests use local fakes of the three APIs
  (`slashing-log/wormfake`). The lock reads
  are untested against the real APIs.
