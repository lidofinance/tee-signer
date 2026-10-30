# Durable state and the handover

Three mechanisms for the clouds whose runner keeps its state on
a disk that does not outlive the container or VM (Azure ACI, GCP
Confidential Space):

1. The state copy (`-state-store`, `slashing-log/statestore`): the sealed shares,
   the wrapped sealing key and the rest of the state that matters live in an
   object store as well, and a restart restores them before the mark log
   claim.
2. The handover: on Azure a new image cannot open the old image's sealed
   data or mark log, so the old runner verifies the new runner's
   attestation and hands its shares and its mark over, under an
   approver-signed handover order.
3. On GCP, key release only through attestation: the KMS key and the
   buckets grant their roles to the WIF pool's principal set, not to the
   service account the VM runs as (`platform-gcp/deploy/README.md`, "Key release
   through the principal set").

Nothing here is tested on a cloud. The tests use the fakes of
`tests/e2e` and `attestation-verify/runnerclient` (see "Tests").

## The state copy

### What it holds

The platform store (`-state-dir`) holds, by prefix:

| Prefix | What | In the copy |
| --- | --- | --- |
| `sealing/` | the sealing data key, wrapped by key release (Azure: RSA-OAEP to the released Key Vault key; GCP: Cloud KMS) | yes |
| `shares/` | the sealed shares | yes |
| `mark-hint/` | the mark log's hint, written with every record | no |
| `rr/` | repeat roots of builds with `-persist-repeat-root` (removed); never read, can be deleted | no |
| `wm/` | persisted marks (not used with the mark log) | no |

Without the hint a restart compares nothing. That is no safety loss, and
the hint changes on every mark record, so a copy of it would cost a write
per record. `statestore.Durable` is false for `mark-hint/`, so `Put` writes
no object (`TestPerVoteKeysStayLocal`).

AWS keeps its store on the parent instance through the host agent; it
survives an enclave restart, so the AWS build does not call the copy (the
runner refuses `-state-store` on `nitro`).

### Format

The copy is a log of commits. One change of the durable keys, a `Put`, a
`Delete` or a `platform.Change` of many keys through `Apply`, is one commit,
one object:

    state/<setup_hash hex>/<signer>/<version, 20 digits>

A commit lists the segments that hold the state and carries its own
changes when they are small. A segment is a sorted list of puts and
deletes, split into chunk objects:

    state/<setup_hash hex>/<signer>/c/<SHA-256 of the chunk object, hex>

The state a commit describes is its segments applied in order, then the
changes that the commits since the last segment carry (the chain), oldest
first. Each commit names the one before it by version and SHA-256, so the
newest commit alone leads to everything the state needs.

The path holds `setup_hash`, as the mark log's does, so a new setup with
the same signer name starts with an empty copy. The flag path without a
setup keeps `state/<signer>/`.

Every object:

| Field | Bytes |
| --- | --- |
| magic | 7: `SSTATE1` a commit, `SCHUNK1` a chunk (format version 1; the runner reads no other) |
| version | 8, the version the name carries; 0 in a chunk |
| time | 8, unix seconds |
| key blob | 2 + up to 65535: the object key, wrapped by `platform.Keys` with the aad: context `signer-state-key-v1`, `setup_hash`, signer |
| nonce | 12 |
| ciphertext | AES-256-GCM of the body, aad: context `signer-state-v1`, `setup_hash`, `len:u8` signer, and the header above |

A commit's body:

| Field | Bytes |
| --- | --- |
| previous commit | 8 + 32: its version and the SHA-256 of its object |
| chain | 2: the commits whose changes are in no segment, this one included; 0 when this commit wrote them into a segment |
| state summary | 8 + 8 + 32: entries, bytes of keys and values, and the sum mod 2^256 of every entry's SHA-256 |
| segments | `count:u16`, each `created:u64 entries:u32 bytes:u64 chunks:u32`, each chunk `sha256[32] size:u32` |
| changes | `count:u32`, each `key_len:u16 key kind:u8` (0 put, 1 delete) and for a put `value_len:u32 value`, sorted by key; empty when chain is 0 |

A chunk's body is a list of changes in the same encoding. A segment's
chunks hold its keys in order; segment 0 holds no deletes. The magic is in
the AAD, so no kind of object opens as another.

Every object is at most 1 MiB, the read limit of the store clients
(`s3log.go:358`, `gcslog.go:210`, `azlog.go:253`): a chunk holds at most
960 KiB of changes, a value at most 256 KiB (`MaxEntry`; the largest the
runner writes is a session record, about 17 KB for 64 keys of three
participants), and a commit carries at most 128 KiB of changes.

The object key comes from the same key release as the mark log's record
keys: Key Vault's released key on Azure, Cloud KMS through WIF on GCP. The
store's admin can read nothing (the key blob opens only for the attested
runner) and cannot change an object without the open failing; a commit
copied under another version name or another signer's prefix fails too,
and a chunk must hash to the name its commit holds.

The names are created once (S3 `If-None-Match: *`, GCS
`ifGenerationMatch=0`, Azure `If-None-Match: *`) through the mark log's
clients (`markstore.Log`), so the copy works on the locked bucket of the
mark log as well as on a plain one. A commit name taken by a valid commit
of another process means a clone: that process changes no durable state
from then on (`ErrLost`). Objects that are not commits cost a skip each,
as in the mark log.

### All or nothing

A change is in the copy if and only if its commit object exists. `Apply`
writes every chunk the commit names first and the commit object last, and
a restore reads the state only through a commit. So a write that fails at
any step leaves the copy at the commit before; chunks without a commit are
never read. If the create of the commit object fails without an answer,
the runner reads the name back, and its own object there means the change
landed. If the create lands only later, the next commit's create at that
version finds it and the process stops changing state (`ErrLost`); a
restart restores it.

The local store follows the copy: `Apply` writes the local files after the
commit. If they fail, the process refuses further changes until a restart,
which writes them from the copy.

### Segments and compaction

A commit carries its changes when they take at most 128 KiB, the changes
carried since the last segment at most 256 KiB, and fewer than 64 commits
carry theirs. Otherwise it writes them, with those of the chain, as a new
last segment. Then, while the segment before the last is at most twice the
size of the last, the two merge into one; a merge into segment 0 writes the
whole state without deletes. So each segment is more than twice the size
of the next: a state of S bytes whose newest segment has L bytes is in at
most log2(S/L) + 1 segments, and a byte is written again about that many
times. A change of a few
keys uploads one object of its own size plus the segment list: at 8,192
keys one small change writes one object under 8 KiB
(`TestWriteCostPerSessionIsFlat`). A restore reads at most 64 commits and
the segments' chunks.

The writer keeps the state in memory, about the size of the durable state,
so it writes merged segments without reading them
back.

### Write and restore

- Write. `Put`, `Delete` and `Apply` write the commit first and then the
  local files. If the commit fails, the call fails and the local store
  stays as it was: an import is refused rather than kept on a disk that
  will be lost.
- Restore. The platform calls the copy once its key release works and
  before it reads its sealing key (`platform.Options.Durable`). The copy
  lists every object (every version on S3 and GCS) and takes the highest
  version whose commit opens and whose chunks and chain commits are all
  there and open. It rebuilds the state, checks it against the commit's
  summary, writes the entries into the local store and deletes the local
  keys whose last change in the copy is a delete (a crash between the
  commit and the local delete). It writes the local files without an fsync
  each and syncs the file system once (`filestore.PutMany`): the copy holds
  them. Then the platform unwraps the sealing key it just restored, and only
  then does `main` claim the mark log. So the claim sees the stored shares
  and expects a log with records, as on any restart.
- Fail closed. Any error of the store or the key release stops the start.
  So do: objects under commit names of which none opens with every object
  it needs (another key release, or chunks lost; `-state-create`
  overrides), two different valid commits at the newest version, a rebuilt
  state that differs from the commit's summary, and a local durable key that
  the newest commit neither holds nor deleted (the copy lost commits, or the
  local state came from elsewhere). A commit whose chunks or chain commits
  are missing or changed is skipped for the one before, a rollback as
  below.
- No copy yet but local state (a disk that survived, the copy turned on
  later): its local state becomes the first commit.
- Refresh. `-state-refresh` (default 24 hours) writes the whole state as
  segment 0 when the oldest object the newest commit needs is that old, so
  on a locked bucket no object the state needs comes out of retention.

### Where to keep it

In the mark log's bucket or container, under `state/` (`-state-store` with
the same value as `-mark-store`; `platform-gcp/deploy` `STATE_STORE="$MARK_STORE"`,
`platform-azure/deploy` `STATE_STORE_N="$MARK_STORE_N"`). The runner needs no new
role, and the lock keeps every object for the retention period, so the
admin cannot delete the newest commit or a chunk it needs. A plain bucket
also works; then the admin can delete objects, which the next section is
about.

The runner deletes nothing in the store. It holds what the runner wrote over
the retention period: here a mean of 0.4 to 0.7 MB per 64-key session on a
runner that signs deposits, plus the whole state once a day ("Cost").

### Why a rolled-back copy is no slashing risk

Assume the admin of a plain bucket deletes the newest commits or a chunk,
so a restart restores an older commit. The restored state differs in which
shares it holds, never in a mark:

- The mark the runner signs under comes from the locked mark log, read at
  the claim after the restore. No commit holds a mark (the hint is not in
  the copy, and the hint can only make the claim refuse).
- A share carries no slashing state. An older commit has fewer shares, or
  the shares before a later import of the same validator: the runner then
  holds less, which costs liveness, and signs every message under the
  log's mark either way.
- The sealing key in an older commit is the one the shares of that commit
  are sealed with (the key changes only on a first start, which the commit
  records). Nothing opens with a mixed set.

Where it would matter: a reshare. If the cluster ever reshares a validator
to retire shares an attacker holds (t-1 old shares leaked), a runner whose
copy rolls back to its old share brings that share back to life. It still
signs under its mark, but its partial signature with the old share is the
t-th one the attacker needs, and the honest runners sign with the new
shares: two full signatures of one validator for the same target, one per
share set. The code has no reshare today (nothing replaces the share of an
existing validator), so this is a
condition on a future feature: with a reshare, keep the copy in the locked
bucket (it cannot be rolled back while retention holds and refresh runs),
or bind the share set's generation into the mark log.

### Cost

A commit of many keys uploads about the same amount whatever the size of
the state (`TestWriteCostPerSessionIsFlat`, which writes keys as the key
generation of earlier builds did). Merges into segment 0 write the whole
state, so the mean upload per commit grows with the log of the state. A
restart reads the copy also when the state directory is kept.

On a cloud object store each commit is at least one object create.

### Design notes

- One change per COMMIT. COMMIT writes the shares and key records of a
  session as one change, and loads the shares after it, so a failed write
  leaves no share without its key record, and a retried COMMIT writes a
  missing key record.
- The file store's `List` walks only the prefix's folder, not the whole
  state directory.
- The file store fsyncs each file, and a 64-key COMMIT writes 129 files.
  With the copy, the local writes after a commit and the restore sync the
  file system once instead (`syncfs`); without the copy (Nitro) each write
  syncs.
- Deposit signing writes the key record on each SETUP_SIGN, so one commit
  per signature: 64 per 64-key session on a runner that signs, in the
  request path. On a cloud store each is a PUT request. Fewer would need
  the coordinator to send several deposits per request, which the protocol
  does not have.
- The restart lists the whole prefix, chunks and every version included, so
  the listing grows with what the store keeps, not with the state.
- PUBLIC_KEYS fails above 10,082 keys, because its answer must fit one
  1 MiB frame.

## The handover (Azure)

### Why Azure needs it

On Azure each image gets a new Key Vault key version whose release policy
names the image's CCE policy hash, and the release policy cannot change
afterwards. A new image gets the new version only: it opens neither the old
image's sealing key (so not its sealed shares or state copy) nor its mark
log records (the record keys come from the released key). With key
generation inside the runner there is no other copy of the share. So the
old runner itself has to hand the shares to the new one.

### The mark: a new log above the old mark

The new runner keeps a log of its own (a new `-mark-signer`, which is in its
CCE policy) whose mark starts at least at the old runner's mark. Continuing
the old log would need the new image to open the old records, which on
Azure means handing over a key derived from the old released key and
keeping it sealed in every later image: each upgrade would add a key and
tie the new image to the old key versions. The new log needs nothing from
the old key release, keeps each image's log under its own release policy,
and leaves the old log locked as evidence.

What makes it safe:

- The old runner's mark is at least everything it signed: the core signs
  past its committed mark only after a record is durable, and that record's
  mark is the one handed over.
- The tombstone (block slot, source and target all at 2^64-1) ends the old
  log. After it every append fails, so the old core signs at most inside
  its committed mark, and the server refuses every request but `HEALTH`,
  `PUBLIC_KEYS`, `ATTEST`, `IDENTITY` and the handover messages. A restart of the old
  image reads the tombstone, writes no claim, loads it as its mark and
  refuses everything, with this runner version or an older one.
- The new runner refuses targets and blocks at or below the old mark and
  sources below it, so a vote of the old runner and one of the new can be
  neither a double vote nor a surround.
- The mark travels inside the HPKE associated data of each share: the
  operator cannot lower it without the import failing, and only the old
  runner holds the share to seal. A runner that never had the share cannot
  make such a package.
- The new runner raises its log before it stores the share. If its core
  then refuses the maxima, the validator stays blocked until a restart,
  which reads the raised log. The sealed import with interchange maxima in
  mark log mode raises the log the same way.

The handover can be asked for again for the same target (the same mark
comes back, also after a restart of the old runner, from the record before
the tombstone).

### AWS and GCP

Not needed there. AWS KMS key policies and the GCP WIF provider condition
can name the new measurement next to the old one: the old ciphertext, the
old log's record keys and the state copy stay readable, and the new image
reads its predecessor's log as on a restart. The handover works on every
platform whose attestation the runner's verifiers check.

The trade-off: those policies are mutable. An account admin who edits the
KMS key policy or the WIF condition can let an unmeasured or debug workload
release the key, at any time, without anyone's signature. Azure's release
policy is immutable per key version, which is stronger; the price is the
handover, and the approvers' handover order is the new trust point. On AWS and GCP the
handover would add nothing as long as the admin can rewrite the policy.

## Handover under an order (runners with a setup)

A runner with a setup, in a release build, hands over
under an approver-signed handover order (`signer-protocol/docs/protocol.md`,
"Handover").

- HANDOVER_ORDER (0x31, `tee-signer/handoverorder`): k approvers in force
  sign an order that names this runner's setup as the source and one
  target: its setup_hash, image and verifier settings. The runner checks
  it, keeps the body sealed in the host store and records it as the
  pending order in the mark log's state. It acts the time lock in force
  after its arrival, and at least the images minimum (7 days, 7 minutes in
  a testnet build; the time lock only on dev). A rotation drops it.
- HANDOVER (0x32, `tee-signer/handover` message.go, `tee-signer/server`
  handover_source.go) carries the order, the target's IDENTITY answer and
  its published setup. Before the tombstone the runner checks the order
  (its wait, not_after, signatures and the image list in force), that no
  config update is pending here, and the target: its
  published setup hashes to the order's setup_hash and its attested
  identity carries it; the attestation verifies with the order's settings;
  cluster_id, chain and safety are this runner's, handover_generation is
  one higher, version 0 of both groups equals this runner's config in
  force; it holds no key, has nothing pending, holds this order in its
  slot and has room for every share.
- Then it stops signing and adding shares, reads every share once,
  writes the tombstone that names the target (markstore `HandOverTo`) and
  seals each page from that read. After the tombstone, also after a
  restart, it answers that target only, with the same mark.
- Each share's header adds its key origin (imported, or generated under
  a DKG order in an earlier build, from its sealed record) to the sealed
  import's header. The page carries the carry: the key set handed over and the
  day's exits of the mark log. Each share is sealed under the HPKE
  associated data `signer-handover-share-v1` over its header and the
  carry's hash. The runner signs each header with an origin key it makes
  per process, and the response carries the attestation of that key
  (`signer-handover-origin-key-v1` over the order hash and the key). A
  target that checks both with the order's source settings can count the
  shares as generated; without that check it must count them as imported,
  because anyone can seal a share to its public import key.

### The target

A runner with a setup takes the sealed pages as a target, in a release
build: IMPORT_HANDOVER (0x33, `tee-signer/handover`
import.go, `tee-signer/server` handover_import.go). Its setup comes from
`signer-config setup -handover-from`: the source's cluster_id, chain and
safety, handover_generation 2, version 0 of both groups equal to the
source's config in force. So its first mark log record, the claim of a
fresh log, carries that config as version 0 of both groups.

- Each request carries the signed order and a page, or part of one. The
  order must name this runner's setup_hash as its target, this cluster and
  chain, and verify under the approvers in force here, which are the
  source's. Its not_after does not apply: the source answers its target
  after it, and an import a restart cut must go on.
- The first request finds the runner empty (no key, version 0 of both
  groups, nothing pending, handover_generation 2 or more, max_keys of at
  least the total) and passes every check below before the runner writes
  the order into the order slot of its mark log's state. It checks version
  0 and no key again while it writes, under the locks of config writes and
  share additions, so an update or a share that came in meanwhile stops
  the start. From then on it signs nothing, takes no plain sealed import
  and no CONFIG_UPDATE, and HEALTH is not ready, also after a restart: the
  slot is in the locked log. Only the record that ends the import clears
  the slot, once the runner holds exactly the carry's key set and a share
  of the request opened under that carry: a rotation that comes into force
  keeps it, and later requests of the same order need no approvals in
  force again.
- The origin proof must verify with the verifier and image the order names
  for the source (the dev verifier on the dev platform only), and every
  share's header under the origin key. Then a generated share keeps its
  origin and DKG order hash in its sealed record, so the key origin counts
  survive restarts; an imported one counts as imported. A runner that
  cannot check the proof refuses, unless the request asks to count every
  share as imported (`handover-target import -as-imported`).
- Each share opens with this boot's import key under its header and the
  carry's hash, so a lowered mark, an edited origin or an edited carry does
  not open. The carried exits go into the mark log before the import ends. The mark log is raised
  to the mark before the share is stored, as for a sealed import with
  interchange maxima; a source that never signed hands over an empty mark
  and no maxima. Every request of one process carries the same mark.
- A validator held with the same share counts as held, so a resumed import
  skips what is in. After a restart the import key is new: the tool reads
  the identity again and the source seals again for it.

## The network entry's node state

The runner has no network entry code. A testnet build can add one through
the build hook `SIGNER_BUILD_OVERLAY_DIR` (`scripts/common.sh`). Such an entry may keep its node
state in the runner's store, sealed and bound to setup_hash like the
shares, so the state copy holds it too. On AWS a network entry runs on the
parent, which is untrusted, so its state gives no way into the enclave.

Longer-term options for the network credential: threshold-signer-poc
`research/network-entry-credentials.md`.

## Settings

| Flag | |
| --- | --- |
| `-state-store` | the copy, same syntax as `-mark-store` (`file:`, `s3:`, `gcs:`, `azblob:`) |
| `-state-create` | start over when no commit opens under this key release with every object it needs |
| `-state-refresh` | write the whole state again when the oldest object the newest commit needs is this old (default 24h, 0 off) |

Images: `platform-gcp/deploy` `STATE_STORE`; `platform-azure/deploy` `STATE_STORE_N`. Both
are off unless set. Setting one changes the command line, and with it the
CCE policy hash or the image digest.

## Tests

- `slashing-log/statestore`: restore after lost state, another key release
  refused (and `-state-create`), changed and copied commits, a local key
  the copy lacks, the first commit of old local state, a clone, the key
  release down, the value limit, refresh. Commits: each write of a
  three-object commit failed in turn, refused and with the reply lost, the
  copy holding the state before or after and the same process writing the
  change again (`TestApplyAllOrNothing`); 4,000 random commits against a
  model with restarts from the copy alone (`TestCommitsAgainstModel`);
  8,192 keys written as the key generation of earlier builds wrote them,
  upload per batch flat, every object under 1 MiB, one small change one
  small object (`TestWriteCostPerSessionIsFlat`); a lost
  chunk (fallback to an older commit, then refusal); a delete finished at
  start; hints never uploaded; refresh compacting.
- `platform/filestore`: `PutMany`, `Delete`, `List` by folder.
- `slashing-log` `TestHandOverTombstone`, `TestUntargetedTombstone`,
  `TestAppendMerges`; `tee-signer/handover` and the handover tests of
  `tee-signer/server`; `platform-gcp/gcp` `TestFederatedTokenWithoutServiceAccount` (KMS and
  storage with the federated token, no IAM call; with `service_account` the
  impersonation fails, since the roles sit on the principal set).
- `tests/e2e`: `TestE2EDurableStateDev` and `TestE2EDurableStateGCP` (the
  GCP debug build, mark log and copy in one locked GCS fake): the state
  directory is wiped, the share comes back, a vote below the log's source is
  refused at every epoch and the log's source signs; another image does not
  start on the copy. `TestE2EHandoverGate`: three images hand over in turn
  through the two tools.
- `attestation-verify/runnerclient` `TestE2EAzureRunnerDurable`: the Azure debug build
  with fake SNP, MAA and Key Vault; the file system lost and restored.
- Fuzzer (threshold-signer-poc `signer-core/sim`): `OP_WIPE` covers the restored
  share (the copy does not hold the hint, which the event wipes); `OP_HANDOVER` hands a signer over to a new instance with a log of
  its own, the old one staying up in the clone slot. Negative controls:
  handover with the tombstone 0 violations, with the old log left open
  violations.

## What needs a cloud check

- Azure: MAA's key set at `https://<provider>/certs` as the runner fetches it
  (format: `x5c` and `n`/`e`), a real token's claims in the handover's
  verifier, and the runner's TLS trust of the provider from inside the group. A group
  restart with the container's file system gone, restoring from the locked
  container. The handover between two real groups with two key versions.
- GCP: the STS exchange followed by KMS and Cloud Storage calls with the
  federated token (no service account), and a VM recreated with its disk gone restoring from the bucket.
- All: commit and chunk sizes and timing on the real stores (one commit per
  change, a segment now and then, the whole state once a day), the listing
  time of a prefix that holds a retention period's objects, and a restore of
  8,192 keys from a real bucket.
