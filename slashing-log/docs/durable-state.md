# Durable state

Two mechanisms for the clouds whose runner keeps its state on
a disk that does not outlive the container or VM (Azure ACI, GCP
Confidential Space):

1. The state copy (`-state-store`, `slashing-log/statestore`): the sealed shares,
   the wrapped sealing key and the rest of the state that matters live in an
   object store as well, and a restart restores them before the mark log
   claim.
2. On GCP, key release only through attestation: the KMS key and the
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
960 KiB of changes, a value at most 256 KiB (`MaxEntry`), and a commit
carries at most 128 KiB of changes.

The object key comes from the same key release as the mark log's record
keys: Key Vault's released key on Azure, Cloud KMS through WIF on GCP. The
store's admin can read nothing (the key blob opens only for the attested
runner) and cannot change an object without the open failing; a commit
copied under another version name or another signer's prefix fails too,
and a chunk must hash to the name its commit holds.

The names are created once (S3 `If-None-Match: *`, GCS
`ifGenerationMatch=0`, Azure `If-None-Match: *`) through the mark log's
clients (`markstore.Log`), so the copy works on the locked bucket of the
mark log as well as on a plain one. On the setup path the runner refuses
a store that keeps overwritten objects as previous versions the client
does not read, or that can append to an object (`markstore.CheckVersions`:
an Azure account or container with version-level immutability, or a
policy with protected append writes), since an admin could hide or change
the newest commits there and the restore would take an older one. It
checks before and again after the read, so a store that changes in
between stops the start too. A commit name taken by a
valid commit of another process means a clone: that process changes no
durable state from then on (`ErrLost`). Objects that are not commits cost
a skip each, as in the mark log.

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
- Refresh. The runner writes the whole state as segment 0 when the oldest
  object the newest commit needs is half of the setup's
  `slashing_log_min_lock_days` less two hours old, so on a locked bucket no
  object the state needs comes out of retention, even on a restart half the
  retention after the stop. It checks at least every hour.
  `-state-refresh` (default 24 hours) can make that age shorter, never
  longer. Without a setup, `-state-refresh` alone sets it. With a setup,
  commit times and the age come from the trusted clock the mark log uses.
  A commit or refresh fails while that clock has no reading, and an object
  stamped after now is written again. A refresh that
  fails is tried again at the next check; until one succeeds, HEALTH
  reports `ready` false and `state_copy_failed` with the error.

### Where to keep it

In the mark log's bucket or container, under `state/` (`-state-store` with
the same value as `-mark-store`; `platform-gcp/deploy` `STATE_STORE="$MARK_STORE"`,
`platform-azure/deploy` `STATE_STORE_N="$MARK_STORE_N"`). The runner needs no new
role, and the lock keeps every object for the retention period, so the
admin cannot delete the newest commit or a chunk it needs. A plain bucket
also works off mainnet, with a warning at start; then the admin can delete
objects, which the next section is about. On mainnet the runner runs the
mark log's lock check on the copy's store and does not start if it
fails: where the local store does not last, the copy is the only copy of
the sealed shares.

The runner deletes nothing in the store. It holds what the runner wrote over
the retention period: one object or more per change, plus the whole state
once a day ("Cost").

### Why a rolled-back copy is no slashing risk

Assume the admin of a plain bucket deletes the newest commits or a chunk,
so a restart restores an older commit. The restored state differs in which
shares it holds, never in a mark:

- The mark the runner signs under comes from the locked mark log, read at
  the claim after the restore. No commit holds a mark (the hint is not in
  the copy, and the hint can only make the claim refuse).
- A share record carries `history` and `source_floor`, which bound votes.
  The mark log vouches for the set of share records (`marklog.md`, "Share
  set"). An older commit is not that set, so a restart from it loads no
  key and reports `load_failed` in HEALTH: the operator removes every
  share and imports them again. That costs liveness, never safety.
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
the state (`TestWriteCostPerSessionIsFlat`, 64 keys per change up to
8,192). Merges into segment 0 write the whole
state, so the mean upload per commit grows with the log of the state. A
restart reads the copy also when the state directory is kept.

On a cloud object store each commit is at least one object create.

### Design notes

- One change per commit: `Apply` writes a set of store writes as one
  commit, so they land together or not at all.
- The file store's `List` walks only the prefix's folder, not the whole
  state directory.
- The file store fsyncs each file. With the copy, the local writes after
  a commit and the restore sync the file system once instead (`syncfs`);
  without the copy (Nitro) each write syncs.
- The restart lists the whole prefix, chunks and every version included, so
  the listing grows with what the store keeps, not with the state.
- PUBLIC_KEYS fails above 10,082 keys, because its answer must fit one
  1 MiB frame.

## A new image

On Azure each image gets a new Key Vault key version whose release policy
names the image's CCE policy hash, and the release policy cannot change
afterwards. A new image opens neither the old image's sealing key (so not
its sealed shares or state copy) nor its mark log records. This image has
no handover, so a new Azure image starts as a new signer: a new setup and
mark log, and the shares imported again with the sealed import, with
their interchange maxima or under the import floor.

On AWS and GCP the KMS key policy and the WIF provider condition can name
the new measurement next to the old one: the old ciphertext, the old log's
record keys and the state copy stay readable, and the new image reads its
predecessor's log as on a restart. Those policies are mutable: an account
admin who edits them can let another workload release the key without
anyone's signature.

A mark log written by an image with a handover can end with a tombstone
(every bound at 2^64-1), or hold a handover order in the order slot of its
state. This image refuses to claim a log that ends with a tombstone
(`markstore.ErrHandedOver`) and refuses to start on a log state with an
order in the slot.

## The network entry's node state

The runner has no network entry code. A non-prod build can add one through
the build hook `SIGNER_BUILD_OVERLAY_DIR` (`scripts/common.sh`). Such an entry may keep its node
state in the runner's store, sealed and bound to setup_hash like the
shares, so the state copy holds it too. On AWS a network entry runs on the
parent, which is untrusted, so its state gives no way into the enclave.

## Settings

| Flag | |
| --- | --- |
| `-state-store` | the copy, same syntax as `-mark-store` (`file:`, `s3:`, `gcs:`, `azblob:`) |
| `-state-create` | start over when no commit opens under this key release with every object it needs |
| `-state-refresh` | write the whole state again when the oldest object the newest commit needs is this old (default 24h); with a setup at most half of `slashing_log_min_lock_days` less two hours; 0 off without a setup |

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
  8,192 keys written in batches, upload per batch flat, every object under 1 MiB, one small change one
  small object (`TestWriteCostPerSessionIsFlat`); a lost
  chunk (fallback to an older commit, then refusal); a delete finished at
  start; hints never uploaded; refresh compacting.
- `platform/filestore`: `PutMany`, `Delete`, `List` by folder.
- `slashing-log` `TestTombstoneNotClaimed`, `TestAppendMerges`;
  `platform-gcp/gcp` `TestFederatedTokenWithoutServiceAccount` (KMS and
  storage with the federated token, no IAM call; with `service_account` the
  impersonation fails, since the roles sit on the principal set).
- `tests/e2e`: `TestE2EDurableStateDev` and `TestE2EDurableStateGCP` (the
  GCP debug build, mark log and copy in one locked GCS fake): the state
  directory is wiped, the share comes back, a vote below the log's source is
  refused at every epoch and the log's source signs; another image does not
  start on the copy.
- `attestation-verify/runnerclient` `TestE2EAzureRunnerDurable`: the Azure debug build
  with fake SNP, MAA and Key Vault; the file system lost and restored.
- Fuzzer (`signer-core/sim`): `OP_WIPE` covers the restored
  share (the copy does not hold the hint, which the event wipes); `OP_HANDOVER` hands a signer over to a new instance with a log of
  its own, the old one staying up in the clone slot. Negative controls:
  handover with the tombstone 0 violations, with the old log left open
  violations.

## What needs a cloud check

- Azure: MAA's key set at `https://<provider>/certs` as the runner fetches it
  (format: `x5c` and `n`/`e`), and the runner's TLS trust of the provider from inside the group. A group
  restart with the container's file system gone, restoring from the locked
  container.
- GCP: the STS exchange followed by KMS and Cloud Storage calls with the
  federated token (no service account), and a VM recreated with its disk gone restoring from the bucket.
- All: commit and chunk sizes and timing on the real stores (one commit per
  change, a segment now and then, the whole state once a day), the listing
  time of a prefix that holds a retention period's objects, and a restore of
  8,192 keys from a real bucket.
