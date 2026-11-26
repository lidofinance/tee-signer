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
| magic | 6 | `SMARK3`: `SMARK` and the format version, 3 (the runner reads `SMARK2` records, which end before the config history, and `SMARK1` records, which end before the share set) |
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
| pending order | 1, or 42 | presence byte, then kind (1 handover, the only kind; a reader refuses any other), hash, act time; only an image with a handover writes it, and this image does not start on a state that holds one |
| target | 1, or 33 | presence byte, then the `setup_hash` a tombstone hands over to; only an image with a handover writes it |
| exits | 1 | presence byte, always 0. An image with exit approvals wrote the day's exits here; this image refuses a record that holds them |
| source gate | 1, or 9 | presence byte, then the source floor epoch (see "Source gate") |
| share set | 1, 34 or 66 | presence byte, then the current root (32), a presence byte and the pending root (32) (see "Share set") |
| removal time | 1, or 9 | presence byte, then the effective time of the newest locked update in force that removed one approver (never 0); break-glass waits one change delay after it (`setupwire.History`) |
| approver set time | 1, or 9 | presence byte, then the effective time of the newest locked update in force that changed the approver set (other keys, another order or another `approvals_needed`; a removal too; never 0); a break-glass update adds no image until the set has been in force for the images wait (`setupwire.History`) |
| carried revocations | 1 + 32 each | count (0 to 128), then the `revoked_client_certs` entries of a pending open update that a rotation dropped, sorted, without repeats, none zero; the runner refuses them until the next open update comes into force |
| update paths | 4 | the path each update the state names came by (1 normal, 2 break-glass, 3 emergency removal; 0 unknown), for locked active, locked pending, open active, open pending; 0 where the state names no update |
| signature | 64 | Ed25519 over the context `signer-mark-v1` and the fields above |

Each group is the active version (8), the hash of the update that set it
(32; for version 0 the setup's group hash), the active body's copy number
(4) and the time that copy was written (8). A presence byte follows. With
a pending update come its version (8), hash (32), effective activation
time (8), copy number (4) and copy time (8). Version 0 has no body, so its
copy number and time are zero.

The reader refuses any record that does not read back to the same bytes
under its own magic (an `SMARK1` record as `SMARK1`, an `SMARK2` one as `SMARK2`):
a presence byte other than 0 or 1, trailing bytes, a log ID that is zero
in a later record or set in a first one, a target on a record that is not
a tombstone, a pending update at or below the active version, a body past
version 0 without a copy, an order of an unknown kind, a removal time or an
approver set time of 0 with its presence byte, or carried revocations out of order, repeated or
zero.

Fail-closed reader rule. A record the reader refuses is skipped, unless
its start (magic `SMARK` and a digit of 1 or more, setup hash, signer,
version, previous version, previous hash, log ID, owner, key blob) names
this setup, signer and version with a key blob the runner's key release
opens, and its last 64 bytes are an Ed25519 signature under the key inside
that blob, with the context `signer-mark-v1`, over every byte before them.
Then a runner under this key release signed it, most likely a newer image
with a field this one does not know (a digit above 3). The rule runs in
three places. At start, on the versions at and above the newest valid
record and in the chain walk below it, down to the record it links to: the
runner refuses to start (`markstore.ErrUnreadable`). On a write, when the
name the runner wants is taken by such a record: the other instance is
live, so the runner signs nothing new (`ErrLost`, see "Clone") and writes
nothing. Skipping the record in either place would fall back to the mark
below it, and the runner could sign votes around the newer image's marks.
Every later record format keeps that start, the magic's form and the
signed tail. A digit of 0 is no record.

The key blob alone proves nothing: it is a public field, and anyone who
can read the log can copy it from a real record into an object of their
own. Without the signature check such an object, under a compliance lock,
would stop every start of the signer until the lock expires.
`-mark-create` does not clear `ErrUnreadable`: the rule runs before the
override is looked at, and setup images have no override.

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
that copy is two hours short of half the retention, the runner writes copy n+1
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
  store's lock over its own TLS and credentials (`markstore.CheckLock`),
  and the claim reads it again once it has read the log, before it writes
  its claim record. The store can change between the first check and the
  read: on Azure a migration to version-level immutability that completes
  there would let an admin hide the newest records from the read.
  S3 must have Object Lock in compliance mode, GCS a locked retention
  policy, Azure a locked container immutability policy. The retention
  must be at least the setup's `slashing_log_min_lock_days`. Otherwise the
  runner stops. On Azure, version-level immutability on the container or
  the account, or a policy that allows protected append writes, also
  stops it, even with a locked policy (see "The stores"). The file log of
  the dev platform has no lock, and the dev platform skips the check. On
  S3 the check reads the bucket's default retention, which the admin can
  lower later, so wherever the check runs the S3 client also gives each
  object it writes its own compliance retention of at least
  `slashing_log_min_lock_days` (`markstore.Env.RetainDays`); the state
  copy's objects get it too when the copy uses the log's store. The
  runner also checks the lock again at each refresh, hourly
  (`Options.LockDays`). A store that fails that check stops every later
  write: the runner signs nothing above the mark it committed while the
  store was locked, until a restart passes the check again. HEALTH then
  says `ready: false` and `mark_log_lost: "mark log stopped: store lock
  lost: ..."`. A check that cannot read the lock (a host can block the
  management API the Azure check reads) stops writes too, but does not
  latch: no record is written, so nothing is signed above the committed
  mark, until a check passes. The next refresh checks again, and so does a
  write 30 seconds or more after the failed check. Status then shows
  `LOCK-UNCHECKED`, and HEALTH says `ready: false` and `mark_log_lost:
  "mark log paused: store lock unchecked: ..."` until a check passes. A
  refresh reads the lock even while the trusted clock fails. The pause
  writes no keep-alive record, so if no check passes within half the
  retention of the last record, the write age check (below) stops the
  runner for good. Any lock check error at the claim stops the start.
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
  re-import. So `slashing_log_min_lock_days` bounds how long a signer may
  stay stopped: half of it. A new setup of a prod chain takes 7 days or
  more (`setupwire.CheckMinLockDays`), a non-prod one 1 or more.
- Write age check. A running runner holds its own writes to the same
  bound. Before each record, and at each refresh, it compares the trusted
  clock with the time of its last record that landed in time, or of the
  record the claim read. This runs before the lock check, so a store that
  is cut off, lock read included, shows the latch and not a pause. After a create it reads the clock again, since
  the host can hold a create back. Past half the retention it writes no
  more records and latches (`markstore.ErrStale`): it signs nothing above
  its committed mark until a restart, whose claim runs the age check.
  Status then shows `STALE`, and HEALTH says `ready: false` and
  `mark_log_lost: "mark log stopped: no record for half the retention:
  ..."`. HEALTH `mark_log_written_unix` is the time of that last record,
  so monitoring can alert long before. A clock that fails after a create
  fails that write without a latch; the next write measures from the
  record before it.
  The bound holds because a clone that claims the log while this runner
  is cut off writes above this runner's last record, so after it, and
  the store keeps each of the clone's records for at least the retention
  from when it landed (on S3 the runner dates each record's retention with a
  clock S3 holds to within 15 minutes, and adds 25 hours). A write of this
  runner that lands within half the retention of its last record meets
  the clone's record and conflicts (`ErrLost`). Half the retention is at
  least 12 hours; a running runner writes a record at least every
  retention / 8 (at most a day) plus an hour, so only an outage that long
  latches. Any outage counts, though the store itself may work: the store
  out of reach, a lock read that fails (`LOCK-UNCHECKED`), or a trusted
  clock that fails. Each stops the keep-alive records, and the runner
  fails closed.
  The bound holds only while the trusted clock does not lag real time.
  Where the host can set the rate of the guest's counter (no platform's
  documents rule it out, Nitro included), a host that blocks the time
  servers and holds the counter can hold that clock back without limit
  (`trusted-time/clock/nts.go`, the comment on the local clock rate). A
  runner held back that way passes the check after the clone's
  records are gone, writes in their place and signs. A planned check also
  compares the store's own response `Date`, which the host cannot hold
  back, with the time of the last record.
- First start. An empty log and no shares listed: the claim record is
  record 1, with the setup's first config state (version 0 of both
  groups), and its hash is the log ID. An empty log with shares listed
  stops the start.
- Bodies at start. The claim reads one copy of every update body the
  newest record names. A body with no readable copy does not stop the
  start; the runner refuses to sign once its config in force needs that
  body. Sending the same update again writes a new copy and restores it.
- Keep alive. While the runner runs, `Refresh` writes a new copy of every
  body older than half the retention less two hours, and a record when it wrote a copy or
  when the newest record is older than the retention / 8 (at most a day).
  A runner with a setup calls it every hour (`RefreshLoop`).
- Nothing valid. A log with objects under record names but no valid record
  stops the start, with or without shares: those may be records whose keys
  this key release cannot open, and starting over would drop their mark.
  An empty log stops the start of a node that holds shares. `-mark-create`
  overrides both on the flag path, and the new log starts above the
  highest name taken; setup images have no override.
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
  `TestE2EAzureRunnerMarkLogLostState`, `TestE2EAzureRunnerDurable`
  run this on each platform build.
- Merge. A record holds the merge of the mark before it and the new one, so
  the log's mark never goes down. An import with interchange maxima (an
  EIP-3076 import) raises the log before
  the share is stored.
- Tombstone. An image with a handover ends the log with a record whose
  bounds are all 2^64-1, which may name the target's `setup_hash`. Nothing
  appends after it. This image writes none; its claim of a log that ends
  with one fails with `ErrHandedOver`, so it writes no record and signs
  nothing on it (`slashing-log/docs/durable-state.md`, "A new image").
- Hint. After each write the runner keeps the version and hash it wrote,
  sealed in the platform store under the context `signer-mark-hint-v1`,
  the `setup_hash` and the signer. At start a hint above the newest record in
  the log (records hidden, a stale listing) or a different record at the
  hint's version stops the start. The host can roll the hint back, not
  forward, so it can only make the hint say less.
- Clone. A second instance (from the same sealed state, or a second group
  or VM of the same image, or a newer image under the same key release
  during an image swap) claims the log with its own record. The first
  instance's next write then finds its name taken by a valid record of
  another owner, or by a signed record of this signer it cannot read (the
  fail-closed reader rule): from then on it signs nothing new (`ErrLost`,
  refusals with `SC_ERR_STORAGE`). Names stay write-once, so two live
  instances conflict on create. A restart of the first instance over a
  log that holds such a record below its newest readable one refuses too
  (`ErrUnreadable`).
- Store down while running. The core keeps signing inside the committed
  mark and refuses what lies above it until a write succeeds again.
- Restart floor. The core sets it on every load, sources included
  (`signer-core/README.md`, "Restart floor"); the log's mark can only raise
  it. A restart while the chain does not finalize stops votes until the
  chain justifies the floor epoch, with the log as without it.
- Objects that are not records under future names. Anyone with write
  access can create new names, and readers ignore such objects. The
  writer skips a name only if every object under it is locked in
  compliance mode until at least the time of the write plus
  `slashing_log_min_lock_days`, less 15 minutes (`markstore.CheckKept`).
  Nobody can then delete the object before a record under that name could
  go. Each such name costs a skip, up to 16 in a row. Another instance
  that comes to the name later skips it too if the object's date also
  covers its own write, and the two then meet at the next name. Otherwise
  it stops with `markstore.ErrNameTaken`, and the write age check keeps
  it from writing the name after the object is gone. It writes nothing
  more than half the retention after its last record, and the object
  stays for the retention less 15 minutes after the skip. So the skip is
  safe only with the write age check. A log without a setup and the first
  record of a log have nothing for that check to count from, and never
  skip a taken name. The rule assumes the trusted clock does not lag real
  time; a claim refuses a clock that lags the newest record by more than
  15 minutes (`markstore.ErrClockBehind`).
- Any other object under the next name stops the write
  (`markstore.ErrNameTaken`): no retention, S3 governance mode, a shorter
  date, a GCS or Azure policy that is not locked, a store that cannot
  report an object's lock, a lock read that fails, a log without a setup,
  or the first record of a log. The stop does not latch, and until it ends
  the core signs nothing past the committed mark and a start fails at its
  claim. If the object goes within half the retention of the last record,
  the next write takes the name. An object that stays longer cannot clear
  in time: the write age check stops the writer first (`ErrStale`), and
  the signer needs a new setup and a re-import. On a locked GCS or Azure
  store that is any object made more than 15 minutes before the writer
  reaches its name, since the lock runs from the object's creation. The
  writer never passes such an object, because an instance that skipped it
  and one that writes its name after a delete would never meet.
- A listed object that reads as not found is an error, not an absent
  object. A write that meets one fails without a skip and without a latch,
  and a start fails. The listing says the object is there, and reading
  past it could pass over a record.
- More than 16 locked names in a row stop every write and every start for
  their retention, and one such object on a new log stops its first
  claim. Many names above the newest record can also push the claim past
  its timeout. The state copy never skips: it has no write age check,
  so any object that is not a commit under its next name stops its
  commits until it is gone (`durable-state.md`). Whoever can
  create objects in the bucket can stop the signer this way, as they can
  by taking the runner's access away. The design trusts the storage
  admin for liveness, not for safety: nothing they write makes the runner
  sign below its mark. A copy of an old record under a new name does
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

### Share set

The AAD binds a share record to the log, not to the import that wrote
it. A share record carries `history` and `source_floor`, so an old record
of the same key under the same log is a claim the host could replay: a
key imported with history leaves this runner, votes elsewhere and comes
back without history. So the log commits to the stored records.

Each record carries the share set: the root of the stored share records
(`markstore.ShareSetRoot`: sha256 over `signer-share-set-v1` and, in key
order, each validator key and the sha256 of its sealed record as
stored), and, while a write is under way, the root of the set after it.

- A share write (any import) first writes a log record whose current
  root is the set before and whose pending root is the set after, then
  the share record. Share writes go one at a time. The next record
  carries the set after as its current root. The set before leaves out
  an older record of the same key, so a write that fails does not leave
  the log vouching for that older record.
- A start reads every listed record and computes the root over the ones
  that unseal and parse. A stored object that does not (sealed under
  another setup or log, corrupt, or no record) never loads and is no
  part of the set; the runner names it in the start's errors, and the
  operator removes it. If the root is the newest log record's current or
  pending root, the runner loads the records as they are. A cut between
  the two writes leaves one of the two sets, and the set before holds the
  key's earlier record or none: never more history than the set after.
- Any other set means a replayed, hidden, changed or added record, such
  as the blob of an import whose store write failed, which the host kept
  and stored later. The runner cannot tell which record, so it loads no
  key and writes nothing. The start's error and HEALTH `load_failed` name
  the stored records, and `ready` is false until a restart. The runner
  refuses imports (IMPORT_SHARE_SEALED, IMPORT_SHARES_SEALED) with
  `NOT_READY` and that error while it is in that state: an import would
  have the log vouch for a set without the stored records, and they
  would never load again. One import is taken: an IMPORT_SHARES_SEALED
  batch that holds every share name the start listed (every `shares/`
  name that is a lowercase hex key; a name that is not can never load
  and does not count). It writes a record for each of them, so the new
  set leaves no stored record out. The set before is the empty root,
  the keys load without history, `ready` is true, and the next start
  loads the batch's records as vouched. A batch that leaves a listed
  name out is refused. The operator then does one of these:
  - An added record (an import that failed): remove that object and
    restart.
  - A hidden record: put it back, if the host still has it, and restart.
  - A replayed or changed record whose vouched version is gone for good:
    the set cannot be put back. Import every listed share again in one
    batch. Or remove every share record and restart; the runner then
    takes imports again (next bullet). Either way the keys come back
    without history. Where the records come back at every start (a
    state copy that rolled back, `durable-state.md`), the batch is the
    only way short of a new setup.
- A store that lists share records but gives none the runner can read
  (hidden, unreadable, or sealed under another setup or log) under a set
  that is not empty loads no key and reports `ready` false and
  `load_failed`. The log keeps vouching for the set it had, and every
  record written meanwhile (a keep-alive, a config activation) carries it
  on, so the records put back load at the next start. Imports are refused
  with `NOT_READY` until then, for the reason above, but a batch of every
  listed share, as above: the operator puts the records back and
  restarts, imports every listed share in one batch, or removes every
  share record and restarts, then imports.
- A store that lists no share record at all under a set that is not
  empty (the state is lost, or the operator removed every share) loads no
  key and reports `ready` false and `load_failed` the same way, and the
  log keeps vouching for the set it had, so the records put back load at
  the next start. But it takes imports: there is no stored record an
  import could orphan. The first import records a new set over the old
  one (the set before is empty), the key loads without history, and
  `ready` is true. The old records put back after that are no longer
  vouched for and do not load. What counts is the listing the start saw,
  not a later one.
- A store write that fails is read back. If it landed, the runner keeps
  the set after; if not, it writes a log record at once that vouches for
  the set before only, so a blob the host kept and stores later is not
  vouched for. If that record fails too, the runner takes no share write
  until a restart. With a state copy (`-state-store`) the copy reads its
  commit back itself (`durable-state.md`, "All or nothing"), and a write
  whose commit it finds there succeeds.
- A batch import (IMPORT_SHARES_SEALED) writes one log record whose
  current root is the set before and whose pending root is the set after
  all its records, then the records, 16 at once. A batch adds keys only,
  so the set before holds no record of its keys. Each record carries the
  batch's tag (`batch`, random). If a write fails and the read back does
  not find it, the batch fails as a whole and the runner writes a log
  record at once that vouches for the set before only. If that record
  fails too, the runner takes no share write until a restart.
- A batch that did not complete (a write failed, or the runner stopped
  halfway) may leave some of its records in the store. A start whose
  stored records are not vouched for first leaves out the records of one
  tag; if the rest is the current or pending root, it loads the rest as
  it is, and none of the batch's keys. Else it loads no key, as above.
  Later records vouch for sets without those records, so later starts
  leave them out too, until the operator imports the keys again. The
  next batch must hold every key of that batch that may have a record
  stored, and takes its tag, so the store never holds records of two
  batches that did not complete; a key of it imported on its own leaves
  it. The runner that saw the write fail asks for every key of the
  batch, since it does not know which records landed. After a restart
  the runner asks for the keys of the records it found under the tag: a
  key of the batch whose record never landed is not asked for, and a
  batch without it is taken. Leaving records out never loads a
  key the log does not vouch for: what loads is still a vouched set. A
  batch whose writes all landed loads as the set after, through the
  pending root.
- After a share write the newest record keeps its pending root until the
  next record, which carries the set after as current. So a pending root
  in the newest record does not mean a write was cut. It also vouches
  for the set before, which holds no more history.
- A log record written before share sets (`SMARK1`), or one with no share
  set, vouches for the empty set only. The first start of this image on
  such a log with shares resets once: it loads every key without history
  and with a source floor of at least the restart floor epoch now, the
  bounds of an import without history. It first writes a log record that
  vouches for the rewritten records, then rewrites them. If that log
  record fails, no key loads. A record the reset could not write back
  leaves the store outside the vouched set, so the next start loads no
  key and names it; the rewritten record was never stored, so the
  operator imports every listed share again in one batch, or removes
  every share record, restarts and imports again, as above. Such a log
  with no readable record commits nothing, so the log stays one with no
  share set: a store that lists no record is a new signer, ready for its
  first import; one that lists records it does not give (hidden records,
  or objects that are not records of this signer) reports `ready` false
  and `load_failed` and refuses imports with `NOT_READY`, but a batch of
  every listed share: the operator puts the records back and restarts,
  and they take the reset, or imports every listed share in one batch,
  or removes every share record and restarts, then imports.

The log is the anchor because the host cannot roll it back: records are
written once under a lock, and the newest one wins (see "Rules"). The
share records alone have no such anchor.

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

`markstore` checks the shape of a state, not the rules of section 6
(signatures, waits, supersede). `tee-signer/server/config.go` checks those,
writes the body before the record that names an update pending, and
writes the record that shows an update in force once its effective time
has passed.

## The stores

| | AWS | GCP | Azure |
| --- | --- | --- | --- |
| Store | S3 bucket, versioning on, Object Lock default retention in compliance mode | Cloud Storage bucket with a locked retention policy (Bucket Lock) | Blob Storage container with a locked time-based retention policy, container-level (no version-level immutability on the account or the container), no protected append writes, no hierarchical namespace on the account |
| What the admin cannot do | delete or overwrite a locked version ("can't be overwritten or deleted by any user, including the root user"); with the bucket policy of `platform-aws/deploy/main.tf`, delete any object or set a new lifecycle rule (no principal may; a rule set before the policy keeps running), or put under `marks/` and `config/` (only the record writer may); with or without the policy, get a writer past a record name whose object it can delete later (the writer skips only an object in compliance mode retained as long as a record) | delete or replace a retained object; reduce or remove the locked policy; get a writer past a record name whose object it can delete later | modify or delete a locked blob ("not even by users with account administrative privileges"); get a writer past a record name whose object it can delete later |
| What the admin can do | with the bucket policy, mint an access key or a console password for the record writer user and write records as it, or change the policy to lift its denies (including the one on lifecycle rules, whose expiration adds delete markers); without it, add versions and delete markers (the reader lists every version); lower or remove the default retention, which the runner's objects do not use (each PUT names its own compliance retention) | create new names | create new names |
| Client | `platform-aws/s3log`, SigV4 of our own, `platform_aws` | `platform-gcp/gcslog`, JSON API, `platform_gcp` | `platform-azure/azlog`, Blob REST, `platform_azure` |
| Credentials | the enclave's record credentials (an IAM key only the enclave can decrypt) | the workload's federated token (Confidential Space, WIF; the same as for KMS) | the container group's managed identity, resource `https://storage.azure.com/` |
| Lock check reads | `GET /?object-lock` (GetObjectLockConfiguration); needs `s3:GetBucketObjectLockConfiguration`; `GET /?lifecycle` (GetBucketLifecycleConfiguration), refused on an enabled transition rule, a warning on an expiration rule; needs `s3:GetLifecycleConfiguration` (any 403 on this read, whatever its code: a warning, no check); every PUT also needs `s3:PutObjectRetention` | `GET /storage/v1/b/B?fields=retentionPolicy`; needs `storage.buckets.get` | the storage account and the container from the management plane (`immutableStorageWithVersioning`, `immutabilityPolicy`); needs a token for `https://management.azure.com/`, the subscription and the resource group, and Reader on the account |
| Taken name reads | `GET /KEY?retention&versionId=V` (GetObjectRetention) for each version under a record name that holds no valid record; needs `s3:GetObjectRetention`; only `COMPLIANCE` counts | the bucket's policy as above and the generation's `timeCreated` (`storage.objects.get`); the object is kept until `timeCreated` plus the locked period | the container's policy as above and the blob's `x-ms-creation-time` (Get Blob Properties); the blob is kept until its creation plus the locked period |
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
The check reads two resources: the storage account (Storage Accounts, Get
Properties) and the container (Blob Containers, Get), whose
`immutabilityPolicy` carries the state, period and append flags of the
policy. The identity needs Reader on the account scope
(`platform-azure/deploy/deploy.sh store-role N`), which covers both reads.
A custom role without `storageAccounts/read` or `containers/read` gets a
403, and the runner stops. The account name is unique across Azure, so a
wrong subscription or group in the setup finds no account or container
(404). The lock check and the version check of the state copy both fail
on that 404 and name the path they read.

The Azure check refuses version-level immutability on the account or the
container (`immutableStorageWithVersioning` enabled, or a migration to it
under way), locked policy or not. A container read without
`immutableStorageWithVersioning` fails the check too. There an overwrite makes a new current
version and keeps the locked one as a previous version. The client lists
and reads current versions only, so a storage admin could overwrite the
newest records, and a runner without its local hint would start from an
older record: an older config state and an older source bound.
Version-level immutability cannot be turned off again, so a log container migrated to it
stops its runner at the next start, and the signer needs a new container
and a new setup. Account-level version-level immutability can only be set
when the account is created; such an account needs replacing. Whether a
container shows the account setting in its own
`immutableStorageWithVersioning` is not confirmed on Azure; the account
read covers that case either way.

It also refuses an account with a hierarchical namespace (`isHnsEnabled`,
Data Lake Storage). There blobs live in directories that can be renamed,
and a rename could move records out of the names the client lists. The
setting is chosen when the account is created; such an account needs
replacing.

It also refuses a policy with `allowProtectedAppendWrites` or
`allowProtectedAppendWritesAll`. With those, new blocks can be added to a
blob under a locked policy, which would change a record or a state chunk.
The flags cannot change once the policy is locked, so such a container
needs replacing too. Create the policy without them and then lock it:

```sh
az storage container immutability-policy create --account-name A -c C -g G --period DAYS
etag=$(az storage container immutability-policy show --account-name A -c C -g G --query etag -o tsv)
az storage container immutability-policy lock --account-name A -c C -g G --if-match "$etag"
```

The state copy runs the same checks at start (`markstore.CheckVersions`,
`markstore.CheckLock`, `docs/durable-state.md`), before and again after
it reads the copy. On mainnet a copy whose
store fails the lock check stops the start; elsewhere the runner logs a
warning.

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

Retention bounds how long a signer may stay stopped, or cut off from its
store while it runs: the age check stops a runner whose newest record is
older than half of `slashing_log_min_lock_days`, and the write age check
stops a running one whose last record is that old.
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

- Known issue: one vote pins the device source. The record holds one
  source bound for every key, the highest source any key signed, and a
  restart applies it to every key. A client with the signing role can
  send, for one key, a vote whose source is above the epoch the chain
  justified, for example the shape of a vote under finality while the
  chain does not finalize. The core signs it, which is right for that
  key, and the log's source bound moves to it. Until the host restarts
  the runner nothing changes, since the RAM rules are per key; the host
  can restart it at any time. After the restart every other key refuses
  its honest votes until the chain justifies that epoch, which during
  non-finality may take long and which the stopped keys cannot help
  bring about. In signing_mode single the whole validator set behind the
  signer stops attesting; in threshold mode one member of the cluster
  does. It cannot cause a slashing: it only refuses votes. The
  restart floor makes this cost nothing extra: a vote never has a source
  above the epoch of the clock when it was signed, and after a restart the
  floor already holds every key's votes until the chain justifies the
  floor epoch, which is higher.
- An admin who also controls key release (the AWS KMS key policy, the GCP
  WIF provider and the KMS key's IAM, the Azure key's release policy) can
  decrypt the sealed share, make key blobs and forge records. The store
  resists the admin exactly as far as key release does (research note,
  section 2.2). On GCP the KMS key and the bucket grant their roles to the
  WIF pool's principal set only (`platform-gcp/deploy/README.md`), not to
  the service account the VM runs as.
- A new key release. The record keys open only under the key release that
  made them. On mainnet the AWS key policy is locked and the Azure release
  policy is immutable. Neither can change, so neither can take a new
  image, and a new image cannot open the old image's log. A locked AWS
  policy may also name a second image (`prev_pcrs`, such as the image it
  replaces), but only one fixed when the key is created. A mainnet signer
  on AWS or Azure therefore moves to a new image as a new signer: a new
  setup, key and mark log, and the shares imported again
  (`docs/upgrade.md`, "When this works"). On GCP,
  and on AWS or Azure with a key rule that can still change, the key rule
  names the new image next to the old one, and the new image reads the old
  log as on a restart (`docs/upgrade.md`).
- A signer down, or cut off from its store, longer than half the
  retention period: the age check stops it at the claim, the write age
  check while it runs, and it needs a new setup and a re-import.
- Objects under future record names. Anyone who can write the log's bucket
  (an admin, or the runner's own cloud identity) can create junk under the
  next version names. One object that is not locked as long as a record
  stops every write until it is gone. Seventeen locked ones in a row stop
  every write for their retention. Either way the core signs nothing past
  the committed mark, and a start fails at its claim record. If the junk
  stays longer than half the retention after the last record, the stop
  does not clear: the write age check ends the setup, and the signer needs
  a new setup and a re-import. On a locked GCS or Azure store one object
  made more than 15 minutes before the writer reaches its name is enough,
  and so are seventeen locked ones on any store. This costs liveness,
  never a mark: no writer passes a name whose object could be deleted
  later.
- S3's default retention is a bucket setting. An admin with
  `s3:PutBucketObjectLockConfiguration` can lower or remove it after the
  start's check. The runner's own objects are not affected, since each PUT
  sets its own compliance retention. What stays open: the check reads the
  default once per start, so a bucket whose default was removed is noticed
  only at the next start. GCS and Azure lock the policy itself.
- S3 lifecycle rules. The bucket policy denies new rules, but a rule set
  before it, or after a change that lifts the deny, keeps running. An
  expiration adds delete markers, which the reader reads past, and a
  noncurrent version expiration removes a version once its retention
  ends. The checks after a create (`checkHidden`, `checkMarker`) see a
  hidden record only while its version exists. A runner cut off from the
  bucket for longer than the retention, while a clone claims the log and
  writes, could find the clone's record gone and write its own in its
  place without seeing what the clone signed; the write age check
  (Rules) stops it at half the retention, before the clone's records can
  go, as long as the trusted clock does not lag (Rules, "Write age
  check"). The lock check warns of an
  expiration rule and does not stop on it. It also passes on any 403 to
  its read of the rules, whatever the error code, so a runner under an
  older bucket policy still starts; a rule is then not seen.
- The flag path (`-mark-store` without a setup) runs no lock check and sets
  no per-object retention. Only a setup gets either.
- Real cloud stores: the tests use local fakes of the three APIs
  (`slashing-log/wormfake`). The lock reads
  are untested against the real APIs.
