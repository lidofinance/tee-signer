# signer-admin

> **Pre-release.** Running on test networks; not yet for mainnet funds.
> Provided as is, without warranty. Interfaces and formats may change before
> the first release.

Operator tools, outside the TEE: `signer-admin` (drafts and signs setup updates and orders, `approver` and its agents), `cluster` (setups of a signer group), the admin client (`remote/admin`), and the key lifecycle tools: `share-import`, `setup-tool`, `identity-check` and `proof-check`. `fakerunner` is a test runner for the tools.

The runner checks everything these tools send. None of them holds a validator key, except `signer-admin split`, the offline dealer of [Splitting existing keys](#splitting-existing-keys).

`signer-admin exit` signs a voluntary exit. Only the admin role may sign one, so the signing client cannot. It sends the exit to the signers of `cluster.json` in turn with each signer's admin connection file, keeps the first t partial signatures that verify under their share keys (t and the share indices come from the split file of `import-draft`; a cluster of one single-mode signer needs none), combines them, checks the result under the validator key and writes the beacon API body. It posts nothing. To broadcast:

```
signer-admin exit -cluster cluster.json -split split.json -pubkey 0x... -index 123 -epoch 0 -out exit.json
curl -X POST -H 'Content-Type: application/json' --data @exit.json http://BEACON:5052/eth/v1/beacon/pool/voluntary_exits
```

`-pubkey` is the validator key. For a dv_share cluster that is the group key (`distributed_public_key`): each dv_share signer lists its share under the share's own key and signs with it, and `exit` refuses a share key with a message that names its share index and group key. For the Obol exit flow see [Exits of dv_share keys](#exits-of-dv_share-keys).

Every setup file says `signing_mode`: `threshold` (the signers hold shares of t-of-n splits, n >= 2), `single` (one signer holds whole keys) or `dv_share` (each signer holds one share of each validator of a Charon cluster, [below](#charon-shares-signing_mode--dv_share)). One key is held by one runner: `signer-admin setup` refuses `single` with more than one signer and `threshold` with one, every tool that reads `cluster.json` refuses a single-mode cluster of more than one signer, and `import-draft` refuses a split file that gives one share index to two signers, or a split that does not fit the target's mode, as its runner does. `signer-admin setup` refuses a single-mode file whose signer is on GCP: that signer would hold keys alone (1 of 1), which is unsafe there (Cloud KMS has no lock on the key release rule). `-allow-gcp-unsafe-single-key` accepts the risk in the setup of such a one-signer GCP file and prints a WARNING line (a threshold file, or a signer that is not on GCP, refuses the flag); so does the key `sealing_key_release.unsafe_single_key_accepted = true` in the signer's section, which `setup-tool encode` warns about too. On mainnet the setup also needs `sealing_key_release.no_lock_accepted = true`, or it is refused: without it the runner would not start. `signer-admin import-draft` refuses a `not_after` more than 7 days from now: a runner takes shares under an order until its `not_after`, so keep it short. It drafts a 1 of 1 order to a GCP signer only with `-allow-gcp-unsafe-single-key`, and `show` prints the warning to each approver. Why, and what it means: [platform-gcp/deploy/README.md](../platform-gcp/deploy/README.md#setup), "Setup".

Module path `github.com/lidofinance/tee-signer/signer-admin`, with its own `go.mod`. It uses other modules of this repo only through their public packages (`scripts/check-imports.sh`).

Test it on its own from the repo root: `scripts/test-modules.sh signer-admin`.

## Image pin

The verifier of a cloud runner trusts the image that the signer's `cloud.json` pins (`nitro_pcrs` PCR0 to PCR2, `cce_policy_sha256` or `gcp_image_digest`), signed by the key source the file names. Any runner image attests to its own measurement, and whoever hands over the file can name a key source of their own. So before the tools connect, they hold `cloud.json` to the signer's setup (`cluster.CheckConn`):

- The pin must be on the approved list: the setup's `allowed_image_measurements`, or that of the last signed locked update in the `updates` folder. The tools walk the chain from the setup: each update names the one before as `prev_hash`, has a higher version, and carries the signatures of the approvers of the one before. Copies of one update count as one; two different updates that replace the same version stop the tools, so remove the one that was not pushed. A file that does not decode or does not chain gets a warning, once per run, and the chain stops before it.
- An update comes into force on a runner at the later of its `activate_at` and its arrival plus the wait of its time lock. `push` refuses a locked update whose `activate_at` is earlier than now plus the wait, less 5 minutes (`setupwire.PushSlack`), so a pushed update comes into force within 5 minutes after its `activate_at`. Draft with a `-margin` that covers the time from draft to push. An image that an update adds counts from its `activate_at` plus 5 minutes on. An image that the last update drops counts until its `activate_at`, so `push` does not lock out the signers still on it. An update with `activate_at` 0 never lets its added images count, and its dropped images are off at once; `draft` always sets one.
- `setup_sha256` must be the hash of the setup. When `cloud.json` has none, the tools pin that hash on the connection.
- The trust anchor must be the setup's: the verifier of the setup's platform (`dev` only for a dev platform setup), `maa_host` equal to the setup's `maa_endpoint`, the default `compliance_status`, no `gcp_issuer` and no `gcp_jwks_file`, and `mainnet` set exactly when the setup's chain is a prod chain. `maa_host` is a host name with an optional port, as in `sharedweu.weu.attest.azure.net`. The tools compare it with `maa_endpoint` in lower case, without `https://` and a trailing slash; the port must match exactly.
- So a prod-chain `cloud.json` of a cloud signer needs `"mainnet": true`, and then Azure and Nitro signers also need `key_release_sha256` (runnerclient). Older files may lack both.

Every command that reads a member of `cluster.json` runs the check. When the cluster's `updates` folder does not exist, they warn once. When a runner reports a higher locked version than the `updates` folder reaches, the tools print a warning: copy the missing signed updates there. `import -conn` and `share-import` need `-setup`, the runner's setup file, for any verifier but `dev`, and take `-updates`, the cluster's `updates` folder; a named folder that does not exist is refused. With a cloud verifier they also need `-order`, an import order whose target and cluster are those of the `-setup` file, so a runner of another setup refuses the share. They print the locked version the check used, or, without `-updates`, that they checked against the setup's own list, locked version 0. `proof-check` runs the check when the signer's folder holds the setup file (`setup`) and, optionally, an `updates` folder; its result says `pin: listed` or `pin: unchecked`, with the setup (`pin_setup`) and locked version (`pin_locked_version`) it checked against. The tools read the attestation section of `cloud.json` strictly, so a misspelled key stops them. Keep the signed file of every locked update in the `updates` folder; `push` puts it there after it has pushed to every signer.

## Admin certificate

An admin certificate that t signers accept can exit every key they hold, and nothing else gates an exit ([protocol.md](../signer-protocol/docs/protocol.md), "Client roles"). To protect it:

- Keep the admin CA key and the admin certificates offline after the split and import. Bring them out only to send an approver-signed import or config update, or to make an exit.
- Issue short-lived admin leaves. `issue-client-cert -role admin -valid D` sets the validity the operator chooses, up to the issuer's own expiry; without `-valid` a leaf gets 24h.
- Prefer one client root per signer, each held by a different person, so one admin certificate cannot reach t signers. To exit, each holder runs this on their own machine with their own admin certificate:

  ```
  signer-admin exit -cluster cluster.json -signers NAME -split split.json -pubkey 0x... -index 123 -epoch 0 -partial-out NAME.json
  ```

  Anyone then combines t of these files, with no certificate or network:

  ```
  signer-admin exit-combine -split split.json -pubkey 0x... -index 123 -epoch 0 -out exit.json NAME1.json NAME2.json
  ```

  The partial files are not secret.
- A signer accepts admin chains from every root in its `allowed_client_ca` list. Pin on each signer only roots whose keys its own holder controls. Keep any root that all signers share offline, like an admin key. A setup file that sets `allowed_client_ca` once, before the first `[signer NAME]` section, gives every signer the same root.
- The runner refuses a client whose chain holds an entry of the `revoked_client_certs` list in force (open group): the SHA-256 of a certificate's DER (leaf, intermediate or CA), or of a public key's DER SubjectPublicKeyInfo, which revokes every certificate of that key ([protocol.md](../signer-protocol/docs/protocol.md), "Client roles"). To revoke, list the hash in an open config update (`draft -group open`, then `sign`, `assemble` and `push`). It needs the usual approver count and no wait: a runner applies it when it takes the update, and closes open connections of that chain. The list holds at most 128 entries. Dropping an entry needs every approver in force, and the runner refuses a drop until one change delay after an approver removal. If an admin root key leaks, revoke its public key. The runner checks the list on every frame, HEALTH and CONFIG_UPDATE included, so this also refuses the signing clients under that root. A signer that pins only that root then takes no request over TLS: no further config update reaches it, no update can drop the entry, and it needs a new setup. `allowed_client_ca` is fixed in the setup, so a new admin root needs a new setup and a new import.
- A pre-signed voluntary exit exits its key without the signer and stays valid for good (EIP-7044). Keep only a few of them loaded in the validator ejector, not one for every key. The TEE signer does not change the usual ejector advice.

## Splitting existing keys

`signer-admin split` splits EIP-2335 keystores t of n for the sealed import. It is a trusted dealer: it decrypts each whole key, so run it on an offline machine.

```
signer-admin split -keystores DIR -password-file FILE -t T -n N -signers NAME,... [-chain mainnet|hoodi|devnet|ci-test] [-expect FILE] [-allow-swap] -out DIR
```

- `-keystores` is a folder of `keystore-*.json` with the kdf `scrypt` (n*r*p at most 2^24) or `pbkdf2` (c at most 2^24). All keystores share the one password in `-password-file`, which must be printable ASCII, in a file of mode 0600.
- `-signers` lists the signer names of `cluster.json` in share index order, 1 to n. n is at most 8, the most the gateway serves.
- t and n must pass the threshold rule of `-chain` (default mainnet), as `import-draft` checks it. On a prod chain a split needs 2t - n >= 2 (`governance/setupwire/threshold.go`). 2 of 2 passes but stops signing when any signer is down; 3 of 4 is the smallest that keeps signing with one signer down. Signers upgrade one at a time ([docs/upgrade.md](../docs/upgrade.md#rules), "Rules"). A larger margin (n - t >= 2, for example 4 of 6) lets one signer be upgraded or restarted while another is down; with n - t = 1, a second fault during an upgrade stops signing. The prod rule keeps a slashable pair out against one faulty or rogue signer, not two ([signer-protocol/docs/protocol.md](../signer-protocol/docs/protocol.md#key-rule-lock)).
- For a single-node signer, `-t 1 -n 1 -signers NAME` writes each whole key as the share of index 1. The signer's setup must say `signing_mode = single`; on GCP it must also accept the risk (`sealing_key_release.unsafe_single_key_accepted`), and `import-draft` needs `-allow-gcp-unsafe-single-key`. It misses duties for the restart floor of every restart ([docs/upgrade.md](../docs/upgrade.md#downtime-per-signer), "Downtime per signer"), about 20 to 25 minutes on mainnet.
- With `-expect`, a file of one `0x` pubkey per line, split takes exactly these keys in that order and refuses any other. Without it, split takes every keystore in the folder and prints the list.
- `-out` must be a new folder on tmpfs (Linux; for a Mac see [On macOS](#on-macos)). Swap must be off (`swapoff -a`): split refuses to run when `/proc/swaps` lists a swap device or cannot be read, because tmpfs pages and the heap can reach the swap disk. `-allow-swap` goes on with a warning, for zram or an encrypted swap device.
- split turns core dumps off (`RLIMIT_CORE` 0, not dumpable) and locks its memory in RAM when the locked memory limit is unlimited (root, or `ulimit -l unlimited`); otherwise it warns and runs unlocked. Do not suspend or hibernate the machine while split runs or while the tmpfs folder exists: hibernation writes RAM to disk whatever `/proc/swaps` says.

split checks each keystore's checksum and that the secret gives the keystore's pubkey. It checks each share against the Feldman commitments and that t shares recover each key, then reads its outputs back with the readers of `import-draft` and `import`. It writes:

- `OUT/split.json`: t, n, each signer's share index and each key's Feldman commitments. Public.
- `OUT/shares/NAME/shares.txt`: the signer's share of each key, mode 0600. Secret.
- `OUT/manifest.json`: t, n, the share indices, every share pubkey and the sha256 of `split.json`. Public.

Any t of the `shares.txt` files are the whole keys, so they never travel together and never sit on an online machine longer than one import. Per signer NAME, one at a time:

1. `signer-admin import-draft -cluster cluster.json -signer NAME -split OUT/split.json -out import.bin` (the split file is public; copy it off the dealer machine with the manifest).
2. The approvers check it with `signer-admin show` and sign it with `signer-admin sign -expect-sha256 HEX`, where HEX is the direct form's sha256 that `show` printed.
3. `signer-admin assemble -out import.signed import.bin SIG...`
4. On the dealer machine, copy only `OUT/shares/NAME/shares.txt` to removable media, nothing else of `OUT/shares`. Shares leave the dealer in plaintext only here, one signer's file at a time; signer-admin seals online only, to the runner's per-boot import key.
5. On the machine that runs `import` for NAME (it needs the admin connection and the network), copy the file from the media into a new tmpfs folder (`mount -t tmpfs none DIR`), mode 0600, and run `signer-admin import -cluster cluster.json -signer NAME -order import.signed -shares DIR/shares.txt -commitments split.json`. `import` refuses a file whose shares are not the order's share index, before it sends anything, so a wrong NAME stops here. It also turns core dumps off; keep swap off on this machine too.
6. Right after the import succeeds, delete the file: `umount DIR` for the tmpfs folder, and `shred -u` the copy on the media (shred overwrites in place, which works on a plain filesystem on a flash stick or a hard disk; an SSD or a journaling or copy-on-write filesystem may keep old blocks, so treat such media as still holding the share and keep or destroy it as a secret).

After the last signer, delete `OUT` on the dealer machine (`umount` its tmpfs) and do not reboot into a hibernation image that was made while it existed.

### On macOS

`split` and `import` also run on a Mac, Apple silicon or Intel. The steps above stay the same; this section lists what differs. Build with the Xcode command line tools and Go: `make admin` in the repo root writes `build/<arch>/bin/signer-admin`. No other part of this repo builds on macOS.

Prepare the offline Mac:

- Turn FileVault on (System Settings, Privacy & Security). `fdesetup status` must print `FileVault is On.` macOS encrypts swap by itself. Sleep can write the RAM to the disk as a hibernation image, and only FileVault protects that image with your password. signer-admin does not check FileVault.
- Turn Wi-Fi and Bluetooth off and unplug the network cable.
- Keep the Mac awake while split runs and while the RAM disk exists: lid open, and `caffeinate -i` in a second terminal.

macOS has no tmpfs mount for this. Make a RAM disk and pass a new folder on it as `-out`:

```
dev=$(hdiutil attach -nomount ram://2097152)
diskutil erasevolume APFS split $dev
signer-admin split ... -out /Volumes/split/out
```

`ram://` takes the size in 512-byte sectors; 2097152 is 1 GiB. For `import`, copy the shares file from the media to such a RAM disk too. When you are done, eject the RAM disk, which frees its memory: `hdiutil detach $dev`.

What signer-admin does on macOS, and what it does not:

- `split` and `import` turn core dumps off (`RLIMIT_CORE` 0) and stop if they cannot.
- They do not lock memory: macOS has no `mlockall`. They read from the kernel whether swap is encrypted (`vm.swapusage`) and print one line: a note when it is, a warning when it is not.
- `split` has no swap check, because macOS has no supported way to turn swap off; `-allow-swap` changes nothing.
- `split` refuses an `-out` on the startup disk (`/` or a volume under `/System/Volumes`, where the home folders are). It cannot tell a RAM disk from another disk, so for any other volume it prints a note and goes on. Check the path yourself.
- Nothing stops a debugger of the same user from reading the process, so use a machine and an account that run nothing else.

macOS has no `shred`, and overwriting a file in place does not erase it on APFS or on flash media. Treat removable media that held a shares file as a secret: keep it locked away or destroy it.

## Charon shares (signing_mode = dv_share)

A signer behind an Obol Charon node holds that node's share of each distributed validator. Charon's validator client asks for each share under the share's own key, and the aggregates and sync contributions it sends carry the selection proof the cluster combined, which verifies under the validator's group key. A setup with `signing_mode = dv_share` serves such shares: the runner signs under the share key and checks those selection proofs against the group key. Marks, floors and every other rule apply to the share key as for any key.

The group key comes from the import, never from a request. `dv-split` reads the cluster lock and writes the split file:

```
signer-admin dv-split -lock cluster-lock.json -signers NAME=INDEX[,NAME=INDEX...] [-out split.json]
```

- For each validator it takes `distributed_public_key` (the group key) and `public_shares` (share index i + 1 at position i), computes the t commitments of the split from the first t public shares (t is the lock's `threshold`), and checks that commitment 0 is the group key and that every one of the n public shares is the commitments' value at its index. A lock that fails any check writes nothing.
- `-signers` gives each dv_share signer of `cluster.json` the Charon share index it holds: its operator's position in the lock, from 1.
- dv-split does not check the lock's signatures or `lock_hash` yet. The admin vouches for the file; the approvers sign the commitments hash that `import-draft` puts in the order for each group key.

Before they sign an import order for a dv_share signer, the approvers check each group key the order names: it is a validator on chain, or it comes from a cluster lock they trust. The runner cannot tell a Charon split from one made up for the purpose. Anyone who holds a whole validator key can make up a split in which that key is the share at the order's index, with a group key no cluster uses. A dv_share runner that takes it serves the whole key under its own key and signs alone for that validator, without the single-mode rules: no GCP acceptance, no one-signer cluster check. On a prod chain `import-draft` also runs a chain check on the admin's side (below); it does not replace the approvers' check.

Then per signer, as for a split: `import-draft -split split.json -lock cluster-lock.json`, the approvers `show` and `sign`, `assemble`, and `import -order import.signed -commitments split.json -shares FILE`. The shares file may name each share by its own key, as for a single-mode import (`0x<share pubkey> <validator index> 0x<share secret>`): `import` files each share of the order's index under its group key and says how many it filed. The shares file may also name each share by its group key, as for a threshold import. `-interchange` looks each share up under its own key, the key a Charon validator client's slashing protection file uses, and `-skip-loaded` leaves out the shares the runner lists under their own key. A runner holds one share of each group key: it refuses a second one. It also refuses a key that is the group key of a share it holds, and a share whose group key is a key it holds, so it never holds a validator key next to a share of it. Two shares of one validator under two made-up group keys it cannot see: the approvers check the group keys.

For a dv_share signer `import-draft` needs `-lock`: each validator of the split file must be one of the lock's, with the commitments dv-split makes from it, so the signer's share is the lock's public share at its index.

The chain check then looks up each share key and group key of the order, on a beacon node (`-beacon URL`) or in a file of `chain-export` (`-chain-file chain.json`). A share key that is a validator is refused: a whole key would go in as a share. A group key that is unknown, not active or slashed gets a warning, except as below on a prod chain. A status that is not a validator status of the beacon API is refused, from the node or in the file. A node must serve the setup's chain (same `genesis_validators_root` and `genesis_fork_version`) and be current, or the check fails: `/eth/v1/node/syncing` says `is_syncing`, `is_optimistic` and `el_offline` false, and the head slot, timed from `genesis_time` and `SECONDS_PER_SLOT`, started at most 15 minutes before the machine's clock. A node that lost its peers or its execution client can still say `is_syncing` false while its head falls behind, and does not know the validators deposited since.

- On a prod chain (mainnet, or any chain the chain table does not list) the chain check is required. Without `-beacon` or `-chain-file` `import-draft` refuses, `-yes` does not replace the check, and every group key of the order must be a validator on chain that is not slashed or exited (`active_exiting` still passes). A `-beacon` error there says the check is required instead of offering to drop `-beacon`. Deposit a new cluster's validators before the import.
- On a non-prod chain the check is optional, and without it `import-draft` says the lookup was skipped. When no chain check backs the keys (no check, or one that does not find every group key), `import-draft` asks once on the terminal to confirm that they are shares from a Charon cluster, not whole validator keys, and writes the order only on `y` or `yes`. `-yes` confirms without the question, for scripts.

To draft on a machine without network, export the chain data on a machine with a beacon node and carry the file over:

```
signer-admin chain-export -beacon URL -lock cluster-lock.json -out chain.json
```

The file lists every group key and public share of the lock with the node's status for it (`not_found` for a key the node does not know), the chain's `genesis_validators_root` and `genesis_fork_version`, the node's head slot and epoch, the start of the head slot (`head_time`), and the time of the export. It holds public keys only. chain-export refuses a node that `-beacon` would refuse, so the head time is at most 15 minutes before the export. `import-draft -chain-file chain.json` refuses a file of another chain (either genesis value differs from the setup's), a file that does not list every key of the order, and a file whose head time or export time is more than 24 hours old or more than 5 minutes ahead of the drafting machine's clock. The age counts from the head time: a file exported today from a node stalled yesterday is stale. It also refuses a file of format 1, which has no head time. A key that became a validator after the head is not in the file, so export again for a later draft.

The chain check trusts the beacon node or the file. It does not replace the approvers' check of each group key: a beacon node can only say that a key is a validator, not that the cluster is the one the operator runs. The lock's `lock_hash` and the operators' signatures are not checked.

The runner checks the share against the order's commitments at the order's share index (`share_pubkey` must be their value there, and commitment 0 is the group key), seals the group key into the share record and lists the share under its own key in PUBLIC_KEYS. The gateway sees a whole key. The group key check only stops aggregates and contributions with a selection proof the group did not make; none of these messages is slashable.

The split must pass the chain's threshold rule as for threshold mode: on mainnet (and any chain the chain table does not list) 2t - n >= 2, so Charon's 3 of 4, 5 of 7 and 7 of 10 pass and a 2-of-3 cluster is refused.

The gateway serves a dv_share key as a whole key (PUBLIC_KEYS lists `pubkey` = `share_pubkey`): its whole-key check takes `signing_mode = dv_share` as it takes `single` ([gateway/README.md](../gateway/README.md)). A gateway older than that refuses the keys. A builder registration of a dv_share key may name the share key or the group key (a Charon validator client registers the group key); the gateway leaves that check to the runner, which knows the group key, and applies its fee recipient allowlist as for any key.

The tee-signer cluster of a dv_share setup may have any number of signers, since the other shares of each split sit in other operators' signers. A dv_share setup on GCP needs no `unsafe_single_key_accepted`: the signer holds one share, not the key, as long as the approvers checked each group key before they signed its order (above).

### From signing_mode = single

A signer that holds Charon shares as whole keys under `signing_mode = single` signs attestations and blocks, but refuses every aggregate and sync contribution: their selection proof is the group's, not the share's. To move it:

1. Write a setup that says `signing_mode = dv_share` and run `signer-admin setup`. It is a new setup, with a new `setup_sha256`; the approvers check and approve it as any new setup.
2. Start the runner on it with new stores, or remove the old share records (`shares/...` in the encrypted state store) first. Records sealed under the old setup do not open under the new one. A runner that lists records it cannot open takes no import but one batch that holds every listed key. dv_share records have the same names (the share keys), so an `import` of all of them works only while they fit one batch (1024 shares and one frame); with more, remove the old records.
3. `signer-admin dv-split -lock cluster-lock.json -signers NAME=INDEX -out split.json`.
4. `import-draft -lock cluster-lock.json [-beacon URL | -chain-file chain.json] [-yes]`, approvals and `assemble` as above. On a prod chain `-beacon` or `-chain-file` is required.
5. `signer-admin import -cluster cluster.json -signer NAME -order import.signed -commitments split.json -shares FILE [-interchange FILE]`, with the shares file of the single-mode import.

Each key starts with the restart floor of the import, so the signer misses the duties of a restart.

### Exits of dv_share keys

A distributed validator exits with t partial exits, each signed with one operator's share. In an Obol cluster the Obol API stores the partials, and each operator's `charon exit fetch` combines t of them into the full exits that its validator ejector reads. Operators with keystores keep using `lido-dv-exit` or `charon exit sign`. An operator whose share sits in a dv_share signer signs its partials with its admin certificate and posts them from its Charon host. Both kinds of operators can be in one cluster: all partials meet in the Obol API.

The commands below come with the build tag `dvt`. `make admin DVT=1` builds `build/<arch>/bin/signer-admin-dvt` (after `make core DVT=1`); `make admin` builds the default `signer-admin`, which does not have them.

A partial exit needs the validator index, so the steps repeat for each deposit batch, once the deposits are on chain:

1. On a machine with a beacon node, no certificate needed:

   ```
   signer-admin dv-indices -lock cluster-lock.json -beacon URL -out indices.json
   ```

   It checks that the node is synced and on the lock's chain (`fork_version`), and writes the index of each validator of the lock that the node knows, in the form of the beacon API's `GET /eth/v1/beacon/states/head/validators` answer. A saved answer of that endpoint works as the file too.

2. On the admin machine, with the signer's admin connection file:

   ```
   signer-admin dv-exit -cluster cluster.json -signer NAME -split split.json -lock cluster-lock.json -indices indices.json -pubkeys batch.txt [-epoch E] -out NAME-exits.json
   ```

   - `-split` is the file of `dv-split`; it gives NAME's share index. The lock must be the one the split came from.
   - `-pubkeys` names the batch, one group key per line; `-all` instead takes every validator of the lock. Without one of them `dv-exit` refuses. Every validator of the batch needs an index, or nothing is signed. A share key in the list is refused with its share index and group key.
   - After every check, before the first signature, `dv-exit` prints the batch: the count, the signer and its share index, the epoch, the lock hash, the chain and each validator's index and key. It signs only when you type `yes`, on a new connection, so a long wait at the question does not run into the signer's idle timeout. `-yes` skips the question for scripts; without `-yes`, a stdin that is not a terminal is refused. `-check` runs every check, prints the batch and stops: nothing is signed or written, and `-out` is not needed. A partial exit stays valid at every later epoch and the Obol API keeps what it gets, so check the batch before you answer.
   - `-epoch` defaults to 194048 on mainnet and 256 on Hoodi, the epochs Obol's Lido node setup gives `lido-dv-exit`. Every operator of the cluster must use the same epoch: the Obol API keeps the first epoch it gets for a validator. The signer signs in its chain's `voluntary_exit_fork_version` domain, the Capella one (EIP-7044), which is the domain Charon and the Obol API use at any epoch.
   - The setup of NAME must say `signing_mode = dv_share`, and the signer must list each share under the share's own key. `dv-exit` checks every share before it signs anything, then checks each partial under its share key. A partial the signer refuses is reported; the others are written and the command exits non-zero.
   - `-beacon URL` instead of `-indices` asks a node of the signer's chain.
   - The output holds the Obol API's `partial_exits` and `share_idx`, with the lock hash and the domain's values. It is not secret.

3. Copy the file to the Charon host and post it there:

   ```
   signer-admin dv-exit-post -lock .charon/cluster-lock.json -enr-key .charon/charon-enr-private-key NAME-exits.json
   ```

   Before it sends anything it checks: the file's `lock_hash` is the lock's; each public key is a validator of the lock; each partial verifies under the lock's public share at `share_idx` in the chain's exit domain; the ENR key belongs to operator `share_idx` of the lock. It then signs the request with the ENR key, as `charon exit sign` does, and sends `POST /exp/partial_exits/{lock_hash}` to `-api` (default `https://api.obol.tech/v1`, the address Charon uses).

   - The exit domain: on mainnet and Hoodi the tool knows it from the lock's `fork_version`. For another chain it refuses unless `-domain` (its voluntary exit domain), or `-fork-version` (the chain's Capella fork version) with `-genesis-root` (its genesis validators root), names it, and the files must agree with what you give.
   - The key file must have mode 0600 and belong to the user who runs the tool; the tool reads it on that host only and never prints it. Run the tool as the user that owns the key, the one Charon runs as (for example `sudo -u USER signer-admin dv-exit-post ...`), not as root, and do not chown the key: Charon must still read it.
   - `-api` takes https, or http to a host whose every address is a loopback one. The tool resolves the name again when it connects and connects only to such an address. It follows no redirect. An error answer of the API is cut to 200 characters, without control characters, before it is printed.
   - The tool does not recompute the lock's `lock_hash`: Charon's hash covers the whole lock in a layout that changes with the lock's version. The Obol API checks each partial against the public shares of the cluster with that hash.

   Before it signs the request it prints the batch: the count, `share_idx`, the lock hash, the URL, the chain and each validator's index, epoch and key. It posts only when you type `yes`; `-yes` and `-check` work as for `dv-exit`.

4. Once t operators have posted, each operator fetches the full exits on its Charon host into the folder its validator ejector reads (`./validator-ejector` in Obol's Lido node setup):

   ```
   charon exit fetch --all --fetched-exit-path ./validator-ejector --lock-file .charon/cluster-lock.json --private-key-file .charon/charon-enr-private-key --beacon-node-endpoints URL
   ```

   `charon exit fetch` writes `exit-<pubkey>.json`, the beacon API body the ejector reads, with mode 0600; make the files readable by the user the ejector runs as.

Security: after step 4 every operator's ejector folder holds the full exit of every validator of the cluster, as in the stock Obol and Lido flow. Whoever can read one operator's folder can exit all of those validators, so the stored exits are 1 of n whatever t is. The signer keeps the share and the partial signing behind the admin certificate, but does not change this part. The advice above to keep only a few pre-signed exits does not fit this flow.
