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

Every setup file says `signing_mode`: `threshold` (the signers hold shares of t-of-n splits, n >= 2) or `single` (one signer holds whole keys). One key is held by one runner: `signer-admin setup` refuses `single` with more than one signer and `threshold` with one, every tool that reads `cluster.json` refuses a single-mode cluster of more than one signer, and `import-draft` refuses a split file that gives one share index to two signers, or a split that does not fit the target's mode, as its runner does. `signer-admin setup` refuses a single-mode file whose signer is on GCP: that signer would hold keys alone (1 of 1), which is unsafe there (Cloud KMS has no lock on the key release rule). `-allow-gcp-unsafe-single-key` accepts the risk in the setup of such a one-signer GCP file and prints a WARNING line (a threshold file, or a signer that is not on GCP, refuses the flag); so does the key `sealing_key_release.unsafe_single_key_accepted = true` in the signer's section, which `setup-tool encode` warns about too. On mainnet the setup also needs `sealing_key_release.no_lock_accepted = true`, or it is refused: without it the runner would not start. `signer-admin import-draft` refuses a `not_after` more than 7 days from now: a runner takes shares under an order until its `not_after`, so keep it short. It drafts a 1 of 1 order to a GCP signer only with `-allow-gcp-unsafe-single-key`, and `show` prints the warning to each approver. Why, and what it means: [platform-gcp/deploy/README.md](../platform-gcp/deploy/README.md#setup), "Setup".

Module path `github.com/lidofinance/tee-signer/signer-admin`, with its own `go.mod`. It uses other modules of this repo only through their public packages (`scripts/check-imports.sh`).

Test it on its own from the repo root: `scripts/test-modules.sh signer-admin`.

## Admin certificate

An admin certificate that t signers accept can exit every key they hold, and nothing else gates an exit ([protocol.md](../signer-protocol/docs/protocol.md), "Client roles"). To protect it:

- Keep the admin CA key and the admin certificates offline after the split and import. Bring them out only to send an approver-signed import or config update, or to make an exit.
- Issue short-lived admin leaves (`issue-client-cert -role admin -valid`, 24h by default).
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
- The runner has no revocation list. If an admin root key leaks, make a new setup and import the keys again.
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
- `-out` must be a new folder on tmpfs. Swap must be off (`swapoff -a`): split refuses to run when `/proc/swaps` lists a swap device or cannot be read, because tmpfs pages and the heap can reach the swap disk. `-allow-swap` goes on with a warning, for zram or an encrypted swap device.
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
