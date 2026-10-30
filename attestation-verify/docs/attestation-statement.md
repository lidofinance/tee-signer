# Attestation statement: setup format 2

This file gives the exact bytes. The golden vectors are in `attestation-verify/docs/attestation-statement-vectors.json`; `governance/setupwire` makes them (`go test -run TestStatementVectors -update`), except the human forms, which `governance/setuptext` makes (`go test -run TestStatementHuman -update`), and `TestStatementVectors` recomputes every value in the file from the formulas below without the package's helpers.

The source of truth for the code is `governance/setupwire` (setupwire.go, policy.go, update.go, slottimes.go) and `signer-protocol/backend.go` (SetupState, AttestUserData, KeyReleaseHash).

What the circuits (GCP, Azure) need: sections 2, 3, 5 and 6. What the watchdog needs on top: sections 1 and 4.

## Conventions

- Integers are big endian: u8, u16, u32, u64.
- `str` is len:u8 then 1 to 255 bytes of printable ASCII.
- `a || b` is the concatenation of byte strings.
- Every hash is SHA-256. `H(ctx, x)` is SHA-256 over `len(ctx):u16 || ctx || x`, where ctx is the ASCII context string. The length prefix keeps one context from posing as another (the registry in `governance/setupwire/contexts.go`).
- Hex in the vectors file starts with `0x` and is lower case, except `gcp_eat_nonce`, which is exactly what the token carries (no prefix).

Contexts of this file:

| Name in this file | Context string | Length |
| --- | --- | --- |
| `CTX_LEAF` | `signer-policy-leaf-v1` | 21 |
| `CTX_NODE` | `signer-policy-node-v1` | 21 |
| `CTX_POLICY` | `signer-policy-root-v1` | 21 |
| `CTX_PLATFORM` | `signer-platform-commitment-v1` | 29 |
| `CTX_SETUP` | `signer-setup-v1` | 15 |
| `CTX_UPDATE` | `signer-config-update-v1` | 23 |
| `CTX_ATTEST` | `signer-runner-attest-v1` | 23 |
| `CTX_IDENTITY` | `signer-runner-identity-v1` | 25 |
| `CTX_CHAIN` | `signer-chain-v1` | 15 |
| `CTX_APPROVERS` | `signer-approver-set-v1` | 22 |
| `CTX_KEY_RELEASE` | `signer-key-release-v1` | 21 |
| `CTX_MEASUREMENT` | `signer-measurement-v1` | 21 |

`CTX_MEASUREMENT` belongs to the circuits and the watchdog (section 5, the measurement output). The runner never hashes it, so it is not in the runner's registry (`governance/setupwire/contexts.go`); it is distinct from every name there.

## 1. Policy leaves and the policy tree

The public part of a setup is three groups: `public` (fixed for the life of the signer), `locked` and `open` (the two config groups, version 0). Each field of a group is one leaf. A leaf's name is the field's key in the human form, and its value is the field's bytes in the setup encoding (section 3).

```
leaf_hash = H(CTX_LEAF, len(name):u8 || name || len(value):u32 || value || salt[32])
```

Each leaf has its own 32-byte salt. A salt of 32 zero bytes is refused everywhere: it marks a salt nobody drew.

### Leaf order and value bytes

`public`, 17 leaves:

| # | Name | Value |
| --- | --- | --- |
| 0 | `setup_format_version` | u8, 2 |
| 1 | `cluster_id` | 32 bytes, not zero |
| 2 | `handover_generation` | u64, 1 or more |
| 3 | `genesis_validators_root` | 32 bytes |
| 4 | `genesis_fork_version` | 4 bytes |
| 5 | `genesis_time` | u64, Unix seconds |
| 6 | `seconds_per_slot` | u64, not zero; the slot time at genesis |
| 7 | `slots_per_epoch` | u64, not zero |
| 8 | `preset` | u8: 1 mainnet, 2 minimal |
| 9 | `voluntary_exit_fork_version` | 4 bytes |
| 10 | `max_sign_epochs_ahead_of_clock` | u64, 1 to 16 |
| 11 | `slashing_mark_prewrite.block_slots` | u64, 0 to 64 |
| 12 | `slashing_mark_prewrite.source_epochs` | u64, 0 to 8 |
| 13 | `slashing_mark_prewrite.target_epochs` | u64, 0 to 8 |
| 14 | `max_keys` | u32, 1 to 8192 |
| 15 | `slashing_log_min_lock_days` | u32, 1 to 36500 |
| 16 | `signing_mode` | u8: 1 threshold (shares of t-of-n splits, n >= 2), 2 single (whole keys, 1 of 1 import orders only) |

`locked`, 19 leaves:

| # | Name | Value |
| --- | --- | --- |
| 0 | `approvers` | n:u8 (2 to 8), then n Ed25519 public keys of 32 bytes, in signing-position order |
| 1 | `approvals_needed` | u8; at least 2 and more than n/2 |
| 2 | `change_delay_seconds` | has:u8 (0 or 1), then u64 if has is 1; absent means the image default |
| 3 | `allowed_image_measurements` | count:u8 (0 to 32), then per entry kind:u8 (1 nitro, 2 azure, 3 gcp, 4 ta) and the measurement: 144 bytes for nitro (PCR0, PCR1, PCR2), else 32; sorted by kind, then by bytes |
| 4 | `allowed_fee_recipients` | count:u8 (0 to 64), then 20-byte addresses, sorted |
| 5 | `builder_gas_limit_min` | u64 |
| 6 | `builder_gas_limit_max` | u64 |
| 7 | `builder_registration_max_future_seconds` | u64 |
| 8 | `exit_allowed_validators` | count:u16 (0 to 1024), then u64 validator indices, sorted |
| 9 | `exit_stake_cap_per_day` | u64 Gwei |
| 10 | `exit_approvals_needed` | u8 |
| 11 | `min_activation_balance` | u64 Gwei |
| 12 | `max_effective_balance` | u64 Gwei |
| 13 | `withdrawal_credentials` | 32 bytes, prefix 0x01 or 0x02 |
| 14 | `allowed_deposit_amounts` | count:u8 (0 to 8), then u64 Gwei, sorted |
| 15 | `allow_unverified_nonslashable_signing` | u8, 0 or 1 |
| 16 | `bare_root_domains` | u16; bit n set allows domain type 0x0n000000; only bits 2, 5, 6, 7, 8, 9 |
| 17 | `slot_time_changes` | count:u8 (0 to 16), then per change epoch:u64 and seconds_per_slot:u64, ascending epochs (section 4) |
| 18 | `allowed_builder_request_auth_data_roots` | count:u8 (0 to 16), then 32-byte roots, sorted; each is hash_tree_root of a BuilderRequestAuth `data` field as SSZ ByteList[4096] (builder-specs, Gloas). The signer signs a BuilderRequestAuth only when the root of its data is on the list; empty means it signs none |

`open`, 2 leaves:

| # | Name | Value |
| --- | --- | --- |
| 0 | `fork_schedule` | count:u8 (0 to 16), then per fork epoch:u64 and version[4], ascending epochs, one fork per epoch |
| 1 | `gloas_fork_epoch` | has:u8 (0 or 1), then u64 if has is 1; must be the epoch of a fork in `fork_schedule` |

Every list without an order of its own is sorted and holds no repeats, so one set of values has one encoding. An optional field keeps its leaf when absent: the value is the single byte 0.

### The tree

Each group has its own root:

```
group_root = MerkleRoot(leaf_hash[0], ..., leaf_hash[n-1])
```

MerkleRoot pads the list with 32-byte zero hashes up to the next power of two P, then hashes pairs level by level, `node = H(CTX_NODE, left || right)`, until one hash is left. One leaf is its own root. So `public` (17 leaves, padded to 32) has depth 5, `locked` (19 leaves, padded to 32) depth 5 and `open` (2 leaves) depth 1. A zero hash cannot pose as a leaf or node hash, which would need a SHA-256 preimage of zero.

```
policy_root = H(CTX_POLICY, public_root || locked_root || open_root)
```

A leaf proves against policy_root with its Merkle path in its group and the other two group roots. To withhold a field, an operator publishes its leaf hash instead of its name, value and salt; the watchdog checks the rest against the same roots, with no new setup.

`signer-config setup` draws every policy salt once per cluster and writes the same salts into all n setups, so the signers of a cluster with the same public values have the same policy_root.

## 2. Platform commitment

The private part is the rest of the platform part, in this order:

```
private  = signer_name:str platform:u8 ca_count:u8 {der_len:u16 der}
           slashing_log_store has:u8 [encrypted_state_store] sealing_key_release
           host_count:u8 {host_port:str}
store    = nitro: bucket:str region:str
         | azure: account:str container:str subscription:str resource_group:str
         | gcp:   bucket:str
         | dev:   dir:str
sealing_key_release = nitro: region:str kms_key_id:str
         | azure: maa_endpoint:str akv_endpoint:str kid:str
         | gcp:   wif_provider:str kms_key:str attest_audience:str no_lock_accepted:u8
                 unsafe_single_key_accepted:u8
         | dev:   (nothing)
```

`platform` is 1 nitro, 2 azure, 3 gcp, 4 dev. `ca_count` is 1 to 4 DER CA certificates (`allowed_client_ca`), sorted by their bytes. `host_count` is 0 to 16 (`peer_attestation_hosts`, Nitro and dev only), sorted. `no_lock_accepted` (`sealing_key_release.no_lock_accepted`) and `unsafe_single_key_accepted` (`sealing_key_release.unsafe_single_key_accepted`, the setup accepts that the signer holds keys alone, 1 of 1) are GCP only, 0 or 1.

The private part is at most 2560 bytes (`MaxPlatformPrivate`). The attestation circuits hash it with that fixed bound (`MAX_PRIVATE` in `circuits/lib/src/platform.nr`), so a longer one could never be proven, and `signer-config setup` and the decoder refuse it. Four P-256 CA certificates take about 2.07 KB of it.

```
platform_commitment = H(CTX_PLATFORM, platform_salt[32] || private)
```

There is one platform salt per signer, drawn by `signer-config setup`.

## 3. setup_hash and the setup bytes

```
setup_hash = H(CTX_SETUP, policy_root || platform_commitment)
```

The input is 81 bytes: 2 + 15 + 32 + 32. This is setup_hash v4. It goes into every key-release context, the mark log paths and AADs, the state copy and the network-entry state, and into the setup state of IDENTITY, ATTEST and HEALTH (section 5). Verifiers pin it as `setup_sha256`.

The setup the host hands over at every start is one byte string:

```
setup = 'S' public_values public_salts locked_values locked_salts open_values open_salts
        platform_salt[32] private
```

`X_values` is the concatenation of the leaf values of group X in leaf order (section 1), and `X_salts` the concatenation of its salts in the same order (16, 19 and 2 salts). `public_values` is 142 bytes and starts with the format byte 1, so the setup's first two bytes are `0x53 0x01`. The decoder refuses trailing bytes, counts above a cap, presence bytes other than 0 or 1, unknown enum values, unsorted lists, any value the rules refuse, a zero salt, and any input that does not encode back to the same bytes. A setup larger than 64 KiB is refused, and so is one whose private part is above 2560 bytes (section 2).


## 4. Config updates

The hash of a group at version 0, in the setup state and as the `prev_hash` of the group's first update, is the root of its salted leaves: `locked_root` or `open_root` of the setup. An update carries the full new group and a fresh salt for each of its leaves. The approvers sign a header that names the root of the new group's salted leaves instead of its values, so a signature and the update's hash check out against published leaves while other leaves stay withheld, after any number of updates.

```
body   = 'B' 1:u8 cluster_id[32] chain_hash[32] group:u8 config_version:u64
         prev_hash[32] activate_at:u64 group_values group_salts
header = cluster_id[32] chain_hash[32] group:u8 config_version:u64
         prev_hash[32] activate_at:u64 group_root[32]
update = 'U' 1:u8 body_len:u32 body sig_count:u8 {position:u8 signature[64]}
         new_count:u8 {position:u8 signature[64]}
```

- `group` is 1 locked or 2 open. `group_values` are the group's leaf values as in a setup, `group_salts` one salt per leaf of that group (20 or 2), in leaf order. `group_root` is MerkleRoot over the leaves of `group_values` with `group_salts`.
- `chain_hash = H(CTX_CHAIN, genesis_validators_root || genesis_fork_version || genesis_time:u64 || seconds_per_slot:u64 || slots_per_epoch:u64 || preset:u8 || voluntary_exit_fork_version)`, the chain fields of the public group in order (61 bytes).
- The header is 145 bytes. Each signature is Ed25519 over `len(CTX_UPDATE):u16 || CTX_UPDATE || header`.
- `update_hash = H(CTX_UPDATE, header)`. The next update of the group names it as `prev_hash`, and the setup state carries it as the group's hash once the update is active or pending.
- `signer-config draft` draws the salts of each update. They are not secret from the approvers (`signer-config show` prints them and checks the root), and they reach every signer of the cluster in the same signed update.

A watchdog that has the header fields of an update, its signatures, and for each leaf either name, value and salt or only the leaf hash, rebuilds `group_root`, the header and `update_hash`, checks the signatures against the approver set in force, and compares `update_hash` with the setup state.

### Slot time changes

The genesis slot time is `seconds_per_slot` of the public group. `slot_time_changes` (locked) lists later changes: from the first slot of `epoch` on, a slot lasts `seconds_per_slot` seconds. `slots_per_epoch` never changes. Time maps to slots piece by piece: piece 0 starts at slot 0 at `genesis_time`; piece i starts at slot `epoch_i * slots_per_epoch`, at the time piece i-1 reaches that slot; within a piece, `slot = start_slot + (t - start_time) / seconds`. Before genesis the slot is 0. The epoch is `slot / slots_per_epoch`. `setupwire.SlotClock` and the C core's `sc_slot_at` and `sc_epoch_at` compute the same.

Value rules: epochs ascending and above 0, seconds per slot above 0, each change gives a slot time other than the one before it (the first one other than the genesis one), `seconds_per_slot * slots_per_epoch` fits 64 bits, and every change's start time fits 64 bits.

The rule for an update, checked by the runner when the update arrives (`CheckSlotTimeRule`, `sc_signer_check_slot_times`): let T be the update's effective activation time and E = epoch(T) under the slot times in force. Every epoch whose slot time differs between the slot times in force and the new ones must be at least E + `max_sign_epochs_ahead_of_clock` + 2 (sums saturate). Before T the signer signs no epoch past E + `max_sign_epochs_ahead_of_clock`, so both lists give the same clock for every epoch it may sign before T. The new slot times go into the signer core at T, with the other locked values.

The fork rule of the open group counts epochs under the full slot schedule: for an open update with effective time T, epoch(T) is the largest under the slot times in force and under those of a pending locked update (`sc_signer_check_schedule_under`). In the other order, a locked update with new slot times is refused while an open update is pending if, under the new slot times, that pending fork would not keep clear of every epoch the signer may reach before its effective time. So a fork never lands on an epoch whose timing a pending slot change alters within the signer's reach.

## 5. SetupState and the user data

The setup state is 353 bytes:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 32 | `setup_hash` |
| 32 | 8 | locked `version` |
| 40 | 32 | locked `hash`: the group root at version 0, else the update_hash of the update in force |
| 72 | 8 | locked pending `version`, 0 if none |
| 80 | 32 | locked pending `update_hash`, zero if none |
| 112 | 8 | locked pending `effective_at`, Unix seconds, 0 if none |
| 120 | 88 | open: the same five fields |
| 208 | 32 | `approver_set_hash = H(CTX_APPROVERS, approvals_needed:u8 || n:u8 || keys)` of the set in force |
| 240 | 1 | pending order kind: 0 none, 1 handover; a reader refuses any other |
| 241 | 32 | pending order hash, zero if none |
| 273 | 8 | pending order act time, Unix seconds, 0 if none |
| 281 | 32 | `key_release_hash`: what the runner read at start about the key that releases its sealing key, zero if nothing |
| 313 | 4 | reserved, zero |
| 317 | 4 | `imported_keys`: the number of loaded keys |
| 321 | 32 | reserved, zero |

A pending update has a version above the active one; an empty pending update or order is all zero.

The pending order is a handover order (kind 1, `signer-protocol/docs/protocol.md` "Handover"): on a source, the order from its arrival on, also after the tombstone; on a target, the handover import in progress, whose act time is the import's start. The slot holds the order's hash (`handoverorder.Hash`) and the time it may act. A reader refuses a setup state with another kind, and one whose reserved bytes are not zero. Earlier builds used kind 2 and the reserved bytes for keys made in key generation inside the runners; such a state does not read as one without them.

`key_release_hash` is what the runner read at start about the key that releases its sealing key, so a verifier sees whether that key's policy is locked:

```
key_release_hash = H(CTX_KEY_RELEASE, platform:u8 || {len(field):u32 || field} for each field)
```

| Platform | `platform` | Fields, in order | Read with |
| --- | --- | --- | --- |
| AWS Nitro | 1 | key ARN, `Origin`, `KeyManager`, `MultiRegion` (1 byte, 0 or 1), the key policy text | KMS `DescribeKey` and `GetKeyPolicy` (policy name `default`) on the setup's `kms_key_id`, granted to the parent role by the key policy |
| Azure | 2 | the key id with version (`key.kid`), `attributes.exportable` (1 byte), `release_policy.immutable` (1 byte), `release_policy.contentType`, the release policy bytes (`release_policy.data` decoded from base64url) | Key Vault Get Key on the setup's `kid` with the managed identity, which needs Key Vault Reader on the key |

The answers come over TLS from the cloud's API, so the host cannot change them. An absent Azure flag counts as 0. GCP and the dev platform have no such read, so their runners write zeros; for GCP the verifiers pin the project instead. A read that fails also leaves zeros, and the runner logs why; a verifier that pins `key_release_sha256` refuses such a runner. runnerclient (`key_release_sha256`, `-key-release-sha256`) and the watchdog (per signer) take the pin. On mainnet it is mandatory for Azure and Nitro signers: a runnerclient with `mainnet` set refuses an `azure-maa` or `aws-nitro` setting without it (and a runnerclient without `mainnet` refuses a runner whose TLS certificate names mainnet, signer-protocol/docs/protocol.md "Channel binding"), and the watchdog fails the `key_release_hash` check of an unpinned Azure or Nitro signer whose published policy names mainnet. On other chains it stays optional; GCP never takes one. The runner reads the policy once at start: a locked policy cannot change after it, and an unlocked one shows as unlocked.

The last three fields are the key origin, bytes 313 to 352. `imported_keys` counts the loaded keys, the ones `keys_hash` covers. Every key came in by an import: a sealed import, a handover, or a plaintext import in a debug build. The host can hide or roll back a stored share, which takes the key out of the count and out of keys_hash. The reserved bytes around it are zero. A runner without a setup (the flag path) leaves the key origin and `key_release_hash` zero.

The ATTEST user data, which the prover uses:

```
attest_user_data = SHA-256( len(CTX_ATTEST):u16 || CTX_ATTEST
                            || len(nonce):u16 || nonce
                            || setup_state[353]
                            || keys_hash[32] )
keys_hash        = SHA-256( pubkey[48] || share_pubkey[48] for each loaded key,
                            in ascending order of pubkey )
```

With the prover's 32-byte nonce (a beacon block root) the input is 444 bytes: 2 + 23 + 2 + 32 + 353 + 32. With no key loaded, keys_hash is SHA-256 of the empty string. The nonce is at most 1024 bytes.

The IDENTITY user data has the same start and the runner's keys after the setup state:

```
identity_user_data = SHA-256( len(CTX_IDENTITY):u16 || CTX_IDENTITY || len(nonce):u16 || nonce
                              || setup_state[353] || kem:u16 kdf:u16 aead:u16
                              || len(import_key):u16 || import_key
                              || len(tls_key_hash):u16 || tls_key_hash )
```

The IDENTITY and ATTEST messages carry version byte 1 (`wire.IdentityVersion`); a runner refuses a request of another version with UNSUPPORTED. The ATTEST answer is `1:u8 || setup_state || attestation`.

### What the proof outputs

Every byte of the setup state is public; only `keys_hash` stays a private input. The outputs that come from the signer (the vectors file lists them under `public_outputs`):

| Output | Bytes | Content |
| --- | --- | --- |
| `challenge_root` | the nonce, 32 bytes | the beacon block root the prover asked with |
| `policy_root`, `platform_commitment` | 32 bytes each | the two inputs of setup_hash; the circuit hashes them (section 3) to get setup state bytes 0 to 31 |
| `config_state` | setup state bytes 32 to 312 (281 bytes) | both groups (version, hash, pending update), the approver set hash, the pending order (kind, hash, act time) and `key_release_hash` |
| `key_origin` | setup state bytes 313 to 352 (40 bytes) | the number of loaded keys, with the reserved zero bytes around it |

The pending order and `key_release_hash` are public because a pending handover order announces an image change, and `key_release_hash` shows whether the key policies are locked; the watchdog shows both. The sample in the vectors file sets every field so every byte is exercised. `format`, `platform`, `challenge_slot`, `measurement`, `hwmodel` and `vendor_key_set_root` come from the circuit and the attestation, not from the signer's bytes.

### The measurement and hwmodel outputs

Every circuit outputs the image measurement in one form: a 32-byte hash of the platform's measurement values.

```
measurement = H(CTX_MEASUREMENT, platform:u8 || value)
```

| Platform | `platform` | `value` | Bytes | Where the attestation carries it |
| --- | --- | --- | --- | --- |
| AWS Nitro | 1 | PCR0 \|\| PCR1 \|\| PCR2 | 144 | the attestation document's `pcrs` |
| Azure | 2 | the CCE policy hash | 32 | the MAA token's `x-ms-sevsnpvm-hostdata`, lower-case hex |
| GCP | 3 | the container image digest | 32 | the token's `submods.container.image_digest`, the hex after `sha256:` |

The input after the context is an entry of `allowed_image_measurements` exactly as section 1 encodes it (kind:u8, then the measurement; the kinds are the platform codes). A watchdog hashes each entry of the locked group in force and looks for the proof's `measurement` among them, and lists its known reproducible builds by the same hash. The value is a private input of the circuit. The input is 56 bytes for Azure and GCP (two SHA-256 blocks) and 168 bytes for Nitro (three). One width for every platform keeps the output layout the same on every platform, which an outer proof that accepts any of them needs.

`hwmodel` (u8) is the hardware the attestation names, in one code space for every platform: 1 AMD SEV (`GCP_AMD_SEV`), 2 AMD SEV-ES (`GCP_AMD_SEV_ES`), 3 Intel TDX (`GCP_INTEL_TDX`), 4 AMD SEV-SNP (`AMD_SEV_SNP`, an Azure MAA token of attestation type `sevsnpvm`), 5 AWS Nitro (`AWS_NITRO`). The GCP circuit maps the token's `hwmodel` claim; the Azure circuit outputs 4, the Nitro circuit 5. The watchdog maps the code to a chip family (1, 2 and 4 are all AMD; 5 is a family of its own) and flags a cluster in which one family holds two shares.

An NSM attestation document does not reveal the parent host's CPU (Graviton, Intel or AMD), so code 5 names the Nitro system, not a chip. The AWS deploy defaults to Graviton parents (`c6g.large`), so with it family 5 is Graviton. The Nitro circuit accepts only the NSM's payload layout (key order, 16 PCRs, a cabundle of 4; `circuits/nitro/README.md`): a document in another layout fails the proof, and the watchdog shows that as "layout changed". Signing is not affected.

## 6. How each platform carries the user data

From today's runner code (`platform/*`) and verifiers (`attest/`):

| Platform | The runner asks for | Where the 32 bytes of user data end up | Checked by |
| --- | --- | --- | --- |
| GCP Confidential Space | A launcher token (`/v1/token` on the launcher socket) with `audience` = `sealing_key_release.attest_audience` of the setup (default `signer-runner-identity`), `token_type` OIDC and `nonces` = [lower-case hex of the user data] | The token's `eat_nonce` claim: the 64-character hex string. Google sends a single nonce as a string and several as an array; the runner sends one. | `attest.VerifyConfidentialSpace` with `Nonces = [hex(user data)]` (`attestation-verify/runnerclient/gcp_cs.go`) |
| Azure (SNP, MAA) | MAA attestation with runtime data `{"signer-runner-identity":"<hex>"}` (`backend.MAARuntimeData`, the same key for ATTEST and IDENTITY), `dataType` JSON | SNP REPORT_DATA = SHA-256(runtime data bytes) followed by 32 zero bytes; the MAA token has it as `x-ms-sevsnpvm-reportdata` (hex) and the runtime data under `x-ms-runtime` | `attest.VerifyMAA` with `RuntimeData` (`attestation-verify/azureid`) |
| AWS Nitro | An NSM attestation document with `nonce` = the request nonce, `user_data` = the user data, no `public_key` | The COSE_Sign1 payload's `user_data` (32 bytes) and `nonce` | `attest.VerifyNitro` with `Nonce` and `UserData` |

For GCP the audience is a private value (it is in the private part), and the token's other claims (image digest, support attributes) are outside this file.

## 7. The vectors file

`attestation-verify/docs/attestation-statement-vectors.json` holds:

- `contexts`: the context strings above.
- `setup`: a sample GCP signer of a testnet cluster with one slot time change (6 s slots from epoch 200000): its human form, its bytes, every leaf (name, value, salt, hash) of the three groups, the three group roots, policy_root, the platform salt, the private part bytes, platform_commitment and setup_hash. Salts are SHA-256 of fixed strings, so the vectors never change by chance; real salts are random.
- `update`: a locked update of that setup (version 1, `builder_gas_limit_max` to 300000000, signed by approvers 1 and 2 of the test keys): its human form, body, group root, header, update_hash and the signed update.
- `setup_state`: a SetupState (locked version 1 in force with that update, an open update pending, a pending handover order, a key_release_hash, 3 loaded keys) as JSON and as its 353 bytes. Its order hash and key_release_hash are placeholders (SHA-256 of fixed strings), not outputs of the formulas; `key_release` works key_release_hash through.
- `key_release`: key_release_hash of a sample AWS key (a policy without `kms:PutKeyPolicy`) and a sample Azure key (an immutable release policy): the platform byte, the named fields, the input and the hash.
- `attest`: the nonce (a sample beacon block root), two loaded keys, keys_hash, the exact input of attest_user_data, attest_user_data, the GCP `eat_nonce` string, the Azure runtime data and report data, and the Nitro nonce and user data.
- `public_outputs`: challenge_root, policy_root, platform_commitment, config_state and key_origin as section 5 cuts them from the setup state; `private_inputs`: keys_hash.
- `azure_setup`, `azure_attest`, `azure_public_outputs`: a second sample signer, on Azure, in the same cluster. Its public values and salts are the GCP sample's, so it has the same policy_root; its private part (MAA host `sharedneu.neu.attest.azure.net`), platform salt, platform_commitment and setup_hash are its own. `azure_attest` is its ATTEST user data for the same nonce, setup state (bytes 32 to 352 as above, its own setup_hash) and keys, with the runtime data and report data of section 6. The Azure circuit's vectors use this signer. The sample lists only a GCP image in `allowed_image_measurements`, which the circuits do not check.
- `nitro_setup`, `nitro_attest`, `nitro_public_outputs`: a third sample signer, on AWS Nitro, in the same cluster: the same public values and salts, its own private part (bucket and KMS key in eu-central-1, one peer attestation host), platform salt, platform_commitment and setup_hash. `nitro_attest` is its ATTEST user data for the same nonce, setup state and keys: the NSM document's `user_data`, with `nonce` the challenge root. The Nitro circuit's vectors use this signer.
- `measurement`: the measurement output for the sample's allowed GCP image, a sample CCE policy hash and three sample PCRs: platform, value, input and hash.

The approver keys are the Ed25519 keys from the seeds 0x01..01, 0x02..02 and 0x03..03 (32 bytes each), as in `governance/setupwire/helpers_test.go`. The client CA is `governance/setupwire/testdata/client-ca.der`.

## 8. Choices this file makes that the design left open

The design fixes the split and the field names. This file adds these points, and makes the pending order and `key_release_hash` public outputs (section 5):

1. `cluster_id`, `handover_generation` and `setup_format_version` are public leaves; `signer_name` and the platform kind are private.
2. One leaf per key of the human form. A list is one leaf (count and entries); an optional field keeps its leaf with a presence byte.
3. The tree is three group trees and a root over the three group roots, not one flat tree, so a config update can carry the root of one group.
4. The version 0 hash of a group is its root.
5. Approvers sign a header with the group root, not the values; the body carries values and salts. `signer-config draft` draws fresh salts for each update.
6. Key origin counts are u32 and are part of the setup state, so they are in IDENTITY and ATTEST alike. Every byte of the setup state is a public output; keys_hash is the one private input from the signer.
7. The slot time rule compares the new changes with the ones in force and is checked at arrival with T the effective activation time; the core takes the new slot times at T. The fork rule counts epochs under the slot times in force and those pending, in both orders of arrival (section 4).
8. The ranges: `max_sign_epochs_ahead_of_clock` 1 to 16, `slashing_mark_prewrite.block_slots` 0 to 64, `source_epochs` and `target_epochs` 0 to 8 (the design's proposed numbers, lower bounds this file's).
9. `signing_mode` is a public leaf (format 2), the last of `public`, so the leaf numbers of format 1 stay. A verifier who gets the published leaves reads whether the signer holds shares or whole keys, checked against the attested policy_root, and the mode cannot change without a new setup.
