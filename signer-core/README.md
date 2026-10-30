# signer-core

> **Early proof of concept.** Provided as is, without any warranty or guarantee.
> Not audited. Not for production or mainnet funds. Interfaces and formats will
> change without notice.

In this repo, signer-core is the C module of the TEE signer. The runner links it through its Go binding (`core`; module path `github.com/lidofinance/tee-signer/signer-core`). blst is vendored in `third_party/blst` at the pin in `scripts/common.sh`, checked against `third_party/blst.sha256`. The OP-TEE trusted app and the other folders this README names outside signer-core stay in `lidofinance/threshold-signer-poc`.

The Go packages have separate roles:

- `core` binds signing, policy and slashing protection. Its only first-party production dependency is `signer-protocol`.
- `threshold` checks polynomial commitments and recovers signatures and public keys from shares. It links blst directly and does not import `core`. The current provisioning path still uses its commitment checks.
- `software` is the development backend. It also holds the sample chain configuration, memory-only hooks, random key generation and share splitting used by tests. Runners do not import it.

The binding tests use the public `core` API from an external test package.
Development helpers are test dependencies, so the bindings do not depend on them.
Threshold recovery and commitment checks have their own external test package
in `threshold/`.

Portable C signing core of the threshold signer, for the cloud runner and
the OP-TEE trusted app of each "hardware Dirk" node (`../ta/`):
SSZ hashing, BLS signing with blst, EIP-3076 slashing protection with
commit-ahead watermarks, and a signing policy. This folder builds and tests
it natively on x86_64 and cross-builds it for aarch64. The trusted app
builds the same sources with the OP-TEE TA dev kit
(`../ta/trusted-app/core/sub.mk`).

The core makes no OS calls: no stdio, no files, no time, no malloc. Storage
and the trusted clock come in through callbacks, and the caller hands it
all the memory it uses. The only outside symbols its objects reference are
`blst_*`, `memcpy`, `memset` and `memcmp`, plus the linker's
`_GLOBAL_OFFSET_TABLE_` in x86_64 PIC builds (checked by `scripts/test.sh`,
which also allows the stack protector hook `__stack_chk_fail`).

## Run it

Everything runs inside an Ubuntu 22.04 or 24.04 workbench: native Linux, a
WSL2 instance on Windows, or a Lima VM on macOS. From the repo root:

```sh
bash signer-core/scripts/run-all.sh
```

That runs, in order:

| Script | What it does |
| --- | --- |
| `scripts/deps.sh` | apt packages. On x86_64 also `gcc-aarch64-linux-gnu`, `libc6-dev-arm64-cross` and `qemu-user` (no binfmt registration). |
| `scripts/fetch.sh` | Clones blst into `signer-core/third_party/blst` and the EIP-3076 tests into `signer-core/vectors/`, downloads two consensus-spec-tests tarballs, checks their sha256 and extracts only the vectors used. `--no-vectors` fetches blst only. |
| `scripts/test.sh` | `make`, then the four test suites, the symbol check and 5 s per fuzz target (`scripts/fuzz.sh ci`, `FUZZ=0` skips it). Exits non-zero on any failure. |
| `scripts/cross-aarch64.sh` | On x86_64: cross-builds blst, the core and the tests for aarch64 (static) and runs all suites under `qemu-aarch64`. On aarch64 it does nothing, since `test.sh` already runs natively there. |
| `scripts/xcheck-go.sh` | Regenerates `tests/data/registration_go.txt` with attestantio go-builder-client and diffs it with the committed copy. Skipped if Go is missing. |
| `scripts/negative-controls.sh` | Builds 18 copies of the core, each with one deliberate bug, and checks that a test suite fails for each. |

`make core-test` in the repo root runs the same script.
`SKIP_DEPS=1 scripts/run-all.sh` skips apt. Every script is idempotent and
finds the repo root from its own location. `scripts/fresh-copy-test.sh`
copies the sources to `build/fresh-copy/repo/` (a different repo root with
an empty `third_party/`) and runs `run-all.sh` there.

Plain make also works: `make` (native), `make ARCH=aarch64
CC=aarch64-linux-gnu-gcc LDFLAGS=-static` (cross), `make symbols`,
`make clean`.

### Architectures

| Workbench | Status |
| --- | --- |
| x86_64 (Linux, WSL2) | Tested: native tests and aarch64 cross tests under qemu-user. |
| aarch64 (Lima on Apple Silicon, arm64 Linux) | Untested. The scripts detect `uname -m`, skip the cross toolchain, and build blst and the core natively. The aarch64 code itself passed every suite under qemu-user on x86_64. |

## Layout

```
include/signer_core.h   public API, for the TA and the host
src/ssz.c               SSZ encode/decode, hash_tree_root, compute_domain, signing roots
src/bls.c               blst wrapper and the hash_to_G2 LRU cache
src/slashing.c          EIP-3076 minimal strategy plus commit-ahead watermarks
src/policy.c            clock horizon, exit allowlist, builder registration rules
src/signer.c            signer object: validator table, ties the parts together
tests/                  test programs, EIP-3076 JSON flattener, Go-generated vectors
fuzz/                   fuzz targets (ASan, UBSan), engine for gcc, seed generator (fuzz/README.md)
tools/xcheck-go/        generator for tests/data/registration_go.txt
scripts/                setup, fetch, test, cross, self-test scripts
build/  vectors/  logs/ git-ignored outputs and downloads
```

## API in short

```c
size_t need = sc_signer_mem_size(max_validators, hash_cache_entries);
/* mem: 8-byte aligned, `need` bytes, owned by the caller */
sc_host_ops ops = { .ctx = ctx, .now = now,
                    /* cfg.mark_scope = SC_MARKS_PER_VALIDATOR */
                    .load_watermark = load_wm, .store_watermark = store_wm,
                    /* cfg.mark_scope = SC_MARKS_PER_DEVICE */
                    .load_device_mark = load_dev, .store_device_mark = store_dev,
                    /* cfg.persist_repeat_root = 1 */
                    .load_repeat_roots = load_rr, .store_repeat_roots = store_rr };
sc_signer *s;
sc_signer_init(mem, need, max_validators, hash_cache_entries, &cfg, &ops, &s);
sc_signer_add_validator(s, validator_pubkey, share_secret, validator_index, share_pubkey_out);
sc_sign_attestation(s, validator_pubkey, &attestation_data, signature);
sc_sign_block(s, validator_pubkey, &block_header, signature);
sc_sign_randao_reveal(s, validator_pubkey, epoch, signature);
sc_sign_voluntary_exit(s, validator_pubkey, &exit, signature);
sc_sign_validator_registration(s, validator_pubkey, &registration, signature);
sc_signer_set_policy(s, &new_policy); /* policy fields only, see Policy */
sc_signer_set_schedule(s, &new_schedule, activate_at); /* forks and Gloas, see Policy */
sc_signer_set_slot_times(s, &new_slot_times, activate_at); /* slot time changes, see Policy */
sc_sign_selection_proof(s, validator_pubkey, slot, signature, NULL);
sc_sign_aggregate_and_proof(s, validator_pubkey, ssz, len, SC_AGGREGATE_ELECTRA,
                            &SC_PRESET_MAINNET, scratch, signature, NULL);
sc_sign_sync_committee_message(s, validator_pubkey, slot, block_root, signature, NULL);
sc_sign_sync_selection_proof(s, validator_pubkey, slot, subcommittee, &SC_PRESET_MAINNET,
                             signature, NULL);
sc_sign_contribution_and_proof(s, validator_pubkey, ssz, len, &SC_PRESET_MAINNET, signature, NULL);
sc_sign_root(s, validator_pubkey, domain_type, epoch, object_root, signature);
```

The aggregate and sync committee calls (`src/typed.c` and `src/signer.c`)
take the whole message, decode it, compute its root and check it: the clock horizon, the
fork domain of the slot's epoch, the aggregator index against the bound
index (`SC_ERR_POLICY_INDEX`), the selection proof against the validator
(group) key (`SC_ERR_SELECTION_PROOF`), the subcommittee index, and for an
aggregate its form (Gloas's progressive Attestation from the Gloas fork
epoch on, `SC_ERR_POLICY_FORK` otherwise). The signer TA and the cloud
runner both sign these messages through them.

`sc_sign_root` signs a caller-supplied object root for the six types that
need no slashing protection (RANDAO, selection proof, aggregate and proof,
sync committee message, sync committee selection proof, contribution and
proof) and refuses every other domain type with `SC_ERR_POLICY_DOMAIN`. The
epoch must pass the clock horizon, and a RANDAO root must equal
`hash_tree_root(epoch)`. For the other five types the core does not see the
message content. Only the cloud runner's generic path calls it: a bare root
from Dirk's generic `Sign` (stock Vouch), behind the runner's
`allow_unverified_nonslashable` switch.

`validator_pubkey` is the validator's on-chain key and identifies it for
slashing protection and policy. The secret can be a threshold share of
that key; the signature is then a partial signature that verifies under
`share_pubkey_out`. `tests/test_unit.c` (`make_config`, `new_signer`,
`host_ops`) shows a full config and host callbacks. `sc_signer_init`
refuses a config whose callbacks are missing: a host sets only the ones its
`mark_scope` and `persist_repeat_root` need.

Lower layers are public too, so a TA or host can reuse them:
`sc_htr_*`, `sc_ssz_encode_*` / `sc_ssz_decode_*`, `sc_compute_domain`,
`sc_compute_signing_root`, `sc_compute_builder_domain`, `sc_bls_*`, and the
`sc_slashing_*` state machine.

Domains: block, attestation and RANDAO use the fork version active at the
message epoch from `cfg.forks`. Exits use `cfg.voluntary_exit_fork_version`
(set it to the Capella version, per EIP-7044). Registrations use
`DOMAIN_APPLICATION_BUILDER` with `cfg.genesis_fork_version` and an all-zero
genesis validators root.

The core is not thread safe; callers serialize calls on one signer.

## Slashing protection

RAM state per validator holds the exact highest block slot, source epoch and
target epoch signed in this run. The minimal-strategy rules refuse:

- a block with slot <= highest signed slot
- an attestation with source > target
- an attestation with source < highest signed source (it could surround an older vote)
- an attestation with target <= highest signed target (double vote, or surrounded)

These are the `sc_slashing_*` rules, and there an exact repeat is refused
too: the EIP-3076 tests expect that from a minimal strategy. The signer
(`sc_sign_attestation`, `sc_sign_block`) adds exact repeats on top, below.

### Exact repeats and `persist_repeat_root`

The signer keeps the signing root of each validator's last attestation and
last block (`sc_repeat_roots`). A request with one of these roots is signed
again without the slashing check: it is the same message, so BLS gives the
same signature, and no new slashable message exists. Policy checks still
run. Only those two roots qualify; an older vote, or another message at the
same target or slot, goes through the slashing rules and is refused.

`cfg.persist_repeat_root` decides whether the roots survive a restart:

| Setting | Writes | After a restart | Backend default |
| --- | --- | --- | --- |
| 0 | none for repeats | the marks refuse the repeat (a validator client retry right after a restart fails, the accepted cost) | OP-TEE board TA (the only value it accepts, invariant 4); cloud runner by default |
| 1 | `store_repeat_roots` before every new attestation or block: one write per vote | `load_repeat_roots` with the validator; the repeat signs | cloud runner with `-persist-repeat-root` |

With 1, the floor and any other refusal still apply to every message that
is not an exact repeat of the stored root. A failed root write does not
refuse the vote: the root stays in RAM and a repeat after a restart is then
refused, the safe direction. A rolled-back root record only holds an older
root that the validator signed. The host must bind each record to its
pubkey (storage key or authenticated data): validators of one committee sign
the same attestation root, so a root moved to another validator would let it
sign a vote it never cast. `sc_repeat_roots_encode` / `decode` give a fixed
72-byte record.

### Commit ahead

The durable watermark `{block_slot, source_epoch, target_epoch}` is a
promise: everything this validator ever signed is at or below it. Before
signing a message above the promise, the core calls `store_watermark` with
a wider one, for example "targets up to E+1, sources up to E, blocks up to
slot S+32". Messages inside the window need no write. With
`commit_ahead = {32, 1, 1}` a validator that attests every epoch writes
once every two epochs. With `{0, 4, 4}` it writes once every five.

On restart, `load_watermark` returns the promise and the RAM state starts
there. The core then refuses every block slot and target epoch at or below
the stored bounds, and every source below the stored source bound. The
source bound matters: without it, a vote signed before the crash could be
surrounded by a vote with a lower source after it. The price of a wider
window is liveness after a restart: up to window-size epochs of refused
attestations, and no attestations at all until the chain's justified epoch
reaches the stored source bound. While the chain does not finalize, the
justified epoch stays put, so a source window above 0 can stop a restarted
validator for as long as that lasts. Per-device marks (below) have no source
window for this reason.

If `store_watermark` fails, the request is refused and the state is left
unchanged.

[`markformat`](../markformat/README.md) provides the fixed 32-byte watermark storage
record. The core only handles in-memory watermark values.
Rollback protection of that record (RPMB or similar) is the TA's job.

### One mark per device

`cfg.mark_scope` picks where the marks live. `SC_MARKS_PER_VALIDATOR` is the
behaviour above: each validator has its own mark, stored with
`store_watermark`, so N validators that attest every epoch with a window of
1 write N/2 times per epoch. `SC_MARKS_PER_DEVICE` (the board TA) keeps one
mark for all validators, stored with `store_device_mark`. A message above it
raises it to targets and block epochs up to `h = epoch + target_epochs`
(blocks up to the last slot of epoch `h`). The source bound is the highest
source signed (or imported), with no window: `source_epochs` and
`block_slots` are not used. A vote whose target the mark covers but whose
source is new moves only the source bound. The first vote of a new window writes once and
every other validator's vote in that window is covered. While the chain does
not finalize, the source stays put and the device writes once per
`target_epochs + 1` epochs whatever its number of keys. While it finalizes,
the source moves every epoch, and the first vote with the new source writes:
once an epoch, whatever the number of keys. The RAM rules stay per
validator. After a restart every validator, also one added later, starts
from the device mark. An EIP-3076 import raises the device mark.

The board TA runs with `target_epochs` 0 (`commit_ahead = 32,0,0` in
`../ta/config/mainnet.conf`): the mark books no epoch ahead, so after a
restart the device refuses the targets it signed and signs the next one. A
window of 2 writes the mark once per three epochs only while the chain does
not finalize (`test_write_counts`), and the TA writes its clock floor in the
other epochs anyway, so `make ta-writes` counts the same storage writes with
0 and with 2. The window's cost after a restart is up to
`target_epochs` epochs that the device never signed and refuses.

Why no source window: after a restart every key starts at the stored source
bound and refuses any vote with a lower source. While the chain does not
finalize (an inactivity leak, for example), every vote carries the same old
source. A bound above it would refuse every vote of every key until the
chain justifies a newer epoch, which the stopped validators cannot help
bring about. With the bound at the signed source, a restarted device signs
again once the target passes the stored target bound (`test_nonfinality_restart`,
with target windows 0 and 2: 40 epochs with one source, a restart, then the next vote above the target
bound signs for all three keys, and double and surround votes are still
refused).

`sc_signer_cover_epoch(s, epoch)` raises the device mark's target and block
bounds for an epoch, never its source bound. A host that writes other state
once an epoch calls it then, so the mark rides on that write. It should do so
after the epoch's first vote: a vote with a new source writes the mark
itself, and the host's write then goes with it. The TA does this with its
clock floor and so writes its storage once per epoch in all (`../ta/README.md`,
"Write rate"). Raising a target bound never makes a vote unsafe.

The `sc_slashing_*_device` functions are the same rules without the signer,
for tests and other hosts.

`sc_signer_import` takes the per-validator maxima of an EIP-3076 interchange
file plus its genesis validators root, which must match the config. The
core does not parse JSON; the caller does.

## Policy

- Attestation target, block epoch and RANDAO epoch must be <= clock epoch +
  `max_epochs_ahead`. The clock epoch comes from the `now` callback and
  `genesis_time`, `seconds_per_slot`, `slots_per_epoch`, and the slot time
  changes the signer holds (`sc_slot_times`, none for `sc_signer_init`):
  time maps to slots piece by piece, each change starting another slot time
  at the first slot of its epoch (`sc_slot_at`, `sc_epoch_at`).
- VoluntaryExit only for a validator index in `exit_allowlist`.
- ValidatorRegistration only with `fee_recipient` in `fee_recipients`,
  `gas_limit` in `[gas_limit_min, gas_limit_max]`, `pubkey` equal to the
  signing validator, and, if `registration_max_future_seconds` is non-zero,
  a timestamp no further than that ahead of the clock.
- If a validator was loaded with an index, block `proposer_index` and exit
  `validator_index` must match it.

`sc_signer_set_policy` replaces the policy fields of a running signer:
`exit_allowlist`, `fee_recipients`, the gas limit range and
`registration_max_future_seconds`. The chain, clock horizon and slashing
settings stay, and so do the loaded validators, their slashing state and
the exact-repeat roots. A merged config that fails the checks of
`sc_signer_init` changes nothing (`SC_ERR_ARG`).

`sc_signer_set_schedule` replaces the fork schedule of a running signer
(`sc_schedule`: `forks`, `gloas_scheduled`, `gloas_fork_epoch`; the `open`
config group of `../research/setup-phase.md`, section 7). With T the later
of `activate_at` and the trusted clock, it takes the new schedule only if it
gives every epoch up to epoch(T) + `max_epochs_ahead` + 1 the same fork
version and Gloas state as the old one (sums saturate), and refuses it with
`SC_ERR_SCHEDULE` otherwise. Before T the signer signs at most
`max_epochs_ahead` epochs past its clock, so no epoch is ever signed under
both schedules, and a fork that has started never changes. An update must
therefore arrive at least `max_epochs_ahead` + 2 epochs before its first
changed epoch. Until T both schedules give the same result, so the host may
apply it as soon as it arrives. The chain identity, the clock horizon, the
slashing settings and the policy are not part of `sc_schedule`.
`sc_signer_check_schedule` makes the same checks without the change. The
cloud runner reaches both through its cgo binding (`signer-core/core`,
`Signer.CheckSchedule` and `Signer.SetSchedule`); the TA gets the same calls
with its `open` update in phase 2.

`sc_signer_init_ext` starts a signer with slot time changes in force, and
`sc_signer_set_slot_times` replaces them on a running signer by the same
rule: every epoch up to epoch(T) + `max_epochs_ahead` + 1 keeps its slot
time, so the first changed epoch is at least epoch(T) + `max_epochs_ahead` +
2, and `SC_ERR_SCHEDULE` refuses anything sooner (`sc_signer_check_slot_times`
checks without the change). The changes come from the `locked` config group
of a cloud setup (`slot_time_changes`, `../research/attestation-prover.md`,
"Signer changes", item 5). `sc_signer_init` passes none, so the board TA
keeps the plain clock and `sc_config` keeps its layout.

The fork rule counts epochs under the full slot schedule.
`sc_signer_check_schedule_under` and `sc_signer_set_schedule_under` take
slot time changes that the host has accepted but that are not yet in force
(a pending `locked` update) and use the largest epoch(T) under the changes
in force and each pending list. In the other order, a host that checks a
slot time change while a fork update is pending checks a return to the
schedule before that update with the new changes as the pending list; the
rule is symmetric, so this refuses a change that would bring the pending
fork within reach before its effective time.

Marks count slots and epochs, never the domain, so a fork change cannot lead
to a slashing: a host that restarts the signer with another fork version for
an epoch it signed gets that attestation and block refused by the marks
(`test_fork_change_marks`, and the `sched` scenario and controls of `sim/`).

## Gloas

Gloas (EIP-7732) adds three message types a validator signs
([research/gloas-signing.md](https://github.com/lidofinance/threshold-signer-poc/blob/main/research/gloas-signing.md), consensus-specs
`460fd37c`):

| Call | Message | Domain, epoch | Rules |
| --- | --- | --- | --- |
| `sc_sign_payload_attestation` | PayloadAttestationData (PTC vote) | `DOMAIN_PTC_ATTESTER` 0x0C000000, epoch of `slot` | clock horizon; one vote per slot |
| `sc_sign_payload_envelope` | ExecutionPayloadEnvelope of a self-built payload | `DOMAIN_BEACON_BUILDER` 0x0B000000, epoch of `payload.slot_number` | clock horizon; `builder_index` must be `BUILDER_INDEX_SELF_BUILD`; payload `fee_recipient` in `fee_recipients`; `beacon_block_root`, `parent_beacon_block_root` and slot of the last block this validator signed in this run; one envelope per slot |
| `sc_sign_proposer_preferences` | ProposerPreferences | `DOMAIN_PROPOSER_PREFERENCES` 0x0D000000, fork version of the epoch of `proposal_slot` | clock horizon; bound index; `fee_recipient` in `fee_recipients`; `target_gas_limit` in the gas limit range |

Each is refused with `SC_ERR_POLICY_FORK` unless `gloas_scheduled` is 1 and
the message's epoch is at or past `gloas_fork_epoch`. A zeroed config leaves
Gloas off, and `sc_signer_init` refuses a Gloas epoch that is not an epoch of
`forks[]`. `sc_sign_root` refuses the three new domain types, so no path signs
them as a bare root. Validators never sign a bid: a self-build bid carries
the point at infinity (`validator.md`).

The envelope comes as `sc_payload_envelope`: every fixed-size field as a
value, and `logs_bloom`, `extra_data`, `transactions`, `withdrawals`,
`block_access_list` and `execution_requests` as their roots, the way a block
comes as its header. The core computes the envelope's `hash_tree_root` from
those fields with progressive merkleization (`sc_merkleize_progressive`,
EIP-7916, and the active-fields mix-in of EIP-7495), and reads the slot, fee
recipient, builder index and block roots itself.

None of the three is slashable in the spec. A threshold signer still must
not let two quorums of shares sign two PTC votes or two envelopes for one
slot, so the core refuses a PTC vote or envelope at or below the slot of the
last one it signed (`SC_ERR_EQUIVOCATION`), except an exact repeat of that
last one. The two slot bounds need no new field in the stored mark: they
share the block bound. Before signing a PTC vote or envelope above the stored
block bound, the core raises that bound (`sc_slashing_cover_slot` per
validator, `sc_slashing_cover_device` per device, one write); after a restart
both kinds start from it. With per-device marks the first vote of an epoch
already moves the block bound to the end of the commit-ahead window, so a
device that votes every epoch writes nothing more for Gloas. Their exact
repeat roots stay in RAM, also with `persist_repeat_root` 1, so a repeat
right after a restart is refused and the other signers of the threshold sign
it. The envelope's block binding also lives in RAM: after a restart between
a block and its envelope, this node refuses the envelope.

## Hash-to-G2 cache

Signing is `sk * H(signing_root)`. The signer keeps a small LRU of
`H(signing_root)` keyed by the 32-byte root, so validators in one committee
signing the same AttestationData pay for one hash. 64 validators signing one
root: 1 miss, 63 hits.

## Pinned inputs

| Input | Version | Integrity |
| --- | --- | --- |
| supranational/blst | v0.3.16 | commit e7f90de551e8df682f3cc99067d204d8b90d27ad |
| consensus-spec-tests `minimal.tar.gz` (ssz_static) | v1.6.0-beta.0 | sha256 c28c30c3... (GitHub asset digest) |
| consensus-spec-tests `general.tar.gz` (bls/sign) | v1.5.0 | sha256 708f8325... (recorded on first download) |
| eth-clients/slashing-protection-interchange-tests | v5.3.0 | commit bb7900688eecd287d8723154faac6addb5e63336 |
| attestantio/go-builder-client (xcheck only) | v0.8.0 | `tools/xcheck-go/go.sum` |

v1.6.0-beta.0 `general.tar.gz` does not ship `phase0/bls/sign`, so the BLS
vectors come from v1.5.0. Full hashes and
URLs are in `scripts/common.sh`.

## Test suites

| Suite | Source | What runs |
| --- | --- | --- |
| `test_ssz_static` | consensus-spec-tests ssz_static, minimal preset, all 9 forks in the release | Checkpoint, AttestationData, BeaconBlockHeader, VoluntaryExit, ForkData, SigningData, and Gloas PayloadAttestationData: snappy decode, SSZ decode, re-encode byte-equal, hash_tree_root equal to `roots.yaml`. |
| `test_unit` Gloas part | `tests/data/gloas_go.txt` from `tools/xcheck-gloas` (go-eth2-client v0.30.3, `scripts/xcheck-gloas.sh` regenerates and compares) | PayloadAttestationData, ProposerPreferences and full ExecutionPayloadEnvelope roots; progressive merkleization by hand; fork gate, equivocation, exact repeats, envelope block binding, preference policy, restart from the block bound with both mark scopes. |
| `test_bls_sign` | consensus-spec-tests general/phase0/bls/sign | Signature bytes equal, verify passes, cached hash path gives the same bytes; zero key refused. |
| `test_eip3076` | slashing-protection-interchange-tests | All 38 tests, using `should_succeed` (the minimal-strategy field), in four modes: no window, window, restart before every op, window plus restart. |
| `test_unit` | this repo | Builder domain known answer, ValidatorRegistrationV1 against go-builder-client, policy refusals, policy replacement with `sc_signer_set_policy`, fork schedule updates with `sc_signer_set_schedule` (the epoch limit, `activate_at`, started forks, Gloas state, saturation), slot time changes (`sc_slot_at` piece by piece, the value rules, the clock horizon of `sc_signer_init_ext`, the rule of `sc_signer_set_slot_times`), marks that refuse a vote and a block signed again under another fork version, commit-ahead write counts, restart behaviour, storage failure, import, cache hits, validator table errors, fork version selection, exact repeats in one run and across a restart with `persist_repeat_root` 0 and 1 (both mark scopes), failing and corrupt root records, per-device marks, `sc_signer_cover_epoch`, write counts for 1, 16 and 1,000 keys with both settings, and randomized restart-safety property tests for per-validator and per-device marks. |
| fuzz targets | `fuzz/`, seeds from the vectors above | One target per decoder entry point with ASan and UBSan: SSZ decoders, stored mark and repeat root records, AggregateAndProof (all forms) and ContributionAndProof against a second merkleization, BuilderRequestAuth, BLS inputs, config and update readers, and the signer driven through every request kind with a slashing-safety oracle. `scripts/test.sh` runs 5 s per target; `scripts/fuzz.sh long` runs 30 min (fuzz/README.md). |

ValidatorRegistrationV1 is a builder-specs container, so consensus-spec-tests
has no vectors for it. `tests/data/registration_go.txt` holds 64 registrations
hashed by go-builder-client (fastssz) instead.

No EIP-3076 test is skipped. Two notes on how they apply:

- `should_succeed_complete` is for the complete strategy and is not used.
- When an interchange contains slashable data, the core imports it by
  taking per-field maxima. The test README allows that.

## Not done

- Deposits in the core. The trusted app signs deposits itself
  (`../ta/trusted-app/signer_ta.c`, see [SIGN_TYPED](https://github.com/lidofinance/threshold-signer-poc/blob/main/ta/README.md#sign_typed)).
- No policy authentication in the core. `sc_signer_set_policy` replaces the
  policy at run time without checking who sent it. The trusted app takes a
  new policy only when m of n approvers signed it (`SET_POLICY`, see
  [Provisioning and the signed policy](https://github.com/lidofinance/threshold-signer-poc/blob/main/ta/README.md#provisioning-and-the-signed-policy)).
- The core trusts the `now` callback. The trusted app keeps its own clock.
  Provisioning sets it from the CA-signed record, and after that the normal
  world can move it only forward, in bounded steps (`clock_max_step`). QEMU
  has no secure real-time clock.
- Attestation `slot` is not checked against `target.epoch`, in the core or
  in the trusted app.
- Restart while the chain justifies nothing, with per-validator marks and
  `commit_ahead.source_epochs` above 0: the stored source bound can sit above
  the last justified epoch until justification reaches it. Per-device marks
  do not have this problem: the source bound is the highest source signed or
  imported, `source_epochs` is not used, and `sc_signer_cover_epoch` covers
  targets and blocks only, so a restarted signer signs again with its first
  vote (`test_nonfinality_restart`).
- Real hardware. The OP-TEE TA dev kit build of the core has run on QEMU
  only.
