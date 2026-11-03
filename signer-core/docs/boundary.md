# Core boundary

The core (`src/`, `include/signer_core.h`) gets everything from its host:
memory, config, keys, request values, stored marks and the clock. This page
lists, for each input, what the core assumes and what it checks itself, with
the code that does it. The claim behind it: whatever the host returns or
asks, the core signs no slashable pair for a validator (two blocks for one
slot, two votes for one target, or a vote that surrounds another), as long
as the assumptions under "Remaining trust" hold. File names are under
`signer-core/src/` unless shown otherwise.

## Callbacks (`sc_host_ops`)

| Callback | The core assumes | The core checks or does itself | Code |
| --- | --- | --- | --- |
| `now` | The trusted clock (see "Remaining trust"). | A code other than `SC_OK` refuses the request (`SC_ERR_CLOCK`), and refuses a validator load. The value sets the clock horizon, the slot rule and the restart floor. | `signer.c` `read_clock`, `load_marks`; `policy.c` `sc_policy_check_epoch`, `sc_policy_check_slot` |
| `load_watermark` | Nothing, for safety. | `SC_ERR_UNKNOWN_VALIDATOR` means nothing stored; any other code but `SC_OK` refuses the load (`SC_ERR_STORAGE`). Unknown flag bits are dropped. The value can only raise the restart floor, never lower it. | `signer.c` `load_marks`; `slashing.c` `sc_slashing_floor`, `sc_slashing_restore` |
| `store_watermark` | `SC_OK` means the mark is durable. Needed for liveness only, with one exception under "Remaining trust". | Called before the core signs past the committed mark. A code other than `SC_OK` refuses the request and leaves the state as it was. | `slashing.c` `sc_slashing_approve_block`, `sc_slashing_approve_attestation`, `sc_slashing_cover_slot`, `sc_slashing_import` |
| `load_device_mark` | As `load_watermark`. | As `load_watermark`. Read once, at the first `sc_signer_add_validator`; each later validator starts from the copy in RAM, raised to its own restart floor. | `signer.c` `load_marks` |
| `store_device_mark` | As `store_watermark`. | As `store_watermark`. | `slashing.c` `device_raise`, `sc_slashing_cover_device`; `signer.c` `sc_signer_import` |

## Other inputs

| Input | The core assumes | The core checks or does itself | Code |
| --- | --- | --- | --- |
| Config (`sc_signer_init_ext`) | The chain values are the chain's. The timing fields and `max_epochs_ahead` are those of the run before a restart (see "Remaining trust"). | Slot timing above 0 and within 64 bits, counts within the arrays, forks in ascending order, the Gloas epoch a fork epoch, slot time changes in order; the callbacks the mark scope needs are set. | `signer.c` `sc_signer_init_ext`; `policy.c` `sc_policy_check_config`, `sc_slot_times_check` |
| Config updates | Nothing. | `sc_signer_set_policy` changes the policy fields only. `sc_signer_set_schedule` and `sc_signer_set_slot_times` refuse a change at any epoch up to epoch(T) + `max_epochs_ahead` + 1. | `signer.c` `sc_signer_set_policy`, `schedule_rule`, `slot_time_rule` |
| Secret (`sc_signer_add_validator`) | It is the share of the named validator. A wrong key gives signatures that do not verify, nothing slashable. | Nonzero and below the group order. | `bls.c` `sc_bls_load_secret` |
| Typed request values (`sc_sign_block`, `sc_sign_attestation`, the Gloas and aggregate calls) | Nothing. | The core computes the signing root from the same values it checks, so a signature covers exactly what the slashing check saw. Slot rule, clock horizon, source not above target, target the epoch of the slot, fork gate, bound index, fee recipient and gas limit lists, selection proofs. | `signer.c` `sc_sign_*`; `slashing.c` `sc_slashing_check_*`; `policy.c` |
| Bare roots (`sc_sign_root`) | The host computed the root of a type that is not slashable. | Only the listed domain types sign: never a block, attestation, exit, registration or deposit. The RANDAO root must be the root of the epoch. Clock horizon and fork gate. | `signer.c` `sc_sign_root` |
| SSZ bytes (`sc_ssz_decode_*`, aggregates, contributions) | Nothing. | Exact lengths, offsets and bit lists. | `ssz.c`, `typed.c` |
| Import (`sc_signer_import`) | The maxima are those of history the validator signed elsewhere. | `genesis_validators_root` equals the config's; unknown flag bits refused; the marks only rise (maximum per field); the repeat roots are dropped. | `signer.c` `sc_signer_import`; `slashing.c` `sc_slashing_import` |
| `sc_signer_cover_epoch` | Nothing. | Raises the device mark's target and block bounds only. | `slashing.c` `sc_slashing_cover_device` |
| Memory and calls | Calls on one `sc_signer` are serialized. | Memory size and 8-byte alignment. | `signer.c` `sc_signer_init_ext` |

## Restart floor

Each `sc_signer_add_validator` reads `now` and raises the loaded mark to
floor epoch F = epoch(now) + `max_epochs_ahead` + `SC_RESTART_FLOOR_EPOCHS`
(`signer.c` `load_marks`, `slashing.c` `sc_slashing_floor`). The validator
then refuses block slots up to the last slot of F, targets up to F and
sources below F. Gloas PTC votes and envelopes take the block bound
(`signer.c` `gloas_restore`).

Why this covers what was signed before the load, whatever the stored mark
says: every block, vote, PTC vote and envelope the core signed at a clock
reading t has an epoch of at most epoch(t) + `max_epochs_ahead`
(`sc_policy_check_epoch`). If the clock never reads an epoch more than
`SC_RESTART_FLOOR_EPOCHS` below an earlier reading, all of them are at or
below F. A new block or PTC vote or envelope is then above every old slot.
A new vote has target above F, so it repeats no old target and no old vote
surrounds it; its source is at least F, and every old source is at most F,
so it surrounds no old vote either.

Exact repeats sign again without the marks (`signer.c` `is_repeat`). The
roots are in RAM only, start empty at each load and are dropped by an
import, and a repeat is the same signature.

## Remaining trust

- The clock. Its epoch never falls more than `SC_RESTART_FLOOR_EPOCHS`
  below an earlier reading, across restarts as well. A clock that runs
  ahead and then goes back further than that can get a slashable pair
  signed.
- One live instance per share. Two cores that run at the same time with the
  same share keep their own RAM marks, and neither sees the other's
  signatures. The core cannot tell; the host must prevent it.
- The config across restarts. A later `genesis_time`, other slot timing or
  slot time changes, or a smaller `max_epochs_ahead` after a restart can
  map the clock to a lower floor than the signatures of the run before
  need.
- Storage, for liveness. A lost, old or garbled mark costs the epochs up
  to the floor, not safety. The one exception: imported maxima above the
  floor of a later load (above the clock horizon at that load) survive a
  restart only through storage.
