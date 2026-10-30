# signer-core fuzz targets

One fuzz target per entry point where bytes from outside reach the core,
built with ASan and UBSan. Each target is a `LLVMFuzzerTestOneInput`, so it
builds with clang's libFuzzer or, where clang's runtime is missing, with
`devkit/cfuzz/driver.c` and gcc.

```sh
make fuzz                         # build into build/<arch>/fuzz/
bash scripts/fuzz.sh ci           # regression inputs, then 5 s per target
bash scripts/fuzz.sh long         # 30 min per target (FUZZ_SECONDS), 8 at a time at most
bash scripts/fuzz.sh replay       # regression inputs and seeds only
FUZZ_TARGETS="signer bls" FUZZ_SECONDS=600 bash scripts/fuzz.sh long
```

`scripts/test.sh` runs the `ci` mode after the other suites (`FUZZ=0` skips
it).

## Targets

| Target | Entry point | Input | Oracles besides the sanitizers |
| --- | --- | --- | --- |
| `ssz_checkpoint` ... `ssz_proposer_preferences` (9) | `sc_ssz_decode_*` | SSZ bytes | wrong length is `SC_ERR_DECODE`; decode, encode gives the input back; root of the re-decoded value matches |
| `payload_envelope` | `sc_decode_payload_envelope` | fixed record | as above |
| `repeat_roots` | `sc_repeat_roots_decode` | stored repeat-root records | as above |
| `builder_request_auth` | `sc_ssz_decode_builder_request_auth`, `sc_htr_builder_auth_data` (kind 14) | SSZ bytes | accepts exactly the strict encoding; data points into the input; roots match the reference merkleization |
| `aggregate_and_proof` | `sc_decode_aggregate_and_proof` (kind 9) | preset byte, form byte, SSZ | form above 2 is `SC_ERR_ARG`; accepts exactly what the reference checks accept; fields at the right offsets; root matches the reference (binary or progressive); Electra and Gloas accept the same bytes |
| `contribution_and_proof` | `sc_decode_contribution_and_proof` (kind 10) | preset byte, SSZ | only the preset size decodes; bits past the subcommittee size refused; root matches the reference |
| `bls` | `sc_bls_verify`, `sc_bls_pubkey`, `sc_bls_sign` | pubkey, signature, secret, message | a secret that loads signs a message that verifies; a flipped signature does not |
| `config` | `sc_signer_init_ext`, `sc_signer_set_policy`, `sc_signer_check/set_schedule_under`, `sc_signer_check/set_slot_times`, `sc_slot_at` | config patches, slot times, updates | bad counts and scopes refused; the slot clock never runs backwards; an accepted schedule keeps every fork version up to epoch(T) + `max_epochs_ahead` + 1; accepted slot times keep the clock up to that epoch; a policy update keeps the chain fields |
| `signer` | every `sc_sign_*` call (kinds 1 to 14), `sc_signer_import`, `sc_signer_add_validator` with stored marks and repeat roots, restarts, storage and clock failures | header block, then operations (`signer_ops.h`) | defined status codes; per validator over the input and across restarts: no double or surround vote, no two blocks, PTC votes or envelopes for one slot; optionally signatures verify over `sc_signer_signing_root` |

The watermark storage decoder and its standalone fuzz target live in
[`markformat`](../../markformat/README.md).

`ref_ssz.h` is a second, recursive merkleization written apart from `src/`
for the root oracles. `mkseeds.c` writes the seed corpora from the test
vectors: consensus-spec-tests ssz_static and bls/sign, the go-eth2-client
and go-builder-client vectors in `tests/data`, and inputs built the way
`tests/test_unit.c` builds them.

`regress/<target>/` holds inputs that once crashed; both modes replay them
first. A crash also gets a red test in `tests/test_unit.c` before its fix.

## Engines

`make fuzz` picks libFuzzer when `clang -fsanitize=fuzzer` links (the first of
`clang`, `clang-21` ... `clang-14` on PATH, or `FUZZ_CLANG`)
(`FUZZ_ENGINE=libfuzzer|driver` forces one). On Ubuntu that needs `clang`
and `libclang-rt-<version>-dev` (the compiler-rt runtimes: libFuzzer, ASan,
UBSan).

Without them, `devkit/cfuzz/driver.c` is the engine: gcc builds the core and the target
with `-fsanitize-coverage=trace-pc,trace-cmp`. It keeps inputs that reach a
new edge, a new hit-count bucket or a comparison that gets closer to
passing, mutates with bit flips, interesting values, comparison operands,
inserts, deletes and splices, and runs the loop in a child process so that
a sanitizer report or an oracle abort saves the input as
`crash-<hash>`. `-minimize_crash=1 -runs=N FILE` shrinks a crash input.
It reads the libFuzzer flags the scripts use (`-max_total_time`, `-runs`,
`-seed`, `-max_len`, `-timeout`, `-artifact_prefix`,
`-exact_artifact_path`), plus `-keep_going=1` to restart after a crash.

To replay one input with a trace of the signer target's operations:

```sh
SC_FUZZ_TRACE=1 build/x86_64/fuzz/fuzz_signer fuzz/regress/signer/<file>
```
