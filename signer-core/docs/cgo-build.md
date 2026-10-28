# The C signer core

The runner signs with the portable C signer core in the `signer-core`
folder of this repo. `scripts/build-core.sh` builds it. The script copies `include/` and `src/` into `build/core-src/`, writes
`build/core-src/SOURCE.txt` (the folder, its last git commit of those files
and the sha256 of each file), and builds `libsigner_core.a` and `libblst.a`
per arch into `build/<arch>/lib/`. `signer-core/core` links them with cgo.

`sc_sign_root` signs an object root for the six message
types that need no slashing protection (RANDAO, selection proof, aggregate
and proof, sync committee message, sync committee selection proof,
contribution and proof). Any other domain type returns
`SC_ERR_POLICY_DOMAIN`. The epoch must pass the clock horizon, and a RANDAO
root must equal `hash_tree_root(epoch)`. signer-core's `test_sign_root`
covers it, and `signer-core/core` tests sign every root type through it.

`sc_signer_set_schedule` and `SC_ERR_SCHEDULE` (setup phase) replace the
fork schedule of a running signer, only when the change leaves
every epoch it may sign before the change applies as it was.
`signer-core/core` exposes them as `Signer.SetSchedule` and
`Signer.CheckSchedule`. The typed SIGN check of the caller's domain
(`signer-protocol/docs/protocol.md`) follows the schedule in force.

`scripts/upstream-tests.sh` compiles signer-core's own test programs (unit,
ssz_static, bls/sign, EIP-3076) against the library built here and runs
them on signer-core's vectors (read-only). It skips if the tests or vectors
are not there.
