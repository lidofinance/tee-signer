package setupwire

import (
	"errors"
	"fmt"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// MainnetForkVersion is the genesis fork version of Ethereum mainnet.
var MainnetForkVersion = backend.Version{0, 0, 0, 0}

// IsMainnet is the mainnet test of the signer's rules: the chain's genesis
// fork version is mainnet's. CheckThreshold and the runner's key lock
// check (docs/protocol.md, "Key rule lock") use it.
func IsMainnet(genesisForkVersion backend.Version) bool {
	return genesisForkVersion == MainnetForkVersion
}

// CheckThreshold is the threshold rule for a t-of-n split of the keys a
// signer of this chain holds (issue #5 R1). Two signing sets of t overlap
// in 2t - n signers. Every chain needs 2t > n, so two disjoint groups
// cannot both sign. A chain with mainnet's genesis fork version also needs
// 2t - n >= 2 (3 of 4, 4 of 5, ...): one signer whose mark fails, plus a
// hostile gateway, must not be enough for a slashable pair. The rule would
// give way to a peer mark quorum, which is not built, so nothing turns it off. Devnets and the test
// networks, the only chains a testnet build runs on, keep 2-of-3.
//
// A single-node signer (t = n = 1) passes on every chain, mainnet
// included, and on every platform; on GCP only with the setup's acceptance
// of the risk (CheckThresholdOn). That is the
// decision of the scope cut to single-node signers (the removal of key
// generation among runners), not a consequence of the rule: with one
// signing set there is nothing to overlap, and the cut accepts that one
// signer whose mark fails, plus a hostile gateway, can sign a slashable
// pair. Its protection is the mark log and the key rule lock, not a
// quorum. Every real split (n > 1) keeps the mainnet rule.
func CheckThreshold(genesisForkVersion backend.Version, t, n int) error {
	if t < 1 || t > n || 2*t <= n {
		return fmt.Errorf("threshold %d of %d: want more than half and at most all", t, n)
	}
	if IsMainnet(genesisForkVersion) && n > 1 && 2*t-n < 2 {
		return fmt.Errorf("threshold %d of %d on mainnet: two signing sets overlap in %d signer, want 2t - n >= 2 (3 of 4, 4 of 5)", t, n, 2*t-n)
	}
	return nil
}

// UnsafeSingleKeyWarning says why a key held alone by a GCP signer is
// unsafe. signer-admin setup prints it, the human setup form carries it
// above sealing_key_release.unsafe_single_key_accepted, and a GCP runner
// logs it at start and at every import of a 1 of 1 share.
const UnsafeSingleKeyWarning = "a single-node (1 of 1) signer on GCP holds the whole validator key, and Cloud KMS has no lock on the rule that releases the sealing key: " +
	"the rule is the IAM bindings of the Workload Identity pool and the KMS key, and anyone with IAM or KMS admin rights on the project, the pool or the key (folder and organization admins included) can change them at any time, with no attestation in the way; " +
	"a changed binding lets any principal, the admin's own account included, decrypt the sealing key outside any TEE, open the sealed key from the state bucket and sign a slashable pair; " +
	"the protection is the project's IAM governance and the watchdog, not the TEE"

// CheckThresholdOn is CheckThreshold for a signer with the platform part
// p of its setup. A GCP signer holds a key alone (a single-node split,
// t = n = 1) only when its setup accepts that
// (sealing_key_release.unsafe_single_key_accepted, UnsafeSingleKeyWarning);
// without the acceptance the split is refused on every chain, also with
// sealing_key_release.no_lock_accepted. The setup has no single-node mode
// of its own: a split of t = n = 1 in an import order is the single-node
// trigger, so this check sits where that order's t and n are read.
func CheckThresholdOn(p *PlatformConfig, genesisForkVersion backend.Version, t, n int) error {
	if p.Platform == PlatformGCP && t == 1 && n == 1 && !p.SealingKeyRelease.UnsafeSingleKeyAccepted {
		return fmt.Errorf("threshold 1 of 1 on gcp: a single-node signer on GCP is refused unless its setup accepts the risk (sealing_key_release.unsafe_single_key_accepted = true, signer-admin setup -allow-gcp-unsafe-single-key): %s", UnsafeSingleKeyWarning)
	}
	return CheckThreshold(genesisForkVersion, t, n)
}

// CheckSingleKeyMainnet refuses a mainnet setup that accepts a key held
// alone on GCP (sealing_key_release.unsafe_single_key_accepted) without
// sealing_key_release.no_lock_accepted. A GCP runner starts on mainnet only
// with no_lock_accepted (platform.Options.CheckNoLock), so such a setup
// makes a runner that never starts. signer-admin setup and setup-tool
// encode both run it before they write a setup.
func CheckSingleKeyMainnet(p *PlatformConfig, genesisForkVersion backend.Version) error {
	k := &p.SealingKeyRelease
	if k.UnsafeSingleKeyAccepted && !k.NoLockAccepted && IsMainnet(genesisForkVersion) {
		return errors.New("the setup accepts a key held alone on GCP (sealing_key_release.unsafe_single_key_accepted) on mainnet, where a GCP runner starts only with the separate acceptance of a key rule without a lock: put sealing_key_release.no_lock_accepted = true")
	}
	return nil
}
