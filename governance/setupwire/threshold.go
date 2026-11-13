package setupwire

import (
	"errors"
	"fmt"
	"slices"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// MainnetForkVersion is the genesis fork version of Ethereum mainnet.
var MainnetForkVersion = backend.Version{0, 0, 0, 0}

// CheckThreshold is the threshold rule for a t-of-n split of the keys a
// signer of this chain holds (issue #5 R1). Two signing sets of t overlap
// in 2t - n signers. Every chain needs 2t > n, so two disjoint groups
// cannot both sign. A prod chain (ProdChain, chains.go) also needs
// 2t - n >= 2 (3 of 4, 4 of 5, ...): one signer whose mark fails, plus a
// hostile gateway, must not be enough for a slashable pair. The rule
// guarantees that for one such signer, not two: 3 of 4 overlaps in two
// signers (signer-protocol/docs/protocol.md, "Key rule lock"). The rule
// would give way to a peer mark quorum, which is not built, so nothing
// turns it off. Devnets and the test networks, the only chains a non-prod
// build runs on, keep 2-of-3, which has no margin: one rogue signer and a
// hostile gateway are enough.
//
// A single-node signer (t = n = 1) passes on every chain, mainnet
// included. CheckThresholdOn adds the rules of the setup: t = n = 1 only
// with signing_mode = single, and on GCP only with the setup's acceptance
// of the risk. That is the
// decision of the scope cut to single-node signers (the removal of key
// generation among runners), not a consequence of the rule: with one
// signing set there is nothing to overlap, and the cut accepts that one
// signer whose mark fails, plus a hostile gateway, can sign a slashable
// pair. Its protection is the mark log and the key rule lock, not a
// quorum. Every real split (n > 1) keeps the prod chain rule.
func CheckThreshold(genesisForkVersion backend.Version, genesisValidatorsRoot backend.Root, t, n int) error {
	if t < 1 || t > n || 2*t <= n {
		return fmt.Errorf("threshold %d of %d: want more than half and at most all", t, n)
	}
	if ProdChain(genesisForkVersion, genesisValidatorsRoot) && n > 1 && 2*t-n < 2 {
		return fmt.Errorf("threshold %d of %d on a prod chain (mainnet, or genesis values no row of the chain table matches): two signing sets overlap in %d signer, want 2t - n >= 2 (3 of 4, 4 of 5)", t, n, 2*t-n)
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

// CheckThresholdOn is CheckThreshold for a signer with setup s: the split
// must also fit the setup's signing_mode. A single-mode signer takes
// t = n = 1 only, and on GCP only with the setup's acceptance of the risk
// (sealing_key_release.unsafe_single_key_accepted, UnsafeSingleKeyWarning;
// Setup.Check refuses a single-mode GCP setup without it, this checks it
// again where the order's t and n are read). A threshold-mode signer
// refuses t = n = 1, so a single-node signer exists only where the
// approvers signed a setup that says so. The runner checks import orders
// with it (tee-signer/server checkSplit); signer-admin setup and
// import-draft check the same rule early.
func CheckThresholdOn(s *Setup, t, n int) error {
	switch s.SigningMode {
	case SigningModeSingle:
		if t != 1 || n != 1 {
			return fmt.Errorf("threshold %d of %d: the setup says signing_mode = single, which takes whole keys (1 of 1) only; a split needs a setup with signing_mode = threshold", t, n)
		}
		p := &s.Platform
		if p.Platform == PlatformGCP && !p.SealingKeyRelease.UnsafeSingleKeyAccepted {
			return fmt.Errorf("threshold 1 of 1 on gcp: a single-node signer on GCP is refused unless its setup accepts the risk (sealing_key_release.unsafe_single_key_accepted = true, signer-admin setup -allow-gcp-unsafe-single-key): %s", UnsafeSingleKeyWarning)
		}
	case SigningModeThreshold, SigningModeDVShare:
		// A dv_share signer holds one share of a Charon split. Its share
		// alone signs nothing for the validator, so GCP needs no acceptance.
		if n == 1 {
			return fmt.Errorf("threshold %d of 1: the setup says signing_mode = %s, so this signer holds shares of splits with n >= 2, never a whole key; a single-node signer needs a setup with signing_mode = single", t, s.SigningMode)
		}
	default:
		return fmt.Errorf("signing_mode %d: unknown, want threshold, single or dv_share", s.SigningMode)
	}
	return CheckThreshold(s.Chain.GenesisForkVersion, s.Chain.GenesisValidatorsRoot, t, n)
}

// CheckMembers is the rule that one key is held by one runner, for the
// signers of one cluster: a single-mode cluster has exactly one signer.
// Two single-mode signers would each hold the whole key with their own
// mark log, and together could sign a slashable pair. signer-admin setup
// and the cluster.json reader of the tools apply it. A runner sees only
// its own setup, so the approvers who sign its import orders hold the
// rule there.
func CheckMembers(mode SigningMode, members int) error {
	switch {
	case mode != SigningModeSingle && mode != SigningModeThreshold && mode != SigningModeDVShare:
		return fmt.Errorf("signing_mode %d: unknown, want threshold, single or dv_share", mode)
	case members < 1:
		return fmt.Errorf("no signer")
	case mode == SigningModeSingle && members != 1:
		return fmt.Errorf("signing_mode = single with %d signers: a single-mode cluster is one signer that holds whole keys, as one key is held by one runner (use signing_mode = threshold for a split)", members)
	}
	return nil
}

// CheckShareIndices checks the share indices of a t-of-n split, signer
// name to index: each is 1 to n, and no two signers have the same one.
// Two signers on one index hold the same share with their own mark logs,
// so two signing sets of t may share no runner, which breaks the overlap
// that CheckThreshold counts on; in a 1 of 1 split both hold the whole
// key.
func CheckShareIndices(n int, shares map[string]uint8) error {
	names := make([]string, 0, len(shares))
	for name := range shares {
		names = append(names, name)
	}
	slices.Sort(names)
	by := map[uint8]string{}
	for _, name := range names {
		i := shares[name]
		if i < 1 || int(i) > n {
			return fmt.Errorf("%s: share index %d, want 1 to %d", name, i, n)
		}
		if other, ok := by[i]; ok {
			return fmt.Errorf("share index %d is given to %s and %s: one share is held by one signer", i, other, name)
		}
		by[i] = name
	}
	return nil
}

// CheckSingleKeyProd refuses a setup of a prod chain that accepts a key held
// alone on GCP (sealing_key_release.unsafe_single_key_accepted) without
// sealing_key_release.no_lock_accepted. A GCP runner starts on a prod chain only
// with no_lock_accepted (platform.Options.CheckNoLock), so such a setup
// makes a runner that never starts. signer-admin setup and setup-tool
// encode both run it before they write a setup.
func CheckSingleKeyProd(p *PlatformConfig, c *Chain) error {
	k := &p.SealingKeyRelease
	if k.UnsafeSingleKeyAccepted && !k.NoLockAccepted && c.Prod() {
		return errors.New("the setup accepts a key held alone on GCP (sealing_key_release.unsafe_single_key_accepted) on a prod chain (mainnet, or genesis values no row of the chain table matches), where a GCP runner starts only with the separate acceptance of a key rule without a lock: put sealing_key_release.no_lock_accepted = true")
	}
	return nil
}
