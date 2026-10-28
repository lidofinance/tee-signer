package setupwire

import (
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
// give way to a peer mark quorum (research/peer-mark-quorum.md in the PoC
// repo), which is not built, so nothing turns it off. Devnets and the test
// networks, the only chains a testnet build runs on, keep 2-of-3. A
// single-node signer (t = n = 1) is not a split: there is one signing set
// and nothing to overlap, so it passes on every chain and every platform;
// its protection is the mark log, not a quorum.
func CheckThreshold(genesisForkVersion backend.Version, t, n int) error {
	if t < 1 || t > n || 2*t <= n {
		return fmt.Errorf("threshold %d of %d: want more than half and at most all", t, n)
	}
	if IsMainnet(genesisForkVersion) && n > 1 && 2*t-n < 2 {
		return fmt.Errorf("threshold %d of %d on mainnet: two signing sets overlap in %d signer, want 2t - n >= 2 (3 of 4, 4 of 5)", t, n, 2*t-n)
	}
	return nil
}
