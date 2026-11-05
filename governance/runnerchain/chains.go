package runnerchain

import (
	"encoding/hex"
	"fmt"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// A non-prod build runs on its own chain only, and never on mainnet or
// another public chain. The runner checks the setup's chain at start
// (tee-signer/runnerchain.go). The mainnet build runs on mainnet only, by
// its exact genesis fork version and genesis validators root
// (tee-signer/prodchain.go): a setup with another chain's fork version
// would start it without the prod rules while it signs for mainnet.
//
//   - hoodi: Hoodi, by its exact genesis fork version and genesis
//     validators root.
//   - ci-test: the chain of governance/chains/chain.ci-test.json, the same
//     values as software.DevConfig, by both values.
//   - devnet: a chain with the devnet row's genesis fork version
//     (ethereum-package GENESIS_FORK_VERSION 0x10000038, the Kurtosis
//     default) and a root that is no public network's.
//
// Every build looks up the setup's genesis values in the chain table
// (governance/setupwire chains.go), which takes a non-prod row only when
// both values are the row's. Values no row matches are an unknown chain,
// which counts as prod, so no non-prod build starts on it: the table fails
// closed. A devnet with a fork version of its own runs the mainnet build
// or gets a row.
//
// A chain with either value of a public network (setupwire.PublicNetwork),
// and not both, is refused by every non-prod build: a known fork version
// with another root is a copy or a mistake, not a devnet. The ci-test
// chain counts by both values only: its fork version 0x00000001 is also
// the minimal preset's, which local devnets use.

// ciTestRoot is the root of governance/chains/chain.ci-test.json:
// sha256("tee-signer dev chain"), as in software.DevConfig. The chain
// table's ci-test row takes any root that is no public network's; the
// ci-test build takes this one only.
const ciTestRoot = "535276eb9690335cc5e4cb926858a79ece25caaf930a7dfad44757c8b7bef420"

// PublicNetwork names the public network with these genesis values, or
// "" for a devnet. exact is true when both values are the network's.
func PublicNetwork(forkVersion [4]byte, root [32]byte) (name string, exact bool) {
	return setupwire.PublicNetwork(backend.Version(forkVersion), backend.Root(root))
}

// CheckChain refuses a chain the build of c must not run on. nil: the
// chain is c's own. The mainnet build runs on mainnet with its exact
// values only, and refuses every other chain. A non-prod build refuses
// every prod chain (a prod row, or genesis values no row matches), and
// then every chain but its own. A build the table does not have runs on
// none.
func (c Chain) CheckChain(forkVersion [4]byte, root [32]byte) error {
	if _, known := setupwire.ChainRowByName(string(c)); !known {
		return fmt.Errorf("chain %s: no build of this name", c)
	}
	name, exact := PublicNetwork(forkVersion, root)
	values := fmt.Sprintf("genesis fork version 0x%x and genesis validators root 0x%x", forkVersion, root)
	if c.Prod() {
		if c == Mainnet && name == "mainnet" && exact {
			return nil
		}
		return fmt.Errorf("chain with %s: a %s build runs on mainnet with its exact values only", values, c)
	}
	own, ok := map[Chain]string{Hoodi: "hoodi with its exact values", CITest: "the ci-test chain (governance/chains/chain.ci-test.json)",
		Devnet: "devnets, whose genesis values are their own"}[c]
	if !ok {
		return fmt.Errorf("chain %s: no build of this name", c)
	}
	row, known := setupwire.ChainRowOf(backend.Version(forkVersion), backend.Root(root))
	switch {
	case known && row.Prod:
		return fmt.Errorf("chain %s (%s): a prod chain, and a %s build runs on %s only", row.Name, values, c, own)
	case known && row.Name == string(c) && (c != CITest || hex.EncodeToString(root[:]) == ciTestRoot):
		return nil
	case exact && !known:
		return fmt.Errorf("chain %s (%s): no row in the chain table, so a prod chain, and a %s build runs on %s only", name, values, c, own)
	case exact:
		return fmt.Errorf("chain %s (%s): a %s build runs on %s only", name, values, c, own)
	case name != "":
		f, r, _ := setupwire.PublicNetworkValues(name)
		return fmt.Errorf("chain with %s: %s has fork version 0x%x and root 0x%x, and a partial match is a prod chain; a %s build runs on %s only", values, name, f, r, c, own)
	case !known:
		return fmt.Errorf("chain with %s: no row in the chain table matches both values, so a prod chain, and a %s build runs on %s only", values, c, own)
	}
	return fmt.Errorf("chain with %s: a %s build runs on %s only", values, c, own)
}
