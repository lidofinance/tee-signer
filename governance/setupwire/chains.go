package setupwire

import (
	"encoding/hex"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/buildchain"
)

// ChainRow is a chain's row in the chain table, the one place that says
// what each chain gets. Code reads Prod, never the chain's name.
//
// Prod is one property with two parts:
//
//   - the build of the chain has the long governance times
//     (signer-protocol/buildchain mainnet.go); a non-prod build has the
//     short ones, starts on its own chain only, and never on a prod chain
//     (governance/runnerchain);
//   - a setup of the chain gets the strict checks: the threshold rule's
//     2t - n >= 2 (CheckThreshold), the change delay floor
//     (MinChangeDelay), the key rule lock at start
//     (platform.Options.Prod), the GCP single-key rule
//     (CheckSingleKeyProd), and the client's refusal of a runner whose
//     certificate names a prod chain when its settings do not say mainnet
//     (attestation-verify/runnerclient).
//
// A setup's chain is the pair (genesis fork version, genesis validators
// root). Signing domains come from the root and the fork schedule, not
// from the genesis fork version, so a setup with a test network's fork
// version and mainnet's root signs valid mainnet messages. The fork
// version alone therefore cannot make a chain non-prod: ChainRowOf takes a
// non-prod row only when both values are the row's.
//
// The table fails closed: genesis values no row matches are prod. So a
// missing row, a chain nobody added, or a partial match only makes the
// checks stricter.
//
// The table is code in the image, so the measurement covers it. The chain
// parameters stay in the chain files (governance/chains), which the setup
// carries.
type ChainRow struct {
	Name string
	// ForkVersion is the genesis fork version of the chain.
	ForkVersion backend.Version
	// Root is the genesis validators root of the chain, in hex. Empty for
	// a row with no root of its own (devnet, ci-test): it matches any root
	// that is no public network's (PublicNetwork). A prod row matches by its fork
	// version alone, whatever the root, since a match there only makes the
	// checks stricter.
	Root string
	Prod bool
}

// chainTable: mainnet is the one prod chain. The devnet row names the
// genesis fork version of ethereum-package (Kurtosis) devnets, the one
// governance/chains/chain.sh identify takes as a devnet; a devnet with a
// fork version of its own has no row, so it is prod. The hoodi row names
// Hoodi's root (governance/chains/hoodi.json). The ci-test row, like the
// devnet row, takes any root that is no public network's: its fork
// version 0x00000001 is the minimal preset's, which local test chains
// use. The ci-test build itself runs on the exact ci-test chain only
// (governance/runnerchain).
var chainTable = []ChainRow{
	{Name: buildchain.Mainnet, ForkVersion: backend.Version{0x00, 0x00, 0x00, 0x00}, Prod: true},
	{Name: buildchain.Hoodi, ForkVersion: backend.Version{0x10, 0x00, 0x09, 0x10}, Root: "212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f"},
	{Name: buildchain.Devnet, ForkVersion: backend.Version{0x10, 0x00, 0x00, 0x38}},
	{Name: buildchain.CITest, ForkVersion: backend.Version{0x00, 0x00, 0x00, 0x01}},
}

// ChainRows returns a copy of the chain table.
func ChainRows() []ChainRow { return append([]ChainRow(nil), chainTable...) }

// ChainRowByName is the row of the chain called name.
func ChainRowByName(name string) (ChainRow, bool) {
	for _, r := range chainTable {
		if r.Name == name {
			return r, true
		}
	}
	return ChainRow{}, false
}

// matches says whether a chain with these genesis values is r's chain.
func (r ChainRow) matches(forkVersion backend.Version, root backend.Root) bool {
	if r.ForkVersion != forkVersion {
		return false
	}
	switch {
	case r.Prod:
		return true
	case r.Root != "":
		var want backend.Root
		if n, err := hex.Decode(want[:], []byte(r.Root)); err != nil || n != len(want) {
			panic("setupwire: bad root in the chain table row " + r.Name)
		}
		return want == root
	default:
		return !publicRoot(root)
	}
}

// ChainRowOf is the row of the chain with this genesis fork version and
// genesis validators root. ok is false for genesis values no row matches:
// an unknown chain, or a non-prod row's fork version with another root,
// which is prod.
func ChainRowOf(genesisForkVersion backend.Version, genesisValidatorsRoot backend.Root) (row ChainRow, ok bool) {
	for _, r := range chainTable {
		if r.matches(genesisForkVersion, genesisValidatorsRoot) {
			return r, true
		}
	}
	return ChainRow{}, false
}

// ProdChain: a setup of the chain with these genesis values gets the
// strict checks. An unknown chain does, and so does a partial match of a
// non-prod row.
func ProdChain(genesisForkVersion backend.Version, genesisValidatorsRoot backend.Root) bool {
	r, ok := ChainRowOf(genesisForkVersion, genesisValidatorsRoot)
	return !ok || r.Prod
}

// Prod is ProdChain for the setup's chain.
func (c *Chain) Prod() bool { return ProdChain(c.GenesisForkVersion, c.GenesisValidatorsRoot) }
