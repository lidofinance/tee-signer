package setupwire

import (
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
//     2t - n >= 2 (CheckThreshold), the key rule lock at start
//     (platform.Options.Prod), the GCP single-key rule
//     (CheckSingleKeyProd), and the client's refusal of a runner whose
//     certificate names a prod chain when its settings do not say mainnet
//     (attestation-verify/runnerclient).
//
// The table fails closed: a genesis fork version no row names is prod.
// So a missing row, or a chain nobody added, only makes the checks
// stricter.
//
// The table is code in the image, so the measurement covers it. The chain
// parameters stay in the chain files (governance/chains), which the setup
// carries.
type ChainRow struct {
	Name string
	// ForkVersion is the genesis fork version that names a setup's chain.
	ForkVersion backend.Version
	Prod        bool
}

// chainTable: mainnet is the one prod chain. The devnet row names the
// genesis fork version of ethereum-package (Kurtosis) devnets, the one
// governance/chains/chain.sh identify takes as a devnet; a devnet with a
// fork version of its own has no row, so it is prod.
var chainTable = []ChainRow{
	{Name: buildchain.Mainnet, ForkVersion: backend.Version{0x00, 0x00, 0x00, 0x00}, Prod: true},
	{Name: buildchain.Hoodi, ForkVersion: backend.Version{0x10, 0x00, 0x09, 0x10}, Prod: false},
	{Name: buildchain.Devnet, ForkVersion: backend.Version{0x10, 0x00, 0x00, 0x38}, Prod: false},
	{Name: buildchain.CITest, ForkVersion: backend.Version{0x00, 0x00, 0x00, 0x01}, Prod: false},
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

// ChainRowOf is the row that names this genesis fork version. ok is false
// for a fork version no row names: an unknown chain, which is prod.
func ChainRowOf(genesisForkVersion backend.Version) (row ChainRow, ok bool) {
	for _, r := range chainTable {
		if r.ForkVersion == genesisForkVersion {
			return r, true
		}
	}
	return ChainRow{}, false
}

// ProdChain: a setup of the chain with this genesis fork version gets the
// strict checks. An unknown chain does.
func ProdChain(genesisForkVersion backend.Version) bool {
	r, ok := ChainRowOf(genesisForkVersion)
	return !ok || r.Prod
}
