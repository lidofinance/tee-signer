package runnerchain

import (
	"encoding/hex"
	"fmt"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// A non-prod build runs on its own chain only, and never on mainnet or
// another public chain. The runner checks the setup's chain at start
// (tee-signer/runnerchain.go); the mainnet build runs on any chain.
//
//   - hoodi: Hoodi, by its exact genesis fork version and genesis
//     validators root.
//   - ci-test: the chain of governance/chains/chain.ci-test.json, the same
//     values as software.DevConfig, by both values.
//   - devnet: a chain with the devnet row's genesis fork version
//     (ethereum-package GENESIS_FORK_VERSION 0x10000038, the Kurtosis
//     default) and a root that is no public network's.
//
// Every build first looks up the setup's fork version in the chain table
// (governance/setupwire chains.go). A fork version no row names is an
// unknown chain, which counts as prod, so no non-prod build starts on it:
// the table fails closed. A devnet with a fork version of its own runs
// the mainnet build or gets a row.
//
// A chain is a public network when its genesis fork version and its
// genesis validators root are both the network's. A chain with either
// value of a network, and not both, is refused by every non-prod build:
// a known fork version with another root is a copy or a mistake, not a
// devnet. The ci-test chain counts by both values only: its fork version
// 0x00000001 is also the minimal preset's, which local devnets use.
//
// The values come from these sources:
//
//	[geth]   go-ethereum v1.17.8 in the Go module cache, beacon/params/networks.go
//	[epkg]   ethereum-package 6.1.0, src/package_io/constants.star,
//	         GENESIS_VALIDATORS_ROOT
//	[teku]   the local consensys/web3signer:26.9.0 image: spec-26.9.1.jar,
//	         tech/pegasys/teku/spec/config/configs/<name>.yaml (GENESIS_FORK_VERSION),
//	         and networks-26.9.1.jar, <name>-genesis.ssz, whose bytes 8 to 40 are the
//	         genesis state's genesis_validators_root
//	[lh]     the local sigp/lighthouse:v8.2.3 image: the built-in network configs in
//	         /usr/local/bin/lighthouse (GENESIS_FORK_VERSION, and the root next to the
//	         genesis state's checksum for the networks it downloads)
//	[cloud]  governance/chains/hoodi.json and mainnet.json in this repo
//
// Not listed: Teku's swift, less-swift and minimal configs (test presets
// with fork version 0x00000001, which local devnets use too), Teku's
// plataberget (no network named in the file), and ephemery, whose values
// change with each of its periods.
var networks = []network{
	// [geth], [epkg], [cloud]; fork version also [teku] mainnet.yaml, [lh]
	{"mainnet", "00000000", "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"},
	// [teku] gnosis.yaml and gnosis-genesis.ssz; fork version also [lh]
	{"gnosis", "00000064", "f5dcb5564e829aab27264b9becd5dfaa017085611224cb3036f573368dbb9d47"},
	// fork version [teku] holesky.yaml, [lh]; root [epkg], [lh]
	{"holesky", "01017000", "9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1"},
	// [teku] lukso.yaml and lukso-genesis.ssz
	{"lukso", "42000001", "a27edd68cde5c396f499157945d062a010308ce5ed5719a6b1e12ad2a51b97e6"},
	// [geth], [cloud]; root also [epkg], [lh]
	{"hoodi", "10000910", "212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f"},
	// [geth], [epkg]; fork version also [teku] sepolia.yaml, [lh]
	{"sepolia", "90000069", "d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078"},
	// [teku] chiado.yaml and chiado-genesis.ssz; root also [lh]
	{"chiado", "0000006f", "9d642dac73058fbf39c0ae41ab1e34e4d889043cb199851ded7095bc99eb4c1e"},
}

// ciTest is the chain of governance/chains/chain.ci-test.json: the root is
// sha256("tee-signer dev chain"), as in software.DevConfig.
var ciTest = network{"ci-test", "00000001", "535276eb9690335cc5e4cb926858a79ece25caaf930a7dfad44757c8b7bef420"}

// network is a chain by its genesis values, in hex. Strings keep the table
// static data, with nothing to run at package init.
type network struct {
	name string
	fork string
	root string
}

func (n network) values() (fork [4]byte, root [32]byte) {
	if _, err := hex.Decode(fork[:], []byte(n.fork)); err != nil {
		panic("runnerchain: bad fork version of " + n.name)
	}
	if _, err := hex.Decode(root[:], []byte(n.root)); err != nil {
		panic("runnerchain: bad root of " + n.name)
	}
	return fork, root
}

func (n network) is(fork [4]byte, root [32]byte) bool {
	f, r := n.values()
	return f == fork && r == root
}

// PublicNetwork names the public network with these genesis values, or
// "" for a devnet. exact is true when both values are the network's.
func PublicNetwork(forkVersion [4]byte, root [32]byte) (name string, exact bool) {
	for _, n := range networks {
		if n.is(forkVersion, root) {
			return n.name, true
		}
	}
	for _, n := range networks {
		if f, r := n.values(); f == forkVersion || r == root {
			return n.name, false
		}
	}
	return "", false
}

// CheckChain refuses a chain the build of c must not run on. nil: the
// chain is c's own. A prod build runs on any chain. A non-prod build
// refuses every prod chain (a prod row, or a fork version without a row),
// whatever its root, and then every chain but its own. A build the table
// does not have runs on none.
func (c Chain) CheckChain(forkVersion [4]byte, root [32]byte) error {
	if _, known := setupwire.ChainRowByName(string(c)); !known {
		return fmt.Errorf("chain %s: no build of this name", c)
	}
	if c.Prod() {
		return nil
	}
	own := map[Chain]string{Hoodi: "hoodi with its exact values", CITest: "the ci-test chain (governance/chains/chain.ci-test.json)",
		Devnet: "devnets, whose genesis values are their own"}[c]
	name, exact := PublicNetwork(forkVersion, root)
	values := fmt.Sprintf("genesis fork version 0x%x and genesis validators root 0x%x", forkVersion, root)
	row, known := setupwire.ChainRowOf(backend.Version(forkVersion))
	switch {
	case known && row.Prod:
		return fmt.Errorf("chain %s (%s): a prod chain, and a %s build runs on %s only", row.Name, values, c, own)
	case !known && exact:
		return fmt.Errorf("chain %s (%s): no row in the chain table, so a prod chain, and a %s build runs on %s only", name, values, c, own)
	case !known:
		return fmt.Errorf("chain with %s: its fork version has no row in the chain table, so a prod chain, and a %s build runs on %s only", values, c, own)
	}
	switch c {
	case Hoodi:
		if name == "hoodi" && exact {
			return nil
		}
	case CITest:
		if ciTest.is(forkVersion, root) {
			return nil
		}
	case Devnet:
		if row.Name == string(Devnet) && name == "" {
			return nil
		}
	default:
		return fmt.Errorf("chain %s: no build of this name", c)
	}
	switch {
	case exact:
		return fmt.Errorf("chain %s (%s): a %s build runs on %s only", name, values, c, own)
	case name != "":
		for _, n := range networks {
			if n.name == name {
				f, r := n.values()
				return fmt.Errorf("chain with %s: %s has fork version 0x%x and root 0x%x; a %s build runs on %s only", values, name, f, r, c, own)
			}
		}
	}
	return fmt.Errorf("chain with %s: a %s build runs on %s only", values, c, own)
}
