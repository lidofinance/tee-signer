package flavor

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// A testnet build runs on devnets and on the public test networks below
// marked testnet, and on no other public chain. The runner checks the
// setup's chain at start (runner/testnet.go); the default build runs on
// any chain.
//
// A chain is that public network when its genesis fork version and its
// genesis validators root are both the network's. A chain with either
// value of a network, and not both of an allowed one, is refused: a known
// fork version with another root is a copy or a mistake, not a devnet.
// Every other chain counts as a devnet. Kurtosis devnets (ethereum-package
// GENESIS_FORK_VERSION 0x10000038) and core.DevConfig (0x00000001) have
// fork versions no public network below has.
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
//	[cloud]  cloud/chains/hoodi.json in this repo
//
// Not listed: Teku's swift, less-swift and minimal configs (test presets
// with fork version 0x00000001, which local devnets use too), Teku's
// plataberget (no network named in the file), and ephemery, whose values
// change with each of its periods.
var networks = []network{
	// [geth], [epkg]; fork version also [teku] mainnet.yaml, [lh]
	{"mainnet", false, "00000000", "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"},
	// [teku] gnosis.yaml and gnosis-genesis.ssz; fork version also [lh]
	{"gnosis", false, "00000064", "f5dcb5564e829aab27264b9becd5dfaa017085611224cb3036f573368dbb9d47"},
	// fork version [teku] holesky.yaml, [lh]; root [epkg], [lh]
	{"holesky", false, "01017000", "9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1"},
	// [teku] lukso.yaml and lukso-genesis.ssz
	{"lukso", false, "42000001", "a27edd68cde5c396f499157945d062a010308ce5ed5719a6b1e12ad2a51b97e6"},
	// [geth], [cloud]; root also [epkg], [lh]
	{"hoodi", true, "10000910", "212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f"},
	// [geth], [epkg]; fork version also [teku] sepolia.yaml, [lh]
	{"sepolia", true, "90000069", "d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078"},
	// [teku] chiado.yaml and chiado-genesis.ssz; root also [lh]
	{"chiado", true, "0000006f", "9d642dac73058fbf39c0ae41ab1e34e4d889043cb199851ded7095bc99eb4c1e"},
}

// network is a public chain by its genesis values, in hex. Strings keep
// the table static data, with nothing to run at package init.
type network struct {
	name    string
	testnet bool // a testnet build may run on it
	fork    string
	root    string
}

func (n network) values() (fork [4]byte, root [32]byte) {
	if _, err := hex.Decode(fork[:], []byte(n.fork)); err != nil {
		panic("flavor: bad fork version of " + n.name)
	}
	if _, err := hex.Decode(root[:], []byte(n.root)); err != nil {
		panic("flavor: bad root of " + n.name)
	}
	return fork, root
}

// TestnetNetworks names the public networks a testnet build runs on.
func TestnetNetworks() []string {
	var out []string
	for _, n := range networks {
		if n.testnet {
			out = append(out, n.name)
		}
	}
	return out
}

// PublicNetwork names the public network with these genesis values, or
// "" for a devnet. exact is true when both values are the network's.
func PublicNetwork(forkVersion [4]byte, root [32]byte) (name string, exact bool) {
	for _, n := range networks {
		if f, r := n.values(); f == forkVersion && r == root {
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

// CheckChain refuses a chain a testnet build must not run on: a public
// network other than the testnet ones, or a chain with a public network's
// fork version or root but not both of a testnet one. nil: a testnet
// network or a devnet.
func CheckChain(forkVersion [4]byte, root [32]byte) error {
	name, exact := PublicNetwork(forkVersion, root)
	if name == "" {
		return nil
	}
	allowed := strings.Join(TestnetNetworks(), ", ")
	for _, n := range networks {
		if n.name != name {
			continue
		}
		switch {
		case n.testnet && exact:
			return nil
		case exact:
			return fmt.Errorf("chain %s (genesis fork version 0x%x, genesis validators root 0x%x): a testnet build runs on devnets and on %s only", name, forkVersion, root, allowed)
		}
		f, r := n.values()
		return fmt.Errorf("chain with genesis fork version 0x%x and genesis validators root 0x%x: %s has fork version 0x%x and root 0x%x; a testnet build runs on devnets, whose values are their own, and on %s with their exact values only",
			forkVersion, root, name, f, r, allowed)
	}
	return nil
}
