package setupwire

import (
	"encoding/hex"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// A chain is a public network when its genesis fork version and its
// genesis validators root are both the network's. The chain table
// (chains.go) uses the roots: a row with no root of its own (devnet)
// never matches a public network's root. governance/runnerchain uses the
// table to refuse public networks to non-prod builds.
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

// network is a chain by its genesis values, in hex. Strings keep the table
// static data, with nothing to run at package init.
type network struct {
	name string
	fork string
	root string
}

func (n network) values() (fork backend.Version, root backend.Root) {
	if _, err := hex.Decode(fork[:], []byte(n.fork)); err != nil {
		panic("setupwire: bad fork version of " + n.name)
	}
	if _, err := hex.Decode(root[:], []byte(n.root)); err != nil {
		panic("setupwire: bad root of " + n.name)
	}
	return fork, root
}

// PublicNetwork names the public network with these genesis values, or
// "" when neither value is a public network's. exact is true when both
// values are the network's.
func PublicNetwork(forkVersion backend.Version, root backend.Root) (name string, exact bool) {
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

// PublicNetworkValues gives the genesis values of the public network
// called name.
func PublicNetworkValues(name string) (forkVersion backend.Version, root backend.Root, ok bool) {
	for _, n := range networks {
		if n.name == name {
			f, r := n.values()
			return f, r, true
		}
	}
	return forkVersion, root, false
}

// publicRoot says whether root is a public network's genesis validators
// root.
func publicRoot(root backend.Root) bool {
	for _, n := range networks {
		if _, r := n.values(); r == root {
			return true
		}
	}
	return false
}
