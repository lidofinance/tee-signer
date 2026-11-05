package runnerchain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

func fork(t *testing.T, s string) (f [4]byte) {
	t.Helper()
	if _, err := hex.Decode(f[:], []byte(s)); err != nil {
		t.Fatal(err)
	}
	return f
}

// on is a chain with these genesis values and mainnet's slot times.
func on(f [4]byte, r [32]byte) *setupwire.Chain {
	return &setupwire.Chain{GenesisForkVersion: f, GenesisValidatorsRoot: r, GenesisTime: setupwire.MainnetGenesisTime,
		SecondsPerSlot: setupwire.MainnetSecondsPerSlot, SlotsPerEpoch: setupwire.MainnetSlotsPerEpoch, Preset: setupwire.PresetMainnet}
}

func root(t *testing.T, s string) (r [32]byte) {
	t.Helper()
	if _, err := hex.Decode(r[:], []byte(s)); err != nil {
		t.Fatal(err)
	}
	return r
}

// The networks as the sources give them, written out again here so a typo
// in the table shows.
var (
	public = map[string][2]string{
		"mainnet": {"00000000", "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"},
		"gnosis":  {"00000064", "f5dcb5564e829aab27264b9becd5dfaa017085611224cb3036f573368dbb9d47"},
		"holesky": {"01017000", "9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1"},
		"lukso":   {"42000001", "a27edd68cde5c396f499157945d062a010308ce5ed5719a6b1e12ad2a51b97e6"},
		"hoodi":   {"10000910", "212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f"},
		"sepolia": {"90000069", "d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078"},
		"chiado":  {"0000006f", "9d642dac73058fbf39c0ae41ab1e34e4d889043cb199851ded7095bc99eb4c1e"},
	}
	ciTestFork      = [4]byte{0, 0, 0, 1}
	ciTestRootBytes = sha256.Sum256([]byte("tee-signer dev chain"))
	otherRoot       = sha256.Sum256([]byte("a devnet's own genesis"))
	otherFork       = [4]byte{0x10, 0x00, 0x00, 0x38} // ethereum-package's default
)

func TestTableMatchesSources(t *testing.T) {
	for name, want := range public {
		f, r, ok := setupwire.PublicNetworkValues(name)
		if !ok || f != fork(t, want[0]) || r != root(t, want[1]) {
			t.Errorf("%s: %x %x %v, want %v", name, f, r, ok, want)
		}
		if n, exact := PublicNetwork(fork(t, want[0]), root(t, want[1])); n != name || !exact {
			t.Errorf("%s: PublicNetwork %q %v", name, n, exact)
		}
	}
	ci, ok := setupwire.ChainRowByName(string(CITest))
	if !ok || ci.ForkVersion != ciTestFork || ciTestRoot != hex.EncodeToString(ciTestRootBytes[:]) {
		t.Errorf("ci-test row %+v, root %s", ci, ciTestRoot)
	}
}

// The mainnet build runs on mainnet with its exact values only. It
// refuses the other public networks, devnets, and a non-prod row's fork
// version with mainnet's root.
func TestMainnetOwnChainOnly(t *testing.T) {
	mf, mr := fork(t, public["mainnet"][0]), root(t, public["mainnet"][1])
	if err := Mainnet.CheckChain(on(mf, mr)); err != nil {
		t.Fatalf("mainnet: %v", err)
	}
	for name, v := range public {
		if name == "mainnet" {
			continue
		}
		if err := Mainnet.CheckChain(on(fork(t, v[0]), root(t, v[1]))); err == nil || !strings.Contains(err.Error(), "a mainnet build runs on mainnet") {
			t.Errorf("%s: %v", name, err)
		}
	}
	for what, v := range map[string]values{
		"devnet": {otherFork, otherRoot}, "ci-test": {ciTestFork, ciTestRootBytes},
		"hoodi fork version, mainnet root":   {fork(t, public["hoodi"][0]), mr},
		"ci-test fork version, mainnet root": {ciTestFork, mr},
		"devnet fork version, mainnet root":  {otherFork, mr},
		"mainnet fork version, other root":   {mf, otherRoot},
	} {
		if err := Mainnet.CheckChain(on(v.f, v.r)); err == nil {
			t.Errorf("%s: accepted", what)
		}
	}
}

// The mainnet build takes mainnet's genesis time, seconds per slot and
// slots per epoch only, and names the field and mainnet's value.
func TestMainnetTimesOnly(t *testing.T) {
	for _, c := range []struct {
		field string
		set   func(*setupwire.Chain)
	}{
		{"genesis_time 1606824024: mainnet's is 1606824023", func(c *setupwire.Chain) { c.GenesisTime++ }},
		{"seconds_per_slot 6: mainnet's is 12", func(c *setupwire.Chain) { c.SecondsPerSlot = 6 }},
		{"slots_per_epoch 8: mainnet's is 32", func(c *setupwire.Chain) { c.SlotsPerEpoch = 8 }},
		{"preset minimal: mainnet's is mainnet", func(c *setupwire.Chain) { c.Preset = setupwire.PresetMinimal }},
	} {
		ch := on(fork(t, public["mainnet"][0]), root(t, public["mainnet"][1]))
		c.set(ch)
		if err := Mainnet.CheckChain(ch); err == nil || !strings.Contains(err.Error(), c.field) {
			t.Errorf("%s: %v", c.field, err)
		}
	}
}

// The mainnet times in code are those of governance/chains/mainnet.json.
func TestMainnetTimesMatchChainFile(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "chains", "mainnet.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		GenesisTime    uint64 `json:"genesis_time"`
		SecondsPerSlot uint64 `json:"seconds_per_slot"`
		SlotsPerEpoch  uint64 `json:"slots_per_epoch"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if f.GenesisTime != setupwire.MainnetGenesisTime || f.SecondsPerSlot != setupwire.MainnetSecondsPerSlot || f.SlotsPerEpoch != setupwire.MainnetSlotsPerEpoch {
		t.Errorf("mainnet.json %+v", f)
	}
}

type values struct {
	f [4]byte
	r [32]byte
}

// Each non-prod build starts on its own chain and refuses every other:
// the public networks (mainnet first), the other builds' chains, and a
// public network's fork version or root with other values.
func TestNonProdBuildsOwnChainOnly(t *testing.T) {
	devnet := values{otherFork, otherRoot}
	ci := values{ciTestFork, ciTestRootBytes}
	hoodi := values{fork(t, public["hoodi"][0]), root(t, public["hoodi"][1])}
	own := map[Chain][]values{Hoodi: {hoodi}, CITest: {ci}, Devnet: {devnet}}
	for c, oks := range own {
		for _, v := range oks {
			if err := c.CheckChain(on(v.f, v.r)); err != nil {
				t.Errorf("%s build on its own chain %x/%x: %v", c, v.f, v.r[:4], err)
			}
		}
		for name, pv := range public {
			if c == Hoodi && name == "hoodi" {
				continue
			}
			err := c.CheckChain(on(fork(t, pv[0]), root(t, pv[1])))
			if err == nil || !strings.Contains(err.Error(), "chain "+name+" ") || !strings.Contains(err.Error(), "a "+string(c)+" build runs on") {
				t.Errorf("%s build on %s: %v", c, name, err)
			}
			// Its fork version with another root, and its root with
			// another fork version. A fork version without a row (or
			// a prod row) is refused as a prod chain, whatever the root.
			for what, v := range map[string]values{"its fork version": {fork(t, pv[0]), otherRoot}, "its root": {otherFork, root(t, pv[1])}} {
				want := name + " has fork version"
				if what == "its fork version" && name != "hoodi" {
					want = "a prod chain"
				}
				if err := c.CheckChain(on(v.f, v.r)); err == nil || !strings.Contains(err.Error(), want) {
					t.Errorf("%s build, %s with %s only: %v, want %q", c, name, what, err, want)
				}
			}
		}
		// The other builds' chains.
		for other, ovs := range own {
			if other == c {
				continue
			}
			for _, v := range ovs {
				if err := c.CheckChain(on(v.f, v.r)); err == nil {
					t.Errorf("%s build accepted the chain of the %s build (%x/%x)", c, other, v.f, v.r[:4])
				}
			}
		}
	}
	if err := Chain("testnet").CheckChain(on(otherFork, otherRoot)); err == nil {
		t.Error("an unknown build accepted a devnet")
	}
}

// Fail closed: a fork version no row names is prod. Every non-prod build
// refuses it, the devnet build too: a devnet with a fork version of its
// own, or the minimal preset's 0x00000001 with another root than the
// ci-test chain's, is not taken as a devnet.
func TestNonProdRefusesUnknownChains(t *testing.T) {
	for _, v := range []values{{[4]byte{0xde, 0xad, 0xbe, 0xef}, otherRoot}, {[4]byte{0x10, 0, 0, 0x39}, otherRoot}, {ciTestFork, otherRoot}} {
		for _, c := range []Chain{Hoodi, Devnet, CITest} {
			if err := c.CheckChain(on(v.f, v.r)); err == nil {
				t.Errorf("%s build accepted fork version %x root %x", c, v.f, v.r[:4])
			}
		}
	}
	// The devnet build on its own devnet: ethereum-package's fork version,
	// a root of its own.
	if err := Devnet.CheckChain(on(otherFork, otherRoot)); err != nil {
		t.Errorf("devnet build on a Kurtosis devnet: %v", err)
	}
}

// A non-prod build refuses every chain whose row in the chain table is
// prod, by its fork version, whatever the root: mainnet's real root, a
// devnet's, none.
func TestNonProdRefusesProdChains(t *testing.T) {
	var prod int
	for _, r := range setupwire.ChainRows() {
		if !r.Prod {
			continue
		}
		prod++
		for _, c := range Chains {
			if c.Prod() {
				continue
			}
			for _, rt := range [][32]byte{root(t, public["mainnet"][1]), otherRoot, {}} {
				err := c.CheckChain(on([4]byte(r.ForkVersion), rt))
				if err == nil || !strings.Contains(err.Error(), "chain "+r.Name+" (") || !strings.Contains(err.Error(), "a prod chain") {
					t.Errorf("%s build on prod chain %s, root %x: %v", c, r.Name, rt[:4], err)
				}
			}
		}
	}
	if prod == 0 {
		t.Fatal("no prod row")
	}
}

// Every chain of a build has a row, and the prod property is the row's.
func TestChainsAreRows(t *testing.T) {
	if len(Chains) != len(setupwire.ChainRows()) || Chains[0] != Mainnet {
		t.Fatalf("Chains %v", Chains)
	}
	for _, c := range Chains {
		r, ok := setupwire.ChainRowByName(string(c))
		if !ok || r.Prod != c.Prod() {
			t.Errorf("%s: row %+v %v, Prod %v", c, r, ok, c.Prod())
		}
	}
	if !Mainnet.Prod() || Hoodi.Prod() || Devnet.Prod() || CITest.Prod() {
		t.Error("only mainnet is prod")
	}
	if !Chain("testnet").Prod() {
		t.Error("a chain without a row is not prod")
	}
}
