package setupwire

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/buildchain"
)

var (
	hoodiFork   = backend.Version{0x10, 0, 0x09, 0x10}
	devnetFork  = backend.Version{0x10, 0, 0, 0x38}
	ciTestFork  = backend.Version{0, 0, 0, 1}
	hoodiRoot   = hexRoot("212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f")
	mainnetRoot = hexRoot("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95")
	ciTestRoot  = hexRoot("535276eb9690335cc5e4cb926858a79ece25caaf930a7dfad44757c8b7bef420")
	devnetRoot  = backend.Root{0xde, 0x7e, 31: 0x01} // a devnet's own root
)

func hexRoot(s string) (r backend.Root) {
	if n, err := hex.Decode(r[:], []byte(s)); err != nil || n != len(r) {
		panic(s)
	}
	return r
}

// The chain table: mainnet is the one prod chain. Each non-prod row is
// non-prod only with its own genesis values: hoodi with Hoodi's root,
// devnet and ci-test with a root that is no public network's.
func TestChainTableProd(t *testing.T) {
	m, ok := ChainRowByName("mainnet")
	if !ok || !m.Prod || m.ForkVersion != MainnetForkVersion {
		t.Fatalf("mainnet row %+v %v, want prod with fork version 0x00000000", m, ok)
	}
	for _, r := range ChainRows() {
		if r.Prod != (r.Name == "mainnet") {
			t.Errorf("%s: prod %v", r.Name, r.Prod)
		}
	}
	for _, rt := range []backend.Root{mainnetRoot, devnetRoot, {}} {
		if !ProdChain(MainnetForkVersion, rt) {
			t.Errorf("mainnet fork version, root %x: not prod", rt[:4])
		}
	}
	for _, c := range []struct {
		name string
		fv   backend.Version
		root backend.Root
	}{
		{"hoodi", hoodiFork, hoodiRoot},
		{"devnet", devnetFork, devnetRoot},
		{"ci-test", ciTestFork, ciTestRoot},
		{"ci-test", ciTestFork, devnetRoot},
	} {
		r, ok := ChainRowOf(c.fv, c.root)
		if !ok || r.Name != c.name || ProdChain(c.fv, c.root) {
			t.Errorf("%x/%x: row %+v %v, prod %v; want %s, not prod", c.fv, c.root[:4], r, ok, ProdChain(c.fv, c.root), c.name)
		}
	}
	// No two rows name one fork version.
	seen := map[backend.Version]string{}
	for _, r := range ChainRows() {
		if o, dup := seen[r.ForkVersion]; dup {
			t.Errorf("%s and %s have fork version %x", r.Name, o, r.ForkVersion)
		}
		seen[r.ForkVersion] = r.Name
	}
}

// A non-prod row's fork version with mainnet's root signs mainnet
// messages: signing domains come from the fork schedule and the root, not
// from the genesis fork version. Such a setup is prod, and so is any
// other partial match of a non-prod row: its fork version with another
// public network's root, or Hoodi's fork version with a root not Hoodi's.
func TestPartialMatchIsProd(t *testing.T) {
	var public []backend.Root
	for _, n := range networks {
		_, r := n.values()
		public = append(public, r)
	}
	for _, r := range ChainRows() {
		if r.Prod {
			continue
		}
		for _, root := range public {
			if r.Name == "hoodi" && root == hoodiRoot {
				continue
			}
			if !ProdChain(r.ForkVersion, root) {
				t.Errorf("%s fork version %x with public root %x: not prod", r.Name, r.ForkVersion, root[:4])
			}
			if err := CheckThreshold(r.ForkVersion, root, 2, 3); err == nil {
				t.Errorf("%s fork version with public root %x: 2 of 3 passes the threshold rule", r.Name, root[:4])
			}
			s := samples(t)["setup-gcp"]
			s.Chain.GenesisForkVersion, s.Chain.GenesisValidatorsRoot = r.ForkVersion, root
			if err := CheckThresholdOn(s, 2, 3); err == nil {
				t.Errorf("%s fork version with public root %x: 2 of 3 passes the threshold rule of the setup", r.Name, root[:4])
			}
			k := &s.Platform.SealingKeyRelease
			k.UnsafeSingleKeyAccepted, k.NoLockAccepted = true, false
			if CheckSingleKeyProd(&s.Platform, &s.Chain) == nil || !s.Chain.Prod() {
				t.Errorf("%s fork version with public root %x: the single-key rule passes", r.Name, root[:4])
			}
		}
	}
	if !ProdChain(hoodiFork, devnetRoot) {
		t.Error("hoodi fork version with a devnet's root: not prod")
	}
}

// A fork version no non-prod row has is prod whatever the root; a
// non-prod row's fork version needs the root to tell.
func TestProdForkVersion(t *testing.T) {
	for _, v := range []backend.Version{MainnetForkVersion, {0x90, 0, 0, 0x69}, {0xde, 0xad, 0xbe, 0xef}} {
		if !ProdForkVersion(v) {
			t.Errorf("fork version %x: not prod", v)
		}
	}
	for _, r := range ChainRows() {
		if ProdForkVersion(r.ForkVersion) != r.Prod {
			t.Errorf("%s fork version %x: prod %v", r.Name, r.ForkVersion, !r.Prod)
		}
	}
}

// Fail closed: genesis values no row matches are prod, so a setup of an
// unknown chain gets the strict checks. Sepolia, Gnosis and a devnet with
// a fork version of its own are such chains.
func TestUnknownChainIsProd(t *testing.T) {
	for _, v := range []backend.Version{{0x90, 0, 0, 0x69}, {0, 0, 0, 0x64}, {0xde, 0xad, 0xbe, 0xef}, {0x10, 0, 0, 0x39}} {
		for _, rt := range []backend.Root{devnetRoot, mainnetRoot, hoodiRoot} {
			if _, ok := ChainRowOf(v, rt); ok {
				t.Errorf("fork version %x root %x has a row", v, rt[:4])
			}
			if !ProdChain(v, rt) {
				t.Errorf("fork version %x root %x: not prod", v, rt[:4])
			}
			if err := CheckThreshold(v, rt, 2, 3); err == nil {
				t.Errorf("fork version %x: 2 of 3 passes the threshold rule, want the prod rule", v)
			}
			if err := CheckThreshold(v, rt, 3, 4); err != nil {
				t.Errorf("fork version %x: 3 of 4: %v", v, err)
			}
		}
	}
}

// A missing row can only make things stricter: drop each row in turn, and
// no chain becomes non-prod that was prod.
func TestMissingRowIsStricter(t *testing.T) {
	saved := chainTable
	t.Cleanup(func() { chainTable = saved })
	type values struct {
		fv backend.Version
		rt backend.Root
	}
	probe := []values{{backend.Version{0xde, 0xad, 0xbe, 0xef}, devnetRoot}}
	for _, r := range saved {
		for _, rt := range []backend.Root{devnetRoot, mainnetRoot, hoodiRoot, ciTestRoot} {
			probe = append(probe, values{r.ForkVersion, rt})
		}
	}
	before := map[values]bool{}
	for _, v := range probe {
		before[v] = ProdChain(v.fv, v.rt)
	}
	for i, r := range saved {
		chainTable = append(append([]ChainRow(nil), saved[:i]...), saved[i+1:]...)
		for _, v := range probe {
			if before[v] && !ProdChain(v.fv, v.rt) {
				t.Errorf("without the %s row, %x/%x is no longer prod", r.Name, v.fv, v.rt[:4])
			}
		}
		if !ProdChain(r.ForkVersion, devnetRoot) {
			t.Errorf("without the %s row, its fork version is not prod", r.Name)
		}
	}
}

// The public networks table: each network is found by its exact values.
func TestPublicNetworks(t *testing.T) {
	for _, n := range networks {
		f, r := n.values()
		if name, exact := PublicNetwork(f, r); name != n.name || !exact {
			t.Errorf("%s: %q %v", n.name, name, exact)
		}
		if !publicRoot(r) {
			t.Errorf("%s: root not public", n.name)
		}
	}
	if name, _ := PublicNetwork(devnetFork, devnetRoot); name != "" || publicRoot(devnetRoot) {
		t.Errorf("a devnet's values name %q", name)
	}
}

// This build's constants agree with its chain's row: the prod build is
// the one with the long waits.
func TestBuildChainRow(t *testing.T) {
	r, ok := ChainRowByName(buildchain.Name)
	if !ok {
		t.Fatalf("no row for the build's chain %q", buildchain.Name)
	}
	if r.Prod != buildchain.Prod {
		t.Errorf("%s: row prod %v, build Prod %v", r.Name, r.Prod, buildchain.Prod)
	}
	if long := DefaultTimeLock == buildchain.MainnetTimeLock; long != r.Prod {
		t.Errorf("%s: prod %v with a default time lock of %d s", r.Name, r.Prod, DefaultTimeLock)
	}
}

// shellList reads NAME="a b c" from scripts/common.sh.
func shellList(t *testing.T, src []byte, name string) []string {
	t.Helper()
	m := regexp.MustCompile(`(?m)^` + name + `="([^"]*)"$`).FindSubmatch(src)
	if m == nil {
		t.Fatalf("scripts/common.sh has no %s=", name)
	}
	return strings.Fields(string(m[1]))
}

// The chains of the build switch (scripts/common.sh CHAINS and
// PROD_CHAINS) are the rows of the table, and each chain but devnet has
// its chain file with the row's fork version. devnet takes CHAIN_JSON.
func TestChainTableMatchesBuildSwitch(t *testing.T) {
	root := filepath.Join("..", "..")
	src, err := os.ReadFile(filepath.Join(root, "scripts", "common.sh"))
	if err != nil {
		t.Fatal(err)
	}
	var names, prod []string
	for _, r := range ChainRows() {
		names = append(names, r.Name)
		if r.Prod {
			prod = append(prod, r.Name)
		}
	}
	chains, prodChains := shellList(t, src, "CHAINS"), shellList(t, src, "PROD_CHAINS")
	if !slices.Equal(chains, names) {
		t.Errorf("CHAINS %v, chain table %v", chains, names)
	}
	if !slices.Equal(prodChains, prod) {
		t.Errorf("PROD_CHAINS %v, prod rows %v", prodChains, prod)
	}
	for _, r := range ChainRows() {
		var file string
		switch r.Name {
		case "devnet":
			// No file: a devnet's genesis is its own (CHAIN_JSON). Its row
			// names ethereum-package's genesis fork version, which
			// governance/chains/chain.sh identify takes as a devnet.
			if r.ForkVersion != (backend.Version{0x10, 0, 0, 0x38}) {
				t.Errorf("devnet row: fork version %x", r.ForkVersion)
			}
			continue
		case "ci-test":
			file = "chain.ci-test.json"
		default:
			file = r.Name + ".json"
		}
		raw, err := os.ReadFile(filepath.Join(root, "governance", "chains", file))
		if err != nil {
			t.Errorf("%s: %v", r.Name, err)
			continue
		}
		var c struct {
			GenesisForkVersion    string `json:"genesis_fork_version"`
			GenesisValidatorsRoot string `json:"genesis_validators_root"`
		}
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatal(err)
		}
		if got := strings.TrimPrefix(c.GenesisForkVersion, "0x"); got != hex.EncodeToString(r.ForkVersion[:]) {
			t.Errorf("%s: %s has fork version %s, row %x", r.Name, file, got, r.ForkVersion)
		}
		if got := strings.TrimPrefix(c.GenesisValidatorsRoot, "0x"); r.Root != "" && got != r.Root {
			t.Errorf("%s: %s has root %s, row %s", r.Name, file, got, r.Root)
		}
	}
}
