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

// The chain table: mainnet is the one prod chain.
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
	if !ProdChain(MainnetForkVersion) {
		t.Error("a setup of mainnet is not prod")
	}
	for name, v := range map[string]backend.Version{"hoodi": {0x10, 0, 0x09, 0x10}, "ci-test": {0, 0, 0, 1}, "devnet": {0x10, 0, 0, 0x38}} {
		r, ok := ChainRowOf(v)
		if !ok || r.Name != name || ProdChain(v) {
			t.Errorf("fork version %x: row %+v %v, prod %v; want %s, not prod", v, r, ok, ProdChain(v), name)
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

// Fail closed: a fork version no row names is prod, so a setup of an
// unknown chain gets the strict checks. Sepolia, Gnosis and a devnet with
// a fork version of its own are such chains.
func TestUnknownChainIsProd(t *testing.T) {
	for _, v := range []backend.Version{{0x90, 0, 0, 0x69}, {0, 0, 0, 0x64}, {0xde, 0xad, 0xbe, 0xef}, {0x10, 0, 0, 0x39}} {
		if _, ok := ChainRowOf(v); ok {
			t.Errorf("fork version %x has a row", v)
		}
		if !ProdChain(v) {
			t.Errorf("fork version %x: not prod", v)
		}
		if err := CheckThreshold(v, 2, 3); err == nil {
			t.Errorf("fork version %x: 2 of 3 passes the threshold rule, want the prod rule", v)
		}
		if err := CheckThreshold(v, 3, 4); err != nil {
			t.Errorf("fork version %x: 3 of 4: %v", v, err)
		}
	}
}

// A missing row can only make things stricter: drop each row in turn, and
// no fork version becomes non-prod that was prod.
func TestMissingRowIsStricter(t *testing.T) {
	saved := chainTable
	t.Cleanup(func() { chainTable = saved })
	probe := []backend.Version{{0xde, 0xad, 0xbe, 0xef}}
	for _, r := range saved {
		probe = append(probe, r.ForkVersion)
	}
	before := map[backend.Version]bool{}
	for _, v := range probe {
		before[v] = ProdChain(v)
	}
	for i, r := range saved {
		chainTable = append(append([]ChainRow(nil), saved[:i]...), saved[i+1:]...)
		for _, v := range probe {
			if before[v] && !ProdChain(v) {
				t.Errorf("without the %s row, fork version %x is no longer prod", r.Name, v)
			}
		}
		if !ProdChain(r.ForkVersion) {
			t.Errorf("without the %s row, its fork version is not prod", r.Name)
		}
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
			GenesisForkVersion string `json:"genesis_fork_version"`
		}
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatal(err)
		}
		if got := strings.TrimPrefix(c.GenesisForkVersion, "0x"); got != hex.EncodeToString(r.ForkVersion[:]) {
			t.Errorf("%s: %s has fork version %s, row %x", r.Name, file, got, r.ForkVersion)
		}
	}
}
