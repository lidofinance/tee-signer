package flavor

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func fork(t *testing.T, s string) (f [4]byte) {
	t.Helper()
	if _, err := hex.Decode(f[:], []byte(s)); err != nil {
		t.Fatal(err)
	}
	return f
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
	allowed = map[string][2]string{
		"hoodi":   {"10000910", "212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f"},
		"sepolia": {"90000069", "d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078"},
		"chiado":  {"0000006f", "9d642dac73058fbf39c0ae41ab1e34e4d889043cb199851ded7095bc99eb4c1e"},
	}
	refused = map[string][2]string{
		"mainnet": {"00000000", "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"},
		"gnosis":  {"00000064", "f5dcb5564e829aab27264b9becd5dfaa017085611224cb3036f573368dbb9d47"},
		"holesky": {"01017000", "9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1"},
		"lukso":   {"42000001", "a27edd68cde5c396f499157945d062a010308ce5ed5719a6b1e12ad2a51b97e6"},
	}
	otherRoot = sha256.Sum256([]byte("a devnet's own genesis"))
	otherFork = [4]byte{0x10, 0x00, 0x00, 0x38} // ethereum-package's default
)

func TestTableMatchesSources(t *testing.T) {
	if len(networks) != len(allowed)+len(refused) {
		t.Fatalf("%d networks, want %d", len(networks), len(allowed)+len(refused))
	}
	for _, n := range networks {
		want, ok := allowed[n.name]
		if !ok {
			want, ok = refused[n.name]
		}
		if !ok || n.fork != want[0] || n.root != want[1] || n.testnet != (allowed[n.name] != [2]string{}) {
			t.Errorf("%s: %+v, want %v", n.name, n, want)
		}
		n.values() // panics on bad hex
	}
	if got := strings.Join(TestnetNetworks(), ","); got != "hoodi,sepolia,chiado" {
		t.Errorf("TestnetNetworks %s", got)
	}
}

func TestAllowedNetworks(t *testing.T) {
	for name, v := range allowed {
		f, r := fork(t, v[0]), root(t, v[1])
		if err := CheckChain(f, r); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if n, exact := PublicNetwork(f, r); n != name || !exact {
			t.Errorf("%s: PublicNetwork %s %v", name, n, exact)
		}
		// Its fork version with another root, and its root with another
		// fork version.
		for what, c := range map[string][2]any{"another root": {f, otherRoot}, "another fork version": {otherFork, r}} {
			err := CheckChain(c[0].([4]byte), c[1].([32]byte))
			if err == nil || !strings.Contains(err.Error(), name+" has fork version") {
				t.Errorf("%s with %s: %v", name, what, err)
			}
		}
	}
}

func TestRefusedNetworks(t *testing.T) {
	for name, v := range refused {
		f, r := fork(t, v[0]), root(t, v[1])
		err := CheckChain(f, r)
		if err == nil || !strings.Contains(err.Error(), "chain "+name+" ") || !strings.Contains(err.Error(), "hoodi, sepolia, chiado") {
			t.Errorf("%s: %v", name, err)
		}
		for what, c := range map[string][2]any{"its fork version": {f, otherRoot}, "its root": {otherFork, r}} {
			if err := CheckChain(c[0].([4]byte), c[1].([32]byte)); err == nil || !strings.Contains(err.Error(), name) {
				t.Errorf("%s, %s only: %v", name, what, err)
			}
		}
	}
}

func TestDevnets(t *testing.T) {
	devnets := map[string][2]any{
		// A Kurtosis devnet: ethereum-package's fork version, its own root.
		"kurtosis": {otherFork, otherRoot},
		// software.DevConfig, the chain of the runner's own tests.
		"software.DevConfig": {[4]byte{0, 0, 0, 1}, sha256.Sum256([]byte("tee-signer dev chain"))},
		// The minimal preset's fork version.
		"minimal": {[4]byte{0, 0, 0, 1}, otherRoot},
	}
	for name, c := range devnets {
		f, r := c[0].([4]byte), c[1].([32]byte)
		if err := CheckChain(f, r); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if n, _ := PublicNetwork(f, r); n != "" {
			t.Errorf("%s: PublicNetwork %s", name, n)
		}
	}
}
