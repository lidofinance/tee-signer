package setuptext

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

const (
	eth  = 1_000_000_000
	maxU = math.MaxUint64
)

// wireTestdata holds the golden setups and updates in binary form.
// setupwire's TestGolden makes them from its samples, so the fixtures here
// are those samples.
const wireTestdata = "../setupwire/testdata"

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

func must32(k [32]byte) []byte { return k[:] }

func readFile(t testing.TB, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// goldens decodes every golden file of a kind ("setup" or "update") by
// name, afresh for each call, so a test may change what it gets.
func goldens[T any](t testing.TB, kind string, decode func([]byte) (T, error)) map[string]T {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(wireTestdata, kind+"-*.bin"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no golden %s files in %s: %v", kind, wireTestdata, err)
	}
	out := map[string]T{}
	for _, p := range paths {
		v, err := decode(readFile(t, p))
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		out[strings.TrimSuffix(filepath.Base(p), ".bin")] = v
	}
	return out
}

// setups are setupwire's sample setups: setup-nitro, setup-azure,
// setup-gcp, setup-dev and setup-nitro-peers.
func setups(t testing.TB) map[string]*setupwire.Setup {
	return goldens(t, "setup", setupwire.DecodeSetup)
}

// updates are setupwire's signed sample updates of setup-nitro:
// update-locked, update-open and update-rotation.
func updates(t testing.TB) map[string]*setupwire.Update {
	return goldens(t, "update", setupwire.DecodeUpdate)
}

// approverPub is the key of test approver i, as in setupwire's tests.
func approverPub(i byte) [32]byte {
	return [32]byte(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{i}, 32)).Public().(ed25519.PublicKey))
}

// makeCA makes a self-signed certificate (a copy of setupwire's test
// helper). isCA false makes a leaf.
func makeCA(t testing.TB, seed byte, cn string, isCA bool) []byte {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(int64(seed)),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Unix(1_700_000_000, 0),
		NotAfter:     time.Unix(2_000_000_000, 0),
		IsCA:         isCA, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if isCA {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
