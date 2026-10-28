package attls

import (
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/flavor"
)

// The runner's certificate names the build flavour the way clients read it
// (backend/flavor). Run under both tags: go test, go test -tags testnet.
func TestCertificateNamesTheFlavor(t *testing.T) {
	now := time.Now()
	ca := newRoot(t, "client ca", now.Add(-time.Hour), now.Add(time.Hour))
	cfg, _, err := ServerConfig(certPEM(ca.cert), nil)
	if err != nil {
		t.Fatal(err)
	}
	cn := cfg.Certificates[0].Leaf.Subject.CommonName
	if got := flavor.FromCertName(cn); got != flavor.Build {
		t.Errorf("certificate name %q reads as %s, this is a %s build", cn, got, flavor.Build)
	}
	want := map[flavor.Flavor]string{flavor.Default: flavor.DefaultCertName, flavor.Testnet: flavor.TestnetCertName}[flavor.Build]
	if cn != want {
		t.Errorf("certificate name %q, want %q", cn, want)
	}
}
