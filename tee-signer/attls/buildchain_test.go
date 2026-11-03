package attls

import (
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/runnerchain"
)

// The runner's certificate names the chain of its build the way clients
// read it (governance/runnerchain). Run under each build's tags: go test,
// go test -tags nonprod,chain_<name>.
func TestCertificateNamesTheBuild(t *testing.T) {
	now := time.Now()
	ca := newRoot(t, "client ca", now.Add(-time.Hour), now.Add(time.Hour))
	cfg, _, err := ServerConfig(certPEM(ca.cert), nil)
	if err != nil {
		t.Fatal(err)
	}
	cn := cfg.Certificates[0].Leaf.Subject.CommonName
	if got, ok := runnerchain.FromCertName(cn); !ok || got != runnerchain.Build {
		t.Errorf("certificate name %q reads as %s, this is a %s build", cn, got, runnerchain.Build)
	}
	want := map[runnerchain.Chain]string{runnerchain.Mainnet: "signer-runner", runnerchain.Hoodi: "signer-runner hoodi",
		runnerchain.Devnet: "signer-runner devnet", runnerchain.CITest: "signer-runner ci-test"}[runnerchain.Build]
	if cn != want {
		t.Errorf("certificate name %q, want %q", cn, want)
	}
}
