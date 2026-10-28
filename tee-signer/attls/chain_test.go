package attls

import (
	"encoding/asn1"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// WithChain puts the genesis fork version into the TLS certificate as an
// OCTET STRING under backend.RunnerChainOID, the form the clients read
// (attest/runnerclient checkChain). Without it there is no such extension.
func TestServerCertificateNamesTheChain(t *testing.T) {
	ca := newRoot(t, "root", now0.Add(-day(1)), now0.Add(day(1)))
	find := func(opts ...Option) (backend.Version, bool) {
		cfg, _, err := ServerConfig(certPEM(ca.cert), nil, opts...)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range cfg.Certificates[0].Leaf.Extensions {
			if !e.Id.Equal(backend.RunnerChainOID) {
				continue
			}
			if e.Critical {
				t.Fatal("the chain mark is critical; old clients would refuse the runner")
			}
			var b []byte
			if rest, err := asn1.Unmarshal(e.Value, &b); err != nil || len(rest) != 0 || len(b) != 4 {
				t.Fatalf("chain mark %x: %v", e.Value, err)
			}
			return backend.Version(b), true
		}
		return backend.Version{}, false
	}
	if _, ok := find(); ok {
		t.Fatal("a chain mark without WithChain")
	}
	want := backend.Version{0x10, 0, 0, 0x38}
	if got, ok := find(WithChain(want)); !ok || got != want {
		t.Fatalf("chain mark %x (%v), want %x", got, ok, want)
	}
}
