package attls

import (
	"bytes"
	"encoding/asn1"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// WithChain puts the genesis fork version and the genesis validators root
// into the TLS certificate as an OCTET STRING of 36 bytes under
// backend.RunnerChainOID, the form the clients read
// (attestation-verify/runnerclient checkChain). Without it there is no
// such extension.
func TestServerCertificateNamesTheChain(t *testing.T) {
	ca := newRoot(t, "root", now0.Add(-day(1)), now0.Add(day(1)))
	find := func(opts ...Option) ([]byte, bool) {
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
			if rest, err := asn1.Unmarshal(e.Value, &b); err != nil || len(rest) != 0 || len(b) != 36 {
				t.Fatalf("chain mark %x: %v", e.Value, err)
			}
			return b, true
		}
		return nil, false
	}
	if _, ok := find(); ok {
		t.Fatal("a chain mark without WithChain")
	}
	gfv, gvr := backend.Version{0x10, 0, 0, 0x38}, backend.Root{0xaa, 31: 0xbb}
	got, ok := find(WithChain(gfv, gvr))
	if !ok || !bytes.Equal(got[:4], gfv[:]) || !bytes.Equal(got[4:], gvr[:]) {
		t.Fatalf("chain mark %x (%v), want %x then %x", got, ok, gfv, gvr)
	}
}
