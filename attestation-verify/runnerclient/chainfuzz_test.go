package runnerclient

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// FuzzRunnerChain feeds the value of the chain mark of a runner's
// certificate, which the client reads in the handshake, before the
// identity check: no panic, and a value read as a chain is an OCTET
// STRING of exactly 4 bytes that encodes back to the same bytes.
func FuzzRunnerChain(f *testing.F) {
	for _, v := range [][]byte{{0x04, 0x04, 0, 0, 0, 0}, {0x04, 0x04, 0x10, 0, 0, 0x38}, {0x04, 0x03, 1, 2, 3}, {0x04, 0x04, 1, 2, 3, 4, 0}, {0x04, 0x84, 0xff, 0xff, 0xff, 0xff}, {}} {
		f.Add(v)
	}
	f.Fuzz(func(t *testing.T, v []byte) {
		c := &x509.Certificate{Extensions: []pkix.Extension{{Id: backend.RunnerChainOID, Value: v}}}
		gfv, ok, err := runnerChain(c)
		if err != nil {
			if ok {
				t.Fatal("ok with an error")
			}
			return
		}
		if !ok {
			t.Fatal("a certificate with the mark read as one without")
		}
		back, err := asn1.Marshal(gfv[:])
		if err != nil || !bytes.Equal(back, v) {
			t.Fatalf("value %x read as %x, which encodes as %x", v, gfv, back)
		}
	})
}
