package markstore

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/lidofinance/tee-signer/devkit/fuzzcheck"
)

// The host stores the mark records and can hand back any bytes; Parse
// reads them before the signature is checked. Oracles: no panic, bounded
// allocation, and what parses encodes back to the same bytes.
func FuzzParse(f *testing.F) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	r := Record{Signer: "signer-1", Version: 2, PrevVersion: 1, LogID: [32]byte{1}, KeyBlob: []byte{1},
		Exits: &ExitDay{Day: 20000, Stake: 3, Exits: []ExitEntry{{ValidatorIndex: 5, ExitEpoch: 7, Stake: 1, Nonce: [32]byte{1}},
			{ValidatorIndex: 6, ExitEpoch: 7, Stake: 2, Nonce: [32]byte{2}}}}}
	f.Add(r.Sign(key))
	r.Exits = nil
	f.Add(r.Sign(key))
	// An SMARK1 record: the SMARK2 body without the share set's presence
	// byte, which must parse and encode back as SMARK1.
	b := r.encodeBody()
	v1 := append([]byte(recordMagicV1), b[len(recordMagic):len(b)-1]...)
	f.Add(append(v1, ed25519.Sign(key, signedMessage(v1))...))
	f.Fuzz(func(t *testing.T, b []byte) {
		var r *Record
		var err error
		fuzzcheck.Bounded(t, len(b), func() { r, err = Parse(b) })
		if err != nil {
			return
		}
		again := append(r.encodeBody(), r.Sig[:]...)
		if !bytes.Equal(again, b) {
			t.Fatalf("record does not encode back:\n%x\n%x", again, b)
		}
	})
}
