package markstore

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/lidofinance/tee-signer/devkit/fuzzcheck"
	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// The host stores the mark records and can hand back any bytes; Parse
// reads them before the signature is checked. Oracles: no panic, bounded
// allocation, and what parses encodes back to the same bytes.
func FuzzParse(f *testing.F) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	r := Record{Signer: "signer-1", Version: 2, PrevVersion: 1, LogID: [32]byte{1}, KeyBlob: []byte{1}}
	f.Add(r.Sign(key))
	// An SMARK1 record (the SMARK3 body without the share set's presence
	// byte and the config history) and an SMARK2 one (without the
	// history), which must parse and encode back as they are.
	b := r.encodeBody()
	v1 := append([]byte(recordMagicV1), b[len(recordMagic):len(b)-8]...)
	f.Add(append(v1, ed25519.Sign(key, signedMessage(v1))...))
	v2 := append([]byte(recordMagicV2), b[len(recordMagic):len(b)-7]...)
	f.Add(append(v2, ed25519.Sign(key, signedMessage(v2))...))
	r.State.RemovedAt, r.State.ApproversAt, r.State.Carried = 1_800_000_000, 1_800_000_000, [][32]byte{{1}, {2}}
	r.State.Locked.Version, r.State.Paths[0] = 1, setupwire.PathBreakGlass
	f.Add(r.Sign(key))
	f.Fuzz(func(t *testing.T, b []byte) {
		fuzzcheck.Watch(t)
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
