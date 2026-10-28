package markstore

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

// A record with the day's exits reads back with them; without exits the
// record has only the presence byte of the exits field.
func TestRecordExits(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	r := Record{Signer: "signer-1", Version: 2, PrevVersion: 1, LogID: [32]byte{1}, KeyBlob: []byte{1},
		Exits: &ExitDay{Day: 20000, Stake: 3, Exits: []ExitEntry{{ValidatorIndex: 5, ExitEpoch: 7, Stake: 1, Nonce: [32]byte{1}},
			{ValidatorIndex: 6, ExitEpoch: 7, Stake: 2, Nonce: [32]byte{2}}}}}
	enc := r.Sign(key)
	back, err := Parse(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !exitsEqual(back.Exits, r.Exits) {
		t.Fatalf("exits %+v", back.Exits)
	}
	plain := r
	plain.Exits = nil
	if p := plain.Sign(key); len(enc)-len(p) != 8+8+2+2*(48+3*8+32) {
		t.Fatalf("a record without exits is %d bytes, with two %d", len(p), len(enc))
	}
	bad := r
	bad.Exits = &ExitDay{Day: 1, Stake: 5, Exits: []ExitEntry{{Stake: 1}}}
	if _, err := Parse(bad.Sign(key)); err == nil {
		t.Fatal("exits whose stake is not their sum parsed")
	}
}
