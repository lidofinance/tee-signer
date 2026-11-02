package markstore

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
)

// The exits block of an image with exit approvals keeps its presence byte,
// always 0 here; a record whose byte says the block is there is refused.
func TestRecordExitsBlockRefused(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	r := Record{Signer: "signer-1", Version: 2, PrevVersion: 1, LogID: [32]byte{1}, KeyBlob: []byte{1}}
	body := r.encodeBody()
	// The body ends with the presence bytes of the exits block, the
	// source gate and the share set.
	if !bytes.Equal(body[len(body)-3:], []byte{0, 0, 0}) {
		t.Fatalf("the last presence bytes are %x, want 000000", body[len(body)-3:])
	}
	if _, err := Parse(r.Sign(key)); err != nil {
		t.Fatal(err)
	}
	for _, b := range []byte{1, 2} {
		bad := bytes.Clone(body)
		bad[len(bad)-3] = b
		enc := append(bad, ed25519.Sign(key, signedMessage(bad))...)
		if _, err := Parse(enc); !errors.Is(err, errRecord) {
			t.Errorf("exits presence byte %d: %v", b, err)
		}
	}
}
