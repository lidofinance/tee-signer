package handover

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/sealedimport"
)

// testCarry is a carry of a key set of 3 and two exits.
func testCarry() *Carry {
	return &Carry{Set: KeySet{Total: 3, KeysHash: [32]byte{0xaa, 0xbb}}, Exits: &Exits{Day: 20385, Stake: 64_000_000_000, Entries: []Exit{
		{Pubkey: backend.Pubkey{0x81, 7}, ValidatorIndex: 7, ExitEpoch: 900, Stake: 32_000_000_000, Nonce: [32]byte{1}},
		{Pubkey: backend.Pubkey{0x81, 8}, ValidatorIndex: 8, ExitEpoch: 901, Stake: 32_000_000_000, Nonce: [32]byte{2}},
	}}}
}

func TestCarry(t *testing.T) {
	for _, c := range []*Carry{{}, {Set: KeySet{Total: 3}}, testCarry()} {
		enc, err := c.Encode()
		if err != nil {
			t.Fatal(err)
		}
		back, err := DecodeCarry(enc)
		if err != nil {
			t.Fatal(err)
		}
		if again, _ := back.Encode(); !bytes.Equal(again, enc) {
			t.Fatalf("carry does not encode back: %x, %x", again, enc)
		}
	}
	enc, _ := testCarry().Encode()
	back, err := DecodeCarry(enc)
	if err != nil || back.Set != testCarry().Set || back.Exits.Entries[0].Pubkey != testCarry().Exits.Entries[0].Pubkey {
		t.Fatalf("carry back: %+v %v", back, err)
	}
	// The exits flag sits after version, total and keys_hash; the day's
	// stake after the flag and the day.
	const flag = 1 + 4 + 32
	noExits := append([]byte{1}, make([]byte, 4+32)...)
	noExits = append(noExits, 1)
	noExits = append(noExits, make([]byte, 8+8+2)...)
	bad := map[string][]byte{
		"version 0":   append([]byte{0}, enc[1:]...),
		"version 2":   append([]byte{2}, enc[1:]...),
		"flag 2":      func() []byte { b := bytes.Clone(enc); b[flag] = 2; return b }(),
		"trailing":    append(bytes.Clone(enc), 0),
		"short":       enc[:len(enc)-1],
		"no exits":    noExits,
		"stake wrong": func() []byte { b := bytes.Clone(enc); b[flag+1+8+7]++; return b }(),
	}
	for name, b := range bad {
		if _, err := DecodeCarry(b); err == nil {
			t.Errorf("%s decoded", name)
		}
	}
	c := testCarry()
	c.Exits.Stake++
	if _, err := c.Encode(); err == nil {
		t.Fatal("a carry whose exits do not sum to its stake encoded")
	}
}

// A page whose total is not its carry's key set total does not decode:
// the total is the carry's, which every share's associated data binds
// (SHC-01).
func TestResponseTotalIsTheCarrys(t *testing.T) {
	r := &Response{Total: 3, Carry: *testCarry(), Origin: OriginProof{Nonce: []byte("n"),
		Attestation: &backend.Attestation{Platform: "dev", Format: "dev-json", UserData: []byte{1}, Document: []byte("{}")}}}
	enc, err := r.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeResponse(enc); err != nil {
		t.Fatal(err)
	}
	r.Total = 2
	enc, _ = r.Encode()
	if _, err := DecodeResponse(enc); err == nil {
		t.Fatal("a page whose total is not its carry's decoded")
	}
}

// A response seals each share under the header and the carry's hash: the
// share opens only with the carry it came with, and a response whose
// carry was changed opens none.
func TestResponseCarry(t *testing.T) {
	to, _ := sealedimport.Generate()
	id := &backend.Identity{}
	to.Fill(id)
	_, okey, _ := ed25519.GenerateKey(rand.Reader)
	mark := backend.Watermark{HasAttestation: true, SourceEpoch: 5, TargetEpoch: 6}
	c := testCarry()
	c.Set.Total = 1
	r := &Response{Mark: mark, Total: 1, Carry: *c, Origin: OriginProof{Key: [32]byte(okey.Public().(ed25519.PublicKey)), Nonce: []byte("n"),
		Attestation: &backend.Attestation{Platform: "dev", Format: "dev-json", UserData: []byte{1}, Document: []byte("{}")}}}
	ch, err := r.CarryHash()
	if err != nil {
		t.Fatal(err)
	}
	var sec [32]byte
	rand.Read(sec[:])
	s := Share{SealedImportRequest: backend.SealedImportRequest{Pubkey: backend.Pubkey{1}, SharePubkey: backend.Pubkey{2}, Interchange: &mark},
		Origin: OriginImported}
	if s.Sealed, err = sealedimport.SealAAD(id, s.AAD(ch), &sec); err != nil {
		t.Fatal(err)
	}
	s.SignOrigin(okey)
	r.Shares = []Share{s}
	enc, err := r.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeResponse(enc)
	if err != nil {
		t.Fatal(err)
	}
	if back.Carry.Exits.Stake != r.Carry.Exits.Stake || len(back.Carry.Exits.Entries) != 2 {
		t.Fatalf("carry %+v", back.Carry)
	}
	bh, _ := back.CarryHash()
	if got, err := to.OpenAAD(back.Shares[0].Sealed, back.Shares[0].AAD(bh)); err != nil || got != sec {
		t.Fatalf("the share opens not with its carry: %v", err)
	}
	// Changed: one exit less, or another key set.
	c1 := back.Carry
	c1.Exits = &Exits{Day: c1.Exits.Day, Stake: 32_000_000_000, Entries: c1.Exits.Entries[:1]}
	c2 := back.Carry
	c2.Set.KeysHash[0] ^= 1
	for name, c := range map[string]Carry{"exits": c1, "key set": c2} {
		h, _ := c.Hash()
		if _, err := to.OpenAAD(back.Shares[0].Sealed, back.Shares[0].AAD(h)); err == nil {
			t.Fatalf("the share opened under a carry with other %s", name)
		}
	}
	// A response without its carry does not decode.
	enc, _ = r.Encode()
	n := len(enc) - 4 - len(mustEnc(r.Carry.Encode()))
	if _, err := DecodeResponse(enc[:n]); err == nil {
		t.Fatal("a response without a carry decoded")
	}
}

// A carry cut short at any byte is refused, and never panics (SHH-03: the
// day and the stakes were read from a nil slice). The same holds inside an
// IMPORT_HANDOVER request, which the target decodes before any order check.
func TestDecodeCarryEveryTruncation(t *testing.T) {
	enc, err := testCarry().Encode()
	if err != nil {
		t.Fatal(err)
	}
	for n := range len(enc) {
		if _, err := DecodeCarry(enc[:n]); err == nil {
			t.Errorf("a carry of %d of %d bytes decoded", n, len(enc))
		}
	}
	for n := range len(enc) {
		p := []byte{ImportVersion, 0, 0, 0, 0, 0}
		page := responseWithCarryBytes(enc[:n])
		p = binary.BigEndian.AppendUint32(p, uint32(len(page)))
		p = append(p, page...)
		if _, err := DecodeImportRequest(p); err == nil {
			t.Errorf("an import request with a carry of %d of %d bytes decoded", n, len(enc))
		}
	}
}

// responseWithCarryBytes is a HANDOVER response without shares whose
// carry part holds carry as is.
func responseWithCarryBytes(carry []byte) []byte {
	r := &Response{Origin: OriginProof{Nonce: []byte("n"),
		Attestation: &backend.Attestation{Platform: "dev", Format: "dev-json", UserData: []byte{1}, Document: []byte("{}")}}}
	p := mustEnc(r.Encode())
	p = p[:len(p)-4-len(mustEnc(r.Carry.Encode()))]
	p = binary.BigEndian.AppendUint32(p, uint32(len(carry)))
	return append(p, carry...)
}
