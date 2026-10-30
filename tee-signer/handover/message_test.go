package handover

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/sealedimport"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

func TestRequest(t *testing.T) {
	q := &Request{Nonce: []byte("nonce-0123456789"), Identity: []byte{3, 1, 2}, Policy: []byte{1, 9}, Order: []byte{'T', 1}, Start: 512}
	enc, err := q.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeRequest(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back.Nonce, q.Nonce) || !bytes.Equal(back.Identity, q.Identity) || !bytes.Equal(back.Policy, q.Policy) ||
		!bytes.Equal(back.Order, q.Order) || back.Start != 512 {
		t.Fatalf("%+v", back)
	}
	for name, b := range map[string][]byte{
		"version 0": append([]byte{0}, enc[1:]...),
		"version 2": append([]byte{2}, enc[1:]...),
		"trailing":  append(bytes.Clone(enc), 0),
		"short":     enc[:len(enc)-1],
		"huge part": append(enc[:3+len(q.Nonce)], 0xff, 0xff, 0xff, 0xff),
	} {
		if _, err := DecodeRequest(b); err == nil {
			t.Errorf("%s decoded", name)
		}
	}
	if _, err := (&Request{Nonce: make([]byte, wire.MaxNonce+1)}).Encode(); err == nil {
		t.Fatal("a long nonce encoded")
	}
}

// testCarryHash stands in for the hash of a page's carry.
var testCarryHash = [32]byte{0xca}

// share is a sealed handed-over share of a fresh key, with the mark and
// the origin in its header, under testCarryHash.
func share(t *testing.T, to *sealedimport.Key, mark backend.Watermark, okey ed25519.PrivateKey) (*Share, [32]byte) {
	t.Helper()
	var sec [32]byte
	rand.Read(sec[:])
	pk := backend.Pubkey{1, 2}
	rand.Read(pk[2:]) // a page names each validator once
	s := &Share{SealedImportRequest: backend.SealedImportRequest{Pubkey: pk, SharePubkey: backend.Pubkey{3, 4},
		Index: 77, Interchange: &mark}, Origin: OriginImported}
	id := &backend.Identity{}
	to.Fill(id)
	var err error
	if s.Sealed, err = sealedimport.SealAAD(id, s.AAD(testCarryHash), &sec); err != nil {
		t.Fatal(err)
	}
	s.SignOrigin(okey)
	return s, sec
}

// The header binds the mark and the origin twice: in the HPKE associated
// data and under the origin signature. A share does not open as a plain
// sealed import, and the plain form does not open as a handed-over share.
func TestShare(t *testing.T) {
	to, err := sealedimport.Generate()
	if err != nil {
		t.Fatal(err)
	}
	_, okey, _ := ed25519.GenerateKey(rand.Reader)
	opub := [32]byte(okey.Public().(ed25519.PublicKey))
	mark := backend.Watermark{HasAttestation: true, SourceEpoch: 10, TargetEpoch: 11, HasBlock: true, BlockSlot: 400}
	s, sec := share(t, to, mark, okey)
	enc, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeShare(enc)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := back.Encode(); !bytes.Equal(again, enc) {
		t.Fatal("share does not round-trip")
	}
	if err := back.VerifyOrigin(opub); err != nil {
		t.Fatal(err)
	}
	got, err := to.OpenAAD(back.Sealed, back.AAD(testCarryHash))
	if err != nil || got != sec {
		t.Fatalf("open: %v", err)
	}
	if _, err := to.Open(&back.SealedImportRequest); err == nil {
		t.Fatal("a handed-over share opened as a plain sealed import")
	}
	// Another origin, another mark: the AAD and the signature both break.
	o2 := *back
	o2.Origin = 2
	low := *back
	m := mark
	m.TargetEpoch--
	low.Interchange = &m
	for name, x := range map[string]*Share{"origin": &o2, "mark": &low} {
		if _, err := to.OpenAAD(x.Sealed, x.AAD(testCarryHash)); err == nil {
			t.Fatalf("a share opened with another %s", name)
		}
		if err := x.VerifyOrigin(opub); err == nil {
			t.Fatalf("the origin signature verified with another %s", name)
		}
	}
	// A seal of the plain import header does not open as a handed-over
	// share.
	plain := *back
	if plain.Sealed, err = sealedimport.Seal(func() *backend.Identity { id := &backend.Identity{}; to.Fill(id); return id }(),
		&plain.SealedImportRequest, &sec); err != nil {
		t.Fatal(err)
	}
	if _, err := to.OpenAAD(plain.Sealed, plain.AAD(testCarryHash)); err == nil {
		t.Fatal("a plain sealed import opened as a handed-over share")
	}
	// Origin rules: only origin 1. Origin 2 was a key made in key
	// generation in earlier builds, with its order's hash in the reserved
	// bytes; such a share does not decode.
	for _, o := range []uint8{0, 2, 3} {
		bad := *back
		bad.Origin = o
		if _, err := bad.Encode(); err == nil || !strings.Contains(err.Error(), "want 1 (imported)") {
			t.Errorf("origin %d encoded: %v", o, err)
		}
	}
	at := func(set map[int]byte) []byte {
		b := bytes.Clone(enc)
		for i, v := range set {
			b[i] = v
		}
		return b
	}
	h := wireadmin.SealedHeaderLen
	for name, b := range map[string][]byte{
		"short":                    enc[:len(enc)-1],
		"trailing":                 append(bytes.Clone(enc), 0),
		"origin 0":                 at(map[int]byte{h: 0}),
		"origin 2":                 at(map[int]byte{h: 2}),
		"origin 2 with order hash": at(map[int]byte{h: 2, h + 1: 0xd, h + 32: 0xd}),
		"first reserved byte":      at(map[int]byte{h + 1: 1}),
		"last reserved byte":       at(map[int]byte{h + 32: 1}),
	} {
		if _, err := DecodeShare(b); err == nil {
			t.Errorf("share %s decoded", name)
		}
	}
}

func TestResponse(t *testing.T) {
	to, _ := sealedimport.Generate()
	_, okey, _ := ed25519.GenerateKey(rand.Reader)
	mark := backend.Watermark{HasAttestation: true, SourceEpoch: 5, TargetEpoch: 6}
	r := &Response{Mark: mark, Total: 3, Carry: Carry{Set: KeySet{Total: 3}}, Origin: OriginProof{Key: [32]byte(okey.Public().(ed25519.PublicKey)), Nonce: []byte("n"),
		Attestation: &backend.Attestation{Platform: "dev", Format: "dev-json", UserData: []byte{1}, Document: []byte("{}")}}}
	for i := range 3 {
		s, _ := share(t, to, mark, okey)
		s.Pubkey[0] = byte(i)
		s.SignOrigin(okey)
		r.Shares = append(r.Shares, *s)
	}
	enc, err := r.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeResponse(enc)
	if err != nil {
		t.Fatal(err)
	}
	if back.Total != 3 || len(back.Shares) != 3 || back.Mark != mark || back.Origin.Key != r.Origin.Key ||
		!bytes.Equal(back.Origin.Attestation.UserData, []byte{1}) || back.Shares[2].Pubkey[0] != 2 {
		t.Fatalf("%+v", back)
	}
	// A share with another mark than the page's is refused.
	m2 := mark
	m2.SourceEpoch++
	s, _ := share(t, to, m2, okey)
	r.Shares = append(r.Shares, *s)
	enc, _ = r.Encode()
	if _, err := DecodeResponse(enc); err == nil || !strings.Contains(err.Error(), "handed-over mark") {
		t.Fatalf("another mark: %v", err)
	}
	for _, v := range []byte{0, 2} {
		if _, err := DecodeResponse(append([]byte{v}, enc[1:]...)); err == nil {
			t.Fatalf("a response of version %d decoded", v)
		}
	}
	ud := OriginUserData([32]byte{1}, r.Origin.Key)
	if bytes.Equal(ud, OriginUserData([32]byte{2}, r.Origin.Key)) || len(ud) != 32 {
		t.Fatal("origin user data does not bind the order")
	}
}
