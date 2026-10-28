package handover

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"reflect"
	"testing"

	"github.com/lidofinance/tee-signer/devkit/fuzzcheck"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/sealedimport"
)

// Fuzz targets for the handover decoders. Every byte they read comes from
// a client or another runner. The oracles (fuzzcheck): no panic, an
// allocation bounded by the input, and what decodes encodes back to the
// same bytes. One exception, as in wire/admin: a share header whose
// interchange flags are 0 drops the 24 bytes of maxima whatever they
// hold, so there only the value round trip holds. That is safe: the AAD
// and the origin signature are checked over the re-encoded header, so
// such a share does not open. testdata/fuzz holds the inputs that once
// failed (SHH-03, and that header).

// seedPage is a page of two shares and a carry whose key set has the
// page's total, sealed to a fresh key. The keys hash is testCarry's: no
// decoder checks it against the shares.
func seedPage(t testing.TB) *Response {
	carry := testCarry()
	carry.Set.Total = 2
	key, _ := sealedimport.Generate()
	id := &backend.Identity{}
	key.Fill(id)
	_, okey, _ := ed25519.GenerateKey(rand.Reader)
	mark := backend.Watermark{HasAttestation: true, SourceEpoch: 9, TargetEpoch: 10}
	r := &Response{Mark: mark, Total: 2, Carry: *carry,
		Origin: OriginProof{Key: [32]byte(okey.Public().(ed25519.PublicKey)), Nonce: []byte("n"),
			Attestation: &backend.Attestation{Platform: "dev", Format: "dev-json", UserData: []byte{1}, Document: []byte("{}")}}}
	ch, err := r.CarryHash()
	if err != nil {
		t.Fatal(err)
	}
	for i, origin := range []uint8{OriginGenerated, OriginImported} {
		var sec [32]byte
		rand.Read(sec[:])
		s := Share{SealedImportRequest: backend.SealedImportRequest{Pubkey: backend.Pubkey{byte(i + 1)}, SharePubkey: backend.Pubkey{byte(i + 3)},
			Index: uint64(70 + i), Interchange: &mark}, Origin: origin}
		if origin == OriginGenerated {
			s.Order = [32]byte{0xd0}
		}
		if s.Sealed, err = sealedimport.SealAAD(id, s.AAD(ch), &sec); err != nil {
			t.Fatal(err)
		}
		s.SignOrigin(okey)
		r.Shares = append(r.Shares, s)
	}
	return r
}

func mustEnc(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

// sameBytes fails t unless enc (the encoding of what b decoded to) is b.
func sameBytes(t *testing.T, what string, enc []byte, err error, b []byte) {
	t.Helper()
	if err != nil {
		t.Fatalf("decoded %s does not encode: %v", what, err)
	}
	if !bytes.Equal(enc, b) {
		t.Fatalf("%s does not encode back:\n%x\n%x", what, enc, b)
	}
}

func FuzzDecodeCarry(f *testing.F) {
	for _, c := range []*Carry{{}, testCarry()} {
		f.Add(mustEnc(c.Encode()))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		var c *Carry
		var err error
		fuzzcheck.Bounded(t, len(b), func() { c, err = DecodeCarry(b) })
		if err != nil {
			return
		}
		enc, err := c.Encode()
		sameBytes(t, "carry", enc, err, b)
	})
}

func FuzzDecodeImportRequest(f *testing.F) {
	page := seedPage(f)
	f.Add(mustEnc((&ImportRequest{Flags: ImportAsImported, Order: []byte{'T', 1, 2}, Page: page}).Encode()))
	page.Carry.Exits = nil
	f.Add(mustEnc((&ImportRequest{Order: []byte{'T'}, Page: page}).Encode()))
	f.Fuzz(func(t *testing.T, b []byte) {
		var q *ImportRequest
		var err error
		fuzzcheck.Bounded(t, len(b), func() { q, err = DecodeImportRequest(b) })
		if err != nil {
			return
		}
		enc, err := q.Encode()
		sameValue(t, "import request", q, q.Page.Shares, enc, err, b, DecodeImportRequest)
	})
}

func FuzzDecodeImportResponse(f *testing.F) {
	f.Add(mustEnc((&ImportResponse{Outcomes: []uint8{Stored, Held}, Held: 5, Total: 9, Generated: 2, Imported: 3}).Encode()))
	f.Add(mustEnc((&ImportResponse{Done: true}).Encode()))
	f.Fuzz(func(t *testing.T, b []byte) {
		var r *ImportResponse
		var err error
		fuzzcheck.Bounded(t, len(b), func() { r, err = DecodeImportResponse(b) })
		if err != nil {
			return
		}
		enc, err := r.Encode()
		sameBytes(t, "import response", enc, err, b)
	})
}

func FuzzDecodeRequest(f *testing.F) {
	f.Add(mustEnc((&Request{Nonce: []byte("nonce-0123456789"), Identity: []byte{3, 1, 2}, Policy: []byte{1, 9}, Order: []byte{'T', 1}, Start: 512}).Encode()))
	f.Fuzz(func(t *testing.T, b []byte) {
		var q *Request
		var err error
		fuzzcheck.Bounded(t, len(b), func() { q, err = DecodeRequest(b) })
		if err != nil {
			return
		}
		enc, err := q.Encode()
		sameBytes(t, "request", enc, err, b)
	})
}

func FuzzDecodeResponse(f *testing.F) {
	page := seedPage(f)
	f.Add(mustEnc(page.Encode()))
	page.Carry.Exits = nil
	f.Add(mustEnc(page.Encode()))
	f.Fuzz(func(t *testing.T, b []byte) {
		var r *Response
		var err error
		fuzzcheck.Bounded(t, len(b), func() { r, err = DecodeResponse(b) })
		if err != nil {
			return
		}
		enc, err := r.Encode()
		sameValue(t, "response", r, r.Shares, enc, err, b, DecodeResponse)
	})
}

func FuzzDecodeShare(f *testing.F) {
	for _, s := range seedPage(f).Shares {
		f.Add(mustEnc(s.Encode()))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		var s *Share
		var err error
		fuzzcheck.Bounded(t, len(b), func() { s, err = DecodeShare(b) })
		if err != nil {
			return
		}
		enc, err := s.Encode()
		sameValue(t, "share", s, []Share{*s}, enc, err, b, DecodeShare)
	})
}

// sameValue fails t unless enc is b, or b has a share without maxima and
// enc decodes to the value b decoded to (v).
func sameValue[T any](t *testing.T, what string, v T, shares []Share, enc []byte, err error, b []byte, decode func([]byte) (T, error)) {
	t.Helper()
	if err != nil {
		t.Fatalf("decoded %s does not encode: %v", what, err)
	}
	if bytes.Equal(enc, b) {
		return
	}
	noMaxima := false
	for i := range shares {
		noMaxima = noMaxima || shares[i].Interchange == nil
	}
	back, derr := decode(enc)
	if !noMaxima || derr != nil || !reflect.DeepEqual(back, v) {
		t.Fatalf("%s does not encode back (%v):\n%x\n%x", what, derr, enc, b)
	}
}

// TestSeedPageDecodes keeps the seeds useful: a seed that does not decode
// would only feed the fuzz targets' error path.
func TestSeedPageDecodes(t *testing.T) {
	r, err := DecodeResponse(mustEnc(seedPage(t).Encode()))
	if err != nil {
		t.Fatal(err)
	}
	if r.Carry.Set.Total != r.Total || r.Carry.Exits == nil {
		t.Fatalf("seed page's carry has not the page's total: %+v", r.Carry)
	}
	if _, err := DecodeImportRequest(mustEnc((&ImportRequest{Order: []byte{'T'}, Page: seedPage(t)}).Encode())); err != nil {
		t.Fatalf("import request seed: %v", err)
	}
}
