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

func TestImportRequest(t *testing.T) {
	key, _ := sealedimport.Generate()
	_, okey, _ := ed25519.GenerateKey(rand.Reader)
	mark := backend.Watermark{HasAttestation: true, SourceEpoch: 9, TargetEpoch: 10}
	s1, _ := share(t, key, mark, okey)
	s2, _ := share(t, key, mark, okey)
	page := &Response{Mark: mark, Total: 2, Carry: Carry{Set: KeySet{Total: 2}}, Shares: []Share{*s1, *s2},
		Origin: OriginProof{Key: [32]byte(okey.Public().(ed25519.PublicKey)), Nonce: []byte("n"),
			Attestation: &backend.Attestation{Platform: "dev", Format: "dev-json", UserData: []byte{1}, Document: []byte("{}")}}}
	q := &ImportRequest{Flags: ImportAsImported, Order: []byte{'T', 1, 2}, Page: page}
	enc, err := q.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeImportRequest(enc)
	if err != nil {
		t.Fatal(err)
	}
	if back.Flags != ImportAsImported || !bytes.Equal(back.Order, q.Order) || len(back.Page.Shares) != 2 || back.Page.Mark != mark ||
		back.Page.Shares[0].Origin != OriginImported || back.Page.Shares[1].Origin != OriginImported {
		t.Fatalf("%+v", back)
	}
	for name, b := range map[string][]byte{
		"version 0":     append([]byte{0}, enc[1:]...),
		"version 2":     append([]byte{2}, enc[1:]...),
		"unknown flags": append([]byte{1, 2}, enc[2:]...),
		"trailing":      append(bytes.Clone(enc), 0),
		"short":         enc[:len(enc)-1],
		"huge order":    append([]byte{1, 0}, 0xff, 0xff, 0xff, 0xff),
	} {
		if _, err := DecodeImportRequest(b); err == nil {
			t.Errorf("%s decoded", name)
		}
	}
	// A page that names one validator twice does not decode (APSTATE-02).
	twice := *page
	twice.Shares = []Share{*s1, *s1}
	if enc, err := (&ImportRequest{Order: []byte{'T'}, Page: &twice}).Encode(); err != nil {
		t.Fatal(err)
	} else if _, err := DecodeImportRequest(enc); err == nil {
		t.Fatal("a page with one validator twice decoded")
	}
	// A share whose header names another mark than the page's does not
	// decode (DecodeResponse).
	other := mark
	other.TargetEpoch++
	s3, _ := share(t, key, other, okey)
	bad := *page
	bad.Shares = []Share{*s3}
	if enc, err := (&ImportRequest{Order: []byte{'T'}, Page: &bad}).Encode(); err != nil {
		t.Fatal(err)
	} else if _, err := DecodeImportRequest(enc); err == nil {
		t.Fatal("a share with another mark decoded")
	}
	if _, err := (&ImportRequest{Flags: 4, Order: []byte{'T'}, Page: page}).Encode(); err == nil {
		t.Fatal("unknown flags encoded")
	}
}

func TestImportResponse(t *testing.T) {
	r := &ImportResponse{Outcomes: []uint8{Stored, Held, Stored}, Held: 7, Total: 9, Done: false, Imported: 1}
	enc, err := r.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeImportResponse(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back.Outcomes, r.Outcomes) || back.Held != 7 || back.Total != 9 || back.Done || back.Imported != 1 {
		t.Fatalf("%+v", back)
	}
	r.Done = true
	enc, _ = r.Encode()
	if back, err := DecodeImportResponse(enc); err != nil || !back.Done {
		t.Fatalf("%+v %v", back, err)
	}
	badOutcome := bytes.Clone(enc)
	badOutcome[3] = 3
	badDone := bytes.Clone(enc)
	badDone[3+3+8] = 2
	// The four bytes before the imported count are reserved: earlier
	// builds counted keys made in key generation there.
	if !bytes.Equal(enc[len(enc)-8:len(enc)-4], make([]byte, 4)) {
		t.Fatal("the reserved count is not zero")
	}
	badReserved := bytes.Clone(enc)
	badReserved[len(enc)-5] = 6
	tooMany := binary.BigEndian.AppendUint16([]byte{1}, MaxPerResponse+1)
	for name, b := range map[string][]byte{
		"version 2":   append([]byte{2}, enc[1:]...),
		"outcome 3":   badOutcome,
		"done 2":      badDone,
		"reserved 6":  badReserved,
		"trailing":    append(bytes.Clone(enc), 0),
		"short":       enc[:len(enc)-1],
		"257 answers": tooMany,
	} {
		if _, err := DecodeImportResponse(b); err == nil {
			t.Errorf("%s decoded", name)
		}
	}
}
