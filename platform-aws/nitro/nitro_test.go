package nitro

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// A synthetic document in the documented shape: COSE_Sign1 array with a
// CBOR map payload. Real NSM output was not available.
func TestParseDocumentSynthetic(t *testing.T) {
	payload, err := cbor.Marshal(map[string]any{
		"module_id": "i-0123-enc0123",
		"digest":    "SHA384",
		"timestamp": uint64(1791806400123),
		"pcrs":      map[int][]byte{0: make([]byte, 48), 1: make([]byte, 48)},
		"nonce":     []byte("n0nce"),
		"user_data": []byte("ud"),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tagged := range []bool{false, true} {
		var v any = []any{[]byte{0xa1, 0x01, 0x38, 0x22}, map[any]any{}, payload, make([]byte, 96)}
		if tagged {
			v = cbor.Tag{Number: 18, Content: v}
		}
		doc, err := cbor.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		p, err := ParseDocument(doc)
		if err != nil {
			t.Fatalf("tagged=%v: %v", tagged, err)
		}
		if p.Timestamp != 1791806400123 || string(p.Nonce) != "n0nce" || len(p.PCRs[1]) != 48 || p.ModuleID != "i-0123-enc0123" {
			t.Fatalf("%+v", p)
		}
	}
}

func TestParseRoutes(t *testing.T) {
	r, err := ParseRoutes("kms.eu-west-1.amazonaws.com:443=vsock:3:8000, time.example:443=vsock:3:8001")
	if err != nil {
		t.Fatal(err)
	}
	if a := r["kms.eu-west-1.amazonaws.com:443"]; a.Network != "vsock" || a.CID != 3 || a.Port != 8000 {
		t.Fatalf("%+v", a)
	}
	if len(r) != 2 {
		t.Fatal(r)
	}
	if _, err := ParseRoutes("nohost"); err == nil {
		t.Fatal("bad route accepted")
	}
}
