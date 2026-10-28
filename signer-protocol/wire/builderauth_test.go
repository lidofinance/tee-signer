package wire

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// SIGN of kind 14: pubkey, kind, the caller's domain, then the SSZ of the
// BuilderRequestAuth (offset 12, slot, data).
func TestBuilderRequestAuthSign(t *testing.T) {
	pk := backend.Pubkey{1, 2}
	domain := backend.Root{0x0b, 0, 0, 1, 0xaa}
	for _, n := range []int{0, 19, backend.MaxBuilderRequestAuthData} {
		m := &backend.BuilderRequestAuth{Data: bytes.Repeat([]byte{0x5a}, n), Slot: 32}
		p, err := EncodeSign(backend.SignRequest{Pubkey: pk, Message: m, Domain: domain})
		if err != nil {
			t.Fatal(err)
		}
		if p[48] != 14 || len(p) != 48+1+32+12+n || p[81] != 12 {
			t.Fatalf("%d data bytes: layout %x", n, p[:90])
		}
		got, err := DecodeSign(p)
		if err != nil || got.Domain != domain || !reflect.DeepEqual(got.Message, m) {
			t.Fatalf("%d data bytes: %+v %v", n, got, err)
		}
	}
	p, _ := EncodeSign(backend.SignRequest{Pubkey: pk, Message: &backend.BuilderRequestAuth{Data: make([]byte, 4096)}, Domain: domain})
	if _, err := DecodeSign(append(p, 0)); err == nil {
		t.Fatal("4097 data bytes accepted")
	}
}
