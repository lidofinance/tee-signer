package server

import (
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/handoverorder"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	"github.com/lidofinance/tee-signer/tee-signer/handover"
)

// A runner without the source side on (no setup, or a debug build) hands
// over to no one: HANDOVER_ORDER
// and HANDOVER are UNSUPPORTED (handover.go).
func TestHandoverNotBuiltIn(t *testing.T) {
	s := shareServer(t, &shareStore{m: map[string][]byte{}}, [32]byte{1}, [32]byte{2})
	for _, typ := range []wire.MsgType{handoverorder.TypeOrder, handover.Type} {
		_, err := s.dispatch(ctx, wire.Frame{Type: typ, Payload: []byte{1}})
		if err == nil || !strings.Contains(err.Error(), "hands over to no one") {
			t.Fatalf("%v: %v", typ, err)
		}
	}
}

// A runner without the import on (a build without key generation, or no
// setup) takes no handed-over share.
func TestHandoverImportNotOn(t *testing.T) {
	s := shareServer(t, &shareStore{m: map[string][]byte{}}, [32]byte{1}, [32]byte{2})
	_, err := s.dispatch(ctx, wire.Frame{Type: handover.TypeImport, Payload: []byte{1}})
	if err == nil || !strings.Contains(err.Error(), "takes no handed-over shares") {
		t.Fatal(err)
	}
}
