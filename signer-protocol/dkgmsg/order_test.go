package dkgmsg

import (
	"bytes"
	"strings"
	"testing"
)

func TestOrderStateRoundTrip(t *testing.T) {
	s := &OrderState{Outcome: OrderKnown, Status: OrderVoid, Hash: [32]byte{1, 2}, Position: 2, Arrived: 10, ActAt: 20,
		NotAfter: 30, Why: "dkg order: the signature of approver 0 does not verify"}
	got, err := DecodeOrderState(s.Encode())
	if err != nil || *got != *s {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	long := *s
	long.Why = strings.Repeat("x", MaxOrderWhy+10)
	if got, err := DecodeOrderState(long.Encode()); err != nil || len(got.Why) != MaxOrderWhy {
		t.Fatalf("a long reason is cut to %d: %v", MaxOrderWhy, err)
	}
	for name, b := range map[string][]byte{
		"trailing":     append(s.Encode(), 0),
		"short":        s.Encode()[:OrderStateLen-1],
		"outcome 0":    append([]byte{0}, s.Encode()[1:]...),
		"status 5":     append([]byte{OrderKnown, 5}, s.Encode()[2:]...),
		"reason > max": append(append(s.Encode()[:OrderStateLen-2], 0x02, 0x01), bytes.Repeat([]byte{'x'}, 513)...),
	} {
		if _, err := DecodeOrderState(b); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
}

func TestInOrderEnvelope(t *testing.T) {
	m := &InOrder{Order: [32]byte{7}, Type: TypeCommit, Payload: []byte{1, 2, 3}}
	b, err := m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeInOrder(b)
	if err != nil || got.Order != m.Order || got.Type != m.Type || !bytes.Equal(got.Payload, m.Payload) {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	for _, typ := range []byte{byte(TypeOperator), byte(TypeOrder), byte(TypeInOrder), 0x01} {
		if _, err := DecodeInOrder(append(make([]byte, 32), typ)); err == nil {
			t.Errorf("type %#02x travels in an envelope", typ)
		}
	}
	if _, err := DecodeInOrder(make([]byte, 32)); err == nil {
		t.Error("a short envelope decoded")
	}
}
