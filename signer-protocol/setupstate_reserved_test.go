package backend

import "testing"

// The setup state keeps the layout of the builds that counted keys made in
// key generation: the bytes around imported_keys are reserved and zero, and
// only order kinds 0 and 1 exist. ParseSetupState refuses anything else, so
// a state with such keys or with a key generation order (kind 2) never
// reads as a state without them.
func TestSetupStateRefusesReserved(t *testing.T) {
	st := SetupState{SetupHash: Root{1}, KeyOrigin: KeyOrigin{Imported: 5},
		Order: Order{Kind: 1, Hash: Root{2}, ActAt: 3}}
	enc := AppendSetupState(nil, &st)
	if got, err := ParseSetupState(enc); err != nil || got != st {
		t.Fatalf("round trip: %+v, %v", got, err)
	}
	const (
		reserved1 = SetupStateLen - 40 // 4 bytes before imported_keys
		reserved2 = SetupStateLen - 32 // 32 bytes after it
		orderKind = 32 + 2*(8+32+8+32+8) + 32
	)
	for name, off := range map[string]int{"first reserved byte": reserved1, "last of the first four": reserved1 + 3,
		"after imported_keys": reserved2, "last byte": SetupStateLen - 1} {
		b := append([]byte(nil), enc...)
		b[off] = 1
		if _, err := ParseSetupState(b); err == nil {
			t.Errorf("%s set: parsed", name)
		}
	}
	for _, kind := range []byte{2, 3, 0xff} {
		b := append([]byte(nil), enc...)
		b[orderKind] = kind
		if _, err := ParseSetupState(b); err == nil {
			t.Errorf("order kind %d: parsed", kind)
		}
	}
	if enc[orderKind] != 1 {
		t.Fatal("the order kind offset is wrong")
	}
}
