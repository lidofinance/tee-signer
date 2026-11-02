package statestore

import "testing"

// SHO-01: the sealed body of a source's handover order is in the copy. A
// source whose local store is lost (Azure and GCP restarts) gets it back,
// and does not read its own pending order as an import.
func TestSHO01HandoverOrderInTheCopy(t *testing.T) {
	const k = "handover/orders/0123"
	if !Durable(k) {
		t.Fatalf("%s is not durable", k)
	}
	l := newMemLog()
	s, err := open(t, newMemLocal(), l, keysOf("image-a"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(k, []byte("sealed order")); err != nil {
		t.Fatal(err)
	}
	fresh := newMemLocal()
	if _, err := open(t, fresh, l, keysOf("image-a"), Options{}); err != nil {
		t.Fatal(err)
	}
	if v, err := fresh.Get(k); err != nil || string(v) != "sealed order" {
		t.Fatalf("restored %q %v", v, err)
	}
}
