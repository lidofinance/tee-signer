package backend

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

// KeygenOrdersHash is over the distinct order hashes in ascending order,
// whatever order and repeats it gets, and zero without an order.
func TestKeygenOrdersHash(t *testing.T) {
	if KeygenOrdersHash(nil) != (Root{}) {
		t.Fatal("no order: want 32 zero bytes")
	}
	a, b := [32]byte{0x01}, [32]byte{0x02}
	want := func(orders ...[32]byte) Root {
		in := binary.BigEndian.AppendUint16(nil, uint16(len(KeygenOrdersContext)))
		in = append(in, KeygenOrdersContext...)
		in = binary.BigEndian.AppendUint32(in, uint32(len(orders)))
		for _, o := range orders {
			in = append(in, o[:]...)
		}
		return Root(sha256.Sum256(in))
	}
	if got := KeygenOrdersHash([][32]byte{a}); got != want(a) {
		t.Fatalf("one order: %x", got)
	}
	in := [][32]byte{b, a, b, a}
	if got := KeygenOrdersHash(in); got != want(a, b) {
		t.Fatalf("two orders with repeats: %x, want %x", got, want(a, b))
	}
	if in[0] != b || in[1] != a {
		t.Fatal("KeygenOrdersHash changed its argument")
	}
}
