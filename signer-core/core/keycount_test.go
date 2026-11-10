package core_test

import (
	"testing"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
)

// KeyCount counts the loaded validators without copying the list: one
// after the first key, two after the next, and a refused duplicate adds
// none.
func TestKeyCount(t *testing.T) {
	hooks := &software.MemHooks{}
	s, pk, _ := newTestSigner(t, hooks)
	if n := s.KeyCount(); n != 1 {
		t.Fatalf("KeyCount %d after one key, want 1", n)
	}
	sk, _ := software.NewSecret()
	pk2, _ := core.PubkeyOf(sk)
	if _, err := addAtGenesis(hooks, s, pk2, sk, 8, nil); err != nil {
		t.Fatal(err)
	}
	if n := s.KeyCount(); n != 2 {
		t.Fatalf("KeyCount %d after two keys, want 2", n)
	}
	if _, err := addAtGenesis(hooks, s, pk, sk, 9, nil); err == nil {
		t.Fatal("a share loaded twice was accepted")
	}
	if n := s.KeyCount(); n != 2 {
		t.Fatalf("KeyCount %d after a refused add, want 2", n)
	}
}
