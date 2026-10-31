package statestore

import (
	"context"
	"testing"

	"github.com/lidofinance/tee-signer/slashing-log"
)

// A name planted at the last version must not move the next commit: it
// would wrap to version 0, which no restore reads.
func TestPlantedLastVersionNameIsIgnored(t *testing.T) {
	l, _ := markstore.NewFileLog(t.TempDir())
	s, err := open(t, newLocal(t), l, keysOf("image-a"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put("shares/aa", []byte("share a")); err != nil {
		t.Fatal(err)
	}
	if err := l.Create(context.Background(), Name(setupA, "signer-1", ^uint64(0)), []byte("junk")); err != nil {
		t.Fatal(err)
	}
	s2, err := open(t, newLocal(t), l, keysOf("image-a"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.Put("shares/bb", []byte("share b")); err != nil {
		t.Fatalf("put b: %v", err)
	}
	if s2.head == 0 || s2.head == ^uint64(0) {
		t.Fatalf("commit went to version %d", s2.head)
	}
	fresh := newLocal(t)
	if _, err := open(t, fresh, l, keysOf("image-a"), Options{}); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"shares/aa", "shares/bb"} {
		if _, err := fresh.Get(k); err != nil {
			t.Fatalf("%s missing after restore: %v", k, err)
		}
	}
}

// At the last version a commit is refused, not written at version 0.
func TestCommitRefusedAtLastVersion(t *testing.T) {
	l, _ := markstore.NewFileLog(t.TempDir())
	s, err := open(t, newLocal(t), l, keysOf("image-a"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	s.version = ^uint64(0)
	if err := s.Put("shares/aa", []byte("share a")); err == nil {
		t.Fatal("commit after the last version was accepted")
	}
	es, err := l.List(context.Background(), Name(setupA, "signer-1", 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(es) != 0 {
		t.Fatalf("an object was written at version 0: %v", es)
	}
}
