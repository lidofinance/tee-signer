package markstore

import (
	"context"
	"errors"
	"testing"
)

// A log that ends with a tombstone (an image with a handover wrote it) is
// not claimed: this image signs nothing on it and writes no record.
func TestTombstoneNotClaimed(t *testing.T) {
	ctx := context.Background()
	l, _ := NewFileLog(t.TempDir())
	m, _ := New(l, "s1", testKey(0), Options{Log: quiet})
	if _, _, err := m.Claim(ctx, false); err != nil {
		t.Fatal(err)
	}
	if err := m.Append(ctx, mark(10)); err != nil {
		t.Fatal(err)
	}
	if err := m.Append(ctx, Tombstone); err != nil {
		t.Fatal(err)
	}
	_, v := m.Mark()
	m2, _ := New(l, "s1", testKey(0), Options{Log: quiet})
	if _, _, err := m2.Claim(ctx, true); !errors.Is(err, ErrHandedOver) {
		t.Fatalf("claim of a log that ends with a tombstone: %v", err)
	}
	m3, _ := New(l, "s1", testKey(0), Options{Log: quiet})
	if _, _, err := m3.Claim(ctx, true); !errors.Is(err, ErrHandedOver) {
		t.Fatalf("second claim: %v", err)
	}
	if es, err := l.List(ctx, Name([32]byte{}, "s1", v+1)); err != nil || len(es) != 0 {
		t.Fatalf("a refused claim wrote a record: %v %v", es, err)
	}
}

// The log's mark never goes down: Append writes the merge, Raise writes
// only when it raises.
func TestAppendMerges(t *testing.T) {
	ctx := context.Background()
	l, _ := NewFileLog(t.TempDir())
	m, _ := New(l, "s1", testKey(0), Options{Log: quiet})
	if _, _, err := m.Claim(ctx, false); err != nil {
		t.Fatal(err)
	}
	if err := m.Raise(ctx, mark(50)); err != nil {
		t.Fatal(err)
	}
	_, v := m.Mark()
	if err := m.Raise(ctx, mark(40)); err != nil {
		t.Fatal(err)
	}
	if got, v2 := m.Mark(); got != mark(50) || v2 != v {
		t.Fatalf("a lower raise wrote version %d with %+v", v2, got)
	}
	if err := m.Append(ctx, mark(30)); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.Mark(); got != mark(50) {
		t.Fatalf("a lower append lowered the mark to %+v", got)
	}
	m2, _ := New(l, "s1", testKey(0), Options{Log: quiet})
	if got, _, err := m2.Claim(ctx, true); err != nil || got != mark(50) {
		t.Fatalf("restart read %+v %v", got, err)
	}
}
