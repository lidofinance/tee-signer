package markstore

import (
	"context"
	"errors"
	"testing"
)

// The handover's tombstone: written once, the mark before it is what
// HandOverTo returns, Append fails after it, and a new process on the log
// writes no claim record, finds the mark before the tombstone and refuses
// to append.
func TestHandOverTombstone(t *testing.T) {
	ctx := context.Background()
	l, err := NewFileLog(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := [32]byte{0x7a}
	m, _ := New(l, "s1", testKey(0), Options{Log: quiet})
	if _, _, err := m.Claim(ctx, false); err != nil {
		t.Fatal(err)
	}
	if err := m.Append(ctx, mark(10)); err != nil {
		t.Fatal(err)
	}
	before, err := m.HandOverTo(ctx, target)
	if err != nil || before != mark(10) {
		t.Fatalf("handover: %+v %v", before, err)
	}
	if got, v := m.Mark(); !IsTombstone(got) || v != 3 {
		t.Fatalf("after the handover the log's mark is %+v at version %d, want the tombstone at 3", got, v)
	}
	if err := m.Append(ctx, mark(11)); !errors.Is(err, ErrHandedOver) {
		t.Fatalf("append after the handover: %v", err)
	}
	if err := m.Raise(ctx, mark(12)); !errors.Is(err, ErrHandedOver) {
		t.Fatalf("raise after the handover: %v", err)
	}
	again, err := m.HandOverTo(ctx, target)
	if err != nil || again != before {
		t.Fatalf("second handover: %+v %v", again, err)
	}
	if _, err := m.HandOverTo(ctx, [32]byte{0x7b}); err == nil {
		t.Fatal("a second target for one tombstone")
	}

	// A restart of the old image reads the tombstone.
	m2, _ := New(l, "s1", testKey(0), Options{Log: quiet})
	got, found, err := m2.Claim(ctx, true)
	if err != nil || !found || !IsTombstone(got) {
		t.Fatalf("claim after the handover: %+v %v %v", got, found, err)
	}
	if _, v := m2.Mark(); v != 3 {
		t.Fatalf("the restart wrote a claim record (version %d)", v)
	}
	if prev, ok := m2.HandedOver(); !ok || prev != mark(10) {
		t.Fatalf("restart: handed over %v, mark before %+v", ok, prev)
	}
	if err := m2.Append(ctx, mark(20)); !errors.Is(err, ErrHandedOver) {
		t.Fatalf("append after the restart: %v", err)
	}
	if again, err := m2.HandOverTo(ctx, target); err != nil || again != mark(10) {
		t.Fatalf("handover repeated after the restart: %+v %v", again, err)
	}
}

// A tombstone that names no target (no code writes one, SHL-01) still
// stops the runner: the log reads as handed over, signs nothing, and no
// handover to a named target is taken on it.
func TestUntargetedTombstone(t *testing.T) {
	ctx := context.Background()
	l, err := NewFileLog(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	m, _ := New(l, "s1", testKey(0), Options{Log: quiet})
	if _, _, err := m.Claim(ctx, false); err != nil {
		t.Fatal(err)
	}
	if err := m.Append(ctx, mark(10)); err != nil {
		t.Fatal(err)
	}
	// A tombstone without a target.
	m.mu.Lock()
	err = m.appendLocked(ctx, Tombstone, nil)
	m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	m2, _ := New(l, "s1", testKey(0), Options{Log: quiet})
	got, found, err := m2.Claim(ctx, true)
	if err != nil || !found || !IsTombstone(got) {
		t.Fatalf("claim after an untargeted tombstone: %+v %v %v", got, found, err)
	}
	if prev, ok := m2.HandedOver(); !ok || prev != mark(10) {
		t.Fatalf("handed over %v, mark before %+v", ok, prev)
	}
	if _, ok := m2.HandedOverTo(); ok {
		t.Fatal("the tombstone names a target")
	}
	if err := m2.Append(ctx, mark(20)); !errors.Is(err, ErrHandedOver) {
		t.Fatalf("append after an untargeted tombstone: %v", err)
	}
	if _, err := m2.HandOverTo(ctx, [32]byte{0x7a}); err == nil {
		t.Fatal("a named handover on a log an untargeted tombstone ended")
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
