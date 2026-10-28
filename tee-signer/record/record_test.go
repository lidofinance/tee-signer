package record

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/lidofinance/tee-signer/platform/dev"
)

var (
	ctx   = context.Background()
	quiet = slog.New(slog.NewTextHandler(io.Discard, nil))
)

// storeContract checks the conditional-write rules every Store must keep.
func storeContract(t *testing.T, s Store) {
	t.Helper()
	if _, _, err := s.Get(ctx, "node-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty store: %v", err)
	}
	if err := s.Put(ctx, "node-1", 0, 1, []byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, "node-1", 0, 1, []byte("b")); !errors.Is(err, ErrConflict) {
		t.Fatalf("create over an existing record: %v", err)
	}
	if err := s.Put(ctx, "node-1", 1, 2, []byte("c")); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, "node-1", 1, 2, []byte("d")); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale version: %v", err)
	}
	v, val, err := s.Get(ctx, "node-1")
	if err != nil || v != 2 || string(val) != "c" {
		t.Fatalf("get: %d %q %v", v, val, err)
	}
	if _, _, err := s.Get(ctx, "node-2"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other key: %v", err)
	}
	// Racing writers from the same version: exactly one wins.
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := s.Put(ctx, "node-1", 2, 3, []byte{byte(i)}); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			} else if !errors.Is(err, ErrConflict) {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d racing writers won, want 1", wins)
	}
}

func TestFileStore(t *testing.T) { storeContract(t, &FileStore{Dir: t.TempDir()}) }
func TestMemStore(t *testing.T)  { storeContract(t, NewMemStore()) }

func TestOpenSpecs(t *testing.T) {
	for _, s := range []string{"bogus", "file:", "dynamodb:table=x", "dynamodb:region=y", "dynamodb:table=x,region=y,colour=red"} {
		if _, err := Open(s, Env{}); err == nil {
			t.Fatalf("%q accepted", s)
		}
	}
	if s, err := Open("none", Env{}); s != nil || err != nil {
		t.Fatal(s, err)
	}
}

func newGuard(t *testing.T, s Store) *Guard {
	g, err := New(s, "node-1", dev.NewDevSealer(), 0, quiet)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestGuardClaimCoverAndTakeover(t *testing.T) {
	s := NewMemStore()
	a := newGuard(t, s)
	if err := a.Cover(ctx, 5); err == nil {
		t.Fatal("cover before claim")
	}
	if err := a.Claim(ctx, false); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Floor(); ok {
		t.Fatal("first claim has no previous owner")
	}
	if err := a.Cover(ctx, 10); err != nil {
		t.Fatal(err)
	}
	if err := a.Cover(ctx, 9); err != nil { // covered already, no write
		t.Fatal(err)
	}
	if v, _, _ := s.Get(ctx, "node-1"); v != 2 {
		t.Fatalf("version %d, want 2 (claim + one cover)", v)
	}

	// A clone from the same image claims the record.
	b := newGuard(t, s)
	if err := b.Claim(ctx, true); err != nil {
		t.Fatal(err)
	}
	if f, ok := b.Floor(); !ok || f != 10 {
		t.Fatalf("clone floor %d %v, want 10", f, ok)
	}
	if err := a.Cover(ctx, 10); err != nil { // a may still sign what it covered
		t.Fatal(err)
	}
	if err := a.Cover(ctx, 11); err == nil || !strings.Contains(err.Error(), "another runner") {
		t.Fatalf("old owner advanced after the takeover: %v", err)
	}
	if err := a.Cover(ctx, 12); err == nil {
		t.Fatal("old owner recovered")
	}
	if err := b.Cover(ctx, 11); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(a.Status(), "LOST") || strings.Contains(b.Status(), "LOST") {
		t.Fatal(a.Status(), b.Status())
	}
}

func TestGuardStoreFailureRefuses(t *testing.T) {
	s := NewMemStore()
	g := newGuard(t, s)
	if err := g.Claim(ctx, false); err != nil {
		t.Fatal(err)
	}
	s.Fail = errors.New("table unreachable")
	if err := g.Cover(ctx, 3); err == nil {
		t.Fatal("cover without the store")
	}
	s.Fail = nil
	if err := g.Cover(ctx, 3); err != nil { // transient: works again
		t.Fatal(err)
	}
}

// lossyStore applies a write but reports a failure, as when the reply is lost.
type lossyStore struct {
	*MemStore
	drop bool
}

func (l *lossyStore) Put(c context.Context, key string, prev, next uint64, v []byte) error {
	err := l.MemStore.Put(c, key, prev, next, v)
	if l.drop && err == nil {
		l.drop = false
		return errors.New("timeout")
	}
	return err
}

func TestGuardAdoptsOwnLostWrite(t *testing.T) {
	s := &lossyStore{MemStore: NewMemStore()}
	g := newGuard(t, s)
	if err := g.Claim(ctx, false); err != nil {
		t.Fatal(err)
	}
	s.drop = true
	if err := g.Cover(ctx, 4); err == nil {
		t.Fatal("lost reply should fail this call")
	}
	// The retry conflicts with our own landed write and adopts it.
	if err := g.Cover(ctx, 4); err != nil {
		t.Fatalf("retry after a lost reply: %v", err)
	}
	if err := g.Cover(ctx, 5); err != nil {
		t.Fatal(err)
	}
}

func TestGuardMissingOrTamperedRecord(t *testing.T) {
	s := NewMemStore()
	g := newGuard(t, s)
	if err := g.Claim(ctx, true); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing record with stored shares: %v", err)
	}
	g.AllowCreate = true
	if err := g.Claim(ctx, true); err != nil {
		t.Fatal(err)
	}
	// Someone with table access writes a value sealed for another version.
	v, val, _ := s.Get(ctx, "node-1")
	if err := s.Put(ctx, "node-1", v, v+5, val); err != nil {
		t.Fatal(err)
	}
	if err := newGuard(t, s).Claim(ctx, true); err == nil || !strings.Contains(err.Error(), "unseal") {
		t.Fatalf("record moved to another version: %v", err)
	}
}
