package server

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/dev"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/tee-signer/state"
	"github.com/lidofinance/tee-signer/trusted-time/clock"
)

// shareStore is a platform store in memory whose listing of shares/ can
// leave everything out, as a host that hides the shares at List does.
type shareStore struct {
	mu   sync.Mutex
	m    map[string][]byte
	hide bool
	puts map[string]int // writes per name
	// failPut, if set, fails each write it returns true for, without
	// storing it. The store calls it outside its lock, so it may block.
	failPut func(k string) bool
	// dropped holds the last write failPut failed, per name: the host
	// keeps the blob and may store it later.
	dropped map[string][]byte
	// landPut, if set, stores each write it returns true for and then
	// fails it, as a write whose reply was lost.
	landPut func(k string) bool
	// failGet, if set, fails each read it returns true for, as a host
	// that lists a record but denies its read. The store calls it outside
	// its lock.
	failGet func(k string) bool
	// delay, if set, is the time each call takes, as a remote store's
	// round trip.
	delay time.Duration
}

// wait sleeps for the store's delay.
func (s *shareStore) wait() {
	s.mu.Lock()
	d := s.delay
	s.mu.Unlock()
	time.Sleep(d)
}

// putsOf is how many times k was written.
func (s *shareStore) putsOf(k string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.puts[k]
}

func (s *shareStore) Get(k string) ([]byte, error) {
	s.wait()
	s.mu.Lock()
	fail := s.failGet
	s.mu.Unlock()
	if fail != nil && fail(k) {
		return nil, errors.New("test store: read denied")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.m[k]; ok {
		return append([]byte(nil), v...), nil
	}
	return nil, platform.ErrNotFound
}
func (s *shareStore) Put(k string, v []byte) error {
	s.wait()
	s.mu.Lock()
	fail := s.failPut
	s.mu.Unlock()
	if fail != nil && fail(k) {
		s.mu.Lock()
		if s.dropped == nil {
			s.dropped = map[string][]byte{}
		}
		s.dropped[k] = append([]byte(nil), v...)
		s.mu.Unlock()
		return errors.New("test store: write failed")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[k] = append([]byte(nil), v...)
	if s.landPut != nil && s.landPut(k) {
		return errors.New("test store: reply lost")
	}
	if s.puts == nil {
		s.puts = map[string]int{}
	}
	s.puts[k]++
	return nil
}
func (s *shareStore) List(prefix string) ([]string, error) {
	s.wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for k := range s.m {
		if strings.HasPrefix(k, prefix) && !(s.hide && strings.HasPrefix(k, "shares/")) {
			out = append(out, k)
		}
	}
	return out, nil
}

// shareServer is a server of setup with the mark log's logID, on store.
func shareServer(t *testing.T, store platform.Store, setup, logID [32]byte) *Server {
	t.Helper()
	cfg := software.DevConfig(uint64(time.Now().Unix())-3600, 12, 32)
	sealer := dev.NewDevSealer()
	hooks, err := state.New(cfg, state.Mode{Floor: true, FloorMargin: state.DefaultFloorMargin(cfg)}, clock.System{}, store, sealer, quiet)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := core.NewSigner(cfg, 8, 0, hooks)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Close)
	return &Server{Signer: signer, Hooks: hooks, Platform: &platform.Platform{Name: "dev", Store: store, Sealer: sealer},
		SetupHash: setup, LogID: logID, Log: quiet}
}

// A stored share is bound to its setup and to the mark log's log_id: it
// loads under both, under neither another setup nor a log made again. A
// runner with a setup stores and loads no share before its log has a
// log_id.
func TestSharesBoundToSetupAndLog(t *testing.T) {
	store := &shareStore{m: map[string][]byte{}}
	setupA, setupB := [32]byte{0xa}, [32]byte{0xb}
	log1, log2 := [32]byte{1}, [32]byte{2}
	sk, _ := software.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	if _, err := shareServer(t, store, setupA, log1).addShare(pk, &sk, 7, nil, "test"); err != nil {
		t.Fatal(err)
	}
	listed, err := ListShares(store)
	if err != nil || len(listed) != 1 {
		t.Fatalf("listed %v %v", listed, err)
	}
	if n, err := shareServer(t, store, setupA, log1).LoadListedShares(listed); n != 1 || err != nil {
		t.Fatalf("same setup and log: %d loaded, %v", n, err)
	}
	for name, s := range map[string]*Server{
		"a log made again": shareServer(t, store, setupA, log2),
		"another setup":    shareServer(t, store, setupB, log1),
	} {
		if n, err := s.LoadListedShares(listed); n != 0 || err == nil || !strings.Contains(err.Error(), "unseal") {
			t.Errorf("%s: %d loaded, %v", name, n, err)
		}
	}
	unclaimed := shareServer(t, store, setupA, [32]byte{})
	if _, err := unclaimed.LoadListedShares(listed); err == nil || unclaimed.loadFailed.Load() == nil {
		t.Fatal("loaded shares before the mark log had a log_id, or did not latch why not")
	}
	sk2, _ := software.NewSecret()
	pk2, _ := core.PubkeyOf(sk2)
	if _, err := unclaimed.addShare(pk2, &sk2, 8, nil, "test"); err == nil {
		t.Fatal("stored a share before the mark log had a log_id")
	}
	if l, _ := ListShares(store); len(l) != 1 {
		t.Fatalf("the refused import wrote a share: %v", l)
	}
	// The flag path without a setup: both zero, LoadShares lists itself.
	flag := shareServer(t, store, [32]byte{}, [32]byte{})
	if _, err := flag.addShare(pk2, &sk2, 8, nil, "test"); err != nil {
		t.Fatal(err)
	}
	if n, _ := shareServer(t, store, [32]byte{}, [32]byte{}).LoadShares(); n != 1 {
		t.Fatalf("flag path loaded %d, want its own share only", n)
	}
}

// The runner loads only the shares it listed before the claim: a share the
// host hid at that listing stays unloaded when it shows up again.
func TestOnlyTheFirstListLoads(t *testing.T) {
	store := &shareStore{m: map[string][]byte{}}
	setup, logID := [32]byte{0xa}, [32]byte{1}
	sk, _ := software.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	if _, err := shareServer(t, store, setup, logID).addShare(pk, &sk, 7, nil, "test"); err != nil {
		t.Fatal(err)
	}
	store.hide = true
	listed, _ := ListShares(store)
	store.hide = false
	s := shareServer(t, store, setup, logID)
	if n, err := s.LoadListedShares(listed); n != 0 || err != nil || len(s.Signer.Keys()) != 0 {
		t.Fatalf("loaded %d (%v) from a list that held none", n, err)
	}
	if n, err := s.LoadListedShares([]string{"sealing/key"}); n != 0 || err == nil {
		t.Fatalf("a name outside shares/: %d %v", n, err)
	}
}

// One share under two pubkeys: an import of the second is refused before
// it is stored, and at a start the second record does not load while the
// other keys do.
func TestDuplicateShareRefused(t *testing.T) {
	store := &shareStore{m: map[string][]byte{}}
	sk, _ := software.NewSecret()
	pk1, _ := core.PubkeyOf(sk)
	other, _ := software.NewSecret()
	pk2, _ := core.PubkeyOf(other)
	s := shareServer(t, store, [32]byte{}, [32]byte{})
	if _, err := s.addShare(pk1, &sk, 7, nil, "test"); err != nil {
		t.Fatal(err)
	}
	_, err := s.addShare(pk2, &sk, 8, nil, "test")
	if backend.StatusOf(err) != backend.StatusDuplicate || !strings.Contains(err.Error(), "another pubkey") {
		t.Fatalf("second pubkey for one share: %v", err)
	}
	if l, _ := ListShares(store); len(l) != 1 {
		t.Fatalf("the refused import wrote a share: %v", l)
	}

	// A store that holds both records, written by runners that each held
	// one: the start loads one of them and goes on.
	if _, err := shareServer(t, store, [32]byte{}, [32]byte{}).addShare(pk2, &sk, 8, nil, "test"); err != nil {
		t.Fatal(err)
	}
	sk3, _ := software.NewSecret()
	pk3, _ := core.PubkeyOf(sk3)
	if _, err := shareServer(t, store, [32]byte{}, [32]byte{}).addShare(pk3, &sk3, 9, nil, "test"); err != nil {
		t.Fatal(err)
	}
	start := shareServer(t, store, [32]byte{}, [32]byte{})
	n, err := start.LoadShares()
	if n != 2 || backend.StatusOf(err) != backend.StatusDuplicate || !strings.Contains(err.Error(), "another pubkey") {
		t.Fatalf("start: %d loaded, %v", n, err)
	}
	if _, err := start.Signer.State(pk3); err != nil {
		t.Fatalf("the other key did not load: %v", err)
	}
}
