package server

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/dev"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/tee-signer/state"
	"github.com/lidofinance/tee-signer/trusted-time/clock"
)

// shareStore is a platform store in memory whose listing of shares/ can
// leave everything out, as a host that hides the shares at List does.
type shareStore struct {
	mu   sync.Mutex
	m    map[string][]byte
	hide bool
}

func (s *shareStore) Get(k string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.m[k]; ok {
		return append([]byte(nil), v...), nil
	}
	return nil, platform.ErrNotFound
}
func (s *shareStore) Put(k string, v []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[k] = append([]byte(nil), v...)
	return nil
}
func (s *shareStore) List(prefix string) ([]string, error) {
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
	if _, err := unclaimed.LoadListedShares(listed); err == nil {
		t.Fatal("loaded shares before the mark log had a log_id")
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
