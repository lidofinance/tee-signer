//go:build !debugimport

package server

import (
	"bytes"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// gateStore holds each share write until n writes wait or a second passes,
// so concurrent imports reach the store together.
type gateStore struct {
	platform.Store
	n    int
	mu   sync.Mutex
	wait int
	open chan struct{}
}

func (g *gateStore) Put(k string, v []byte) error {
	if strings.HasPrefix(k, "shares/") {
		g.mu.Lock()
		if g.wait++; g.wait == g.n {
			close(g.open)
		}
		g.mu.Unlock()
		select {
		case <-g.open:
		case <-time.After(time.Second):
		}
	}
	return g.Store.Put(k, v)
}

type testKey struct {
	sk [32]byte
	pk backend.Pubkey
}

// lastSlotRace loads one validator on a runner with max_keys 2, then sends
// two imports of other validators at once for the last slot. The loaded
// validator sorts after the other two, so a surplus record lists before
// it at the next start. It returns the loaded validator and how many of
// the two imports succeeded.
func lastSlotRace(t *testing.T) (*tgtEnv, testKey, int) {
	t.Helper()
	e := newTgtEnv(t, "dev", func(s *setupwire.Setup) { s.MaxKeys = 2 })
	var ks []testKey
	for range 3 {
		sk, pk := newKey(t)
		ks = append(ks, testKey{sk, pk})
	}
	slices.SortFunc(ks, func(a, b testKey) int { return bytes.Compare(a.pk[:], b.pk[:]) })
	if err := e.importSealed(ks[2].pk, ks[2].sk, 1, nil); err != nil {
		t.Fatal(err)
	}
	e.srv.Platform.Store = &gateStore{Store: e.store, n: 2, open: make(chan struct{})}
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = e.importSealed(ks[i].pk, ks[i].sk, uint64(10+i), nil)
		}()
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		if err == nil {
			ok++
		}
	}
	return e, ks[2], ok
}

// SIAC-01: the max_keys check counted only loaded keys, so two imports at
// the last free slot both stored their share and one then failed to load.
// Now the stored, loaded and in-flight validators together stay within
// max_keys: one import takes the slot, the other is refused before it
// stores anything.
func TestSIAC01ConcurrentImportsAtLastSlot(t *testing.T) {
	e, _, ok := lastSlotRace(t)
	stored, err := ListShares(e.store)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) > 2 {
		t.Errorf("%d shares stored with max_keys 2", len(stored))
	}
	if ok != 1 || len(e.signer.Keys()) != 2 {
		t.Errorf("%d imports succeeded, %d keys loaded; want 1 and 2", ok, len(e.signer.Keys()))
	}
}

// SIAC-01 after a restart: a surplus record that sorted before a loaded
// validator took its core slot at the next start. Now every key loaded
// before the restart loads after it.
func TestSIAC01RestartKeepsLoadedKeys(t *testing.T) {
	e, funded, _ := lastSlotRace(t)
	before := e.signer.Keys()
	e.restart()
	after := e.signer.Keys()
	for _, k := range before {
		if !slices.ContainsFunc(after, func(a backend.ValidatorKey) bool { return a.Pubkey == k.Pubkey }) {
			t.Errorf("key %s loaded before the restart, not after (funded %s)", k.Pubkey.String()[:18], funded.pk.String()[:18])
		}
	}
}

// plantUnloaded stores a sealed share record that never loaded, as an
// earlier import leaves it when the core refuses its load.
func plantUnloaded(t *testing.T, e *tgtEnv) {
	t.Helper()
	sk, pk := newKey(t)
	blob, err := e.srv.sealRecord(shareRecord{Pubkey: pk, Secret: sk[:], Index: 3})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.store.Put(shareKey(pk), blob); err != nil {
		t.Fatal(err)
	}
}

// HTC-01: a handover target counted only its loaded keys as empty, so a
// stored share that failed to load let the import start. After a restart
// that share loaded beside the handed-over ones and the import never
// ended. Now a target with any stored share refuses the reservation.
func TestHTC01ReserveRefusesStoredShare(t *testing.T) {
	src := newSrcEnv(t, nil)
	src.addKeys(2, &srcMark)
	tgt := newTargetOf(t, src, nil, nil, nil)
	plantUnloaded(t, tgt)
	src.clock.add(8 * testEpoch)
	order, _ := srcOrder(t, src, tgt, []byte{1, 2}, nil)
	if _, err := src.push(order); err != nil {
		t.Fatal(err)
	}
	src.clock.add(srcDelay)
	if _, err := tgt.push(order); err == nil {
		t.Fatal("a target with a stored share reserved itself")
	}
	if o := tgt.srv.importing(); o != nil {
		t.Fatalf("the slot holds order %x", o.Hash[:8])
	}
}

// HTC-01 on the first page without a reservation: the import does not
// start on a runner with a stored share.
func TestHTC01FirstPageRefusesStoredShare(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	plantUnloaded(t, e)
	src := newSource(t, 2, testMark)
	order, hash := e.order([]byte{1, 2}, nil)
	pages := src.pages(e.sealTo(), hash, 1)
	if _, err := e.imp(order, pages[0], 0); err == nil {
		t.Fatal("a runner with a stored share started a handover import")
	}
	if o := e.srv.importing(); o != nil {
		t.Fatalf("the slot holds order %x", o.Hash[:8])
	}
}
