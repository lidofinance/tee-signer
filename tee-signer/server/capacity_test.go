//go:build (peer_azure || peer_aws || peer_gcp || peer_dev) && !debugimport

package server

import (
	"maps"
	"sync"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/tee-signer/keygen"
)

// genBatch is a key generation commit's batch of n fresh shares.
func genBatch(t *testing.T, n int) []keygen.NewShare {
	var out []keygen.NewShare
	for range n {
		sk, pk := newKey(t)
		out = append(out, keygen.NewShare{Pubkey: pk, Secret: &sk, Order: make([]byte, 32)})
	}
	return out
}

// storeInto is the store step of a commit: it writes the sealed shares.
func (e *tgtEnv) storeInto(stored *bool) func(map[string][]byte) error {
	return func(sealed map[string][]byte) error {
		*stored = true
		for k, v := range sealed {
			if err := e.store.Put(k, v); err != nil {
				return err
			}
		}
		return nil
	}
}

// TKGSTATE-01: a key generation batch is checked against max_keys as a
// whole. With max_keys 2 and one funded key loaded, a batch of two is
// refused before anything is stored, and the funded key loads after a
// restart.
func TestDKGBatchWithinMaxKeys(t *testing.T) {
	e := newTgtEnv(t, "dev", func(s *setupwire.Setup) { s.MaxKeys = 2 })
	sk, funded := newKey(t)
	if err := e.importSealed(funded, sk, 10, nil); err != nil {
		t.Fatal(err)
	}
	before := maps.Clone(e.store.m)
	stored := false
	if _, err := e.srv.AddGeneratedShares(genBatch(t, 2), e.storeInto(&stored)); err == nil {
		t.Fatal("a batch of 2 was taken with 1 of max_keys 2 free")
	}
	if stored || !maps.EqualFunc(before, e.store.m, func(a, b []byte) bool { return string(a) == string(b) }) {
		t.Fatal("the refused batch changed the store")
	}
	e.restart()
	if !hasKey(e.srv.Signer.Keys(), funded) {
		t.Fatal("the funded key did not load after the restart")
	}
	// A batch that fits is taken.
	if _, err := e.srv.AddGeneratedShares(genBatch(t, 1), e.storeInto(&stored)); err != nil {
		t.Fatalf("a batch of 1 with 1 slot free: %v", err)
	}
}

// Shares stored but not loaded hold their slot: max_keys bounds what a
// restart loads, and that is every stored share.
func TestDKGBatchCountsStoredShares(t *testing.T) {
	e := newTgtEnv(t, "dev", func(s *setupwire.Setup) { s.MaxKeys = 2 })
	stored := false
	if _, err := e.srv.AddGeneratedShares(genBatch(t, 1), e.storeInto(&stored)); err != nil {
		t.Fatal(err)
	}
	// A share stored by an earlier process that did not load here.
	sk, pk := newKey(t)
	blob, err := e.srv.sealShare(pk, &sk, backend.IndexUnknown, true, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	e.store.Put(shareKey(pk), blob)
	if _, err := e.srv.AddGeneratedShares(genBatch(t, 1), e.storeInto(&stored)); err == nil {
		t.Fatal("a batch was taken with every slot held by a stored share")
	}
}

// Two commits at once with one slot free: one is taken, not both.
func TestDKGBatchesAtOnceWithinMaxKeys(t *testing.T) {
	e := newTgtEnv(t, "dev", func(s *setupwire.Setup) { s.MaxKeys = 1 })
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range 2 {
		b := genBatch(t, 1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			stored := false
			_, errs[i] = e.srv.AddGeneratedShares(b, e.storeInto(&stored))
		}()
	}
	wg.Wait()
	if errs[0] == nil && errs[1] == nil {
		t.Fatal("two batches of 1 were taken with max_keys 1")
	}
	if n, _ := ListShares(e.store); len(n) > 1 {
		t.Fatalf("%d shares stored with max_keys 1", len(n))
	}
}

func hasKey(keys []backend.ValidatorKey, pk backend.Pubkey) bool {
	for _, k := range keys {
		if k.Pubkey == pk {
			return true
		}
	}
	return false
}
