//go:build !debugimport

package server

import (
	"strings"
	"sync"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// listHookStore runs onList once, right after the first listing of the
// shares: a share another request adds just after the caller's check.
type listHookStore struct {
	*shareStore
	once   sync.Once
	onList func()
}

func (s *listHookStore) List(prefix string) ([]string, error) {
	out, err := s.shareStore.List(prefix)
	if prefix == "shares/" {
		s.once.Do(s.onList)
	}
	return out, err
}

// SHO-02: the source compared its stored shares with the target's
// max_keys before it took the share lock. A share added between that check
// and the lock went into the tombstone's set, and the target, whose
// max_keys it passed, could never take every share. The check now runs on
// the set read under the lock: the handover is refused, no tombstone is
// written, and the source signs on.
func TestSHO02CapacityCheckedUnderTheLock(t *testing.T) {
	src := newSrcEnv(t, nil)
	keys := src.addKeys(2, 0, [32]byte{}, &srcMark)
	tgt := newTargetOf(t, src, nil, nil, func(s *setupwire.Setup) { s.MaxKeys = 2 })
	src.clock.add(8 * testEpoch)
	order, _ := srcOrder(t, src, tgt, []byte{1, 2}, nil)
	if _, err := src.push(order); err != nil {
		t.Fatal(err)
	}
	src.clock.add(srcDelay)
	src.srv.Platform.Store = &listHookStore{shareStore: src.store, onList: func() {
		sec, pk := newSecret(t), newPubkey(t)
		if _, err := src.srv.addShareOf(pk, &sec, 300, nil, "sealed", shareOrigin{}, nil); err != nil {
			t.Errorf("the share added meanwhile: %v", err)
		}
	}}
	_, err := handOver(t, src, tgt, order, 0)
	if err == nil || !strings.Contains(err.Error(), "max_keys") {
		t.Fatalf("a handover of 3 shares to a target of max_keys 2: %v", err)
	}
	if _, ok := src.hooks.HandedOverTo(); ok {
		t.Fatal("the source wrote its tombstone")
	}
	ep := src.signer.EpochAt(src.now())
	if err := src.attest(keys[0], ep-1, ep); err != nil {
		t.Fatalf("the source after the refusal: %v", err)
	}
}
