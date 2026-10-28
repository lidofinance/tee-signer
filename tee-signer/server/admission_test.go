//go:build (peer_azure || peer_aws || peer_gcp || peer_dev) && !debugimport

package server

import (
	"slices"
	"sync"
	"testing"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/tee-signer/handover"
)

// Share admission: sealed import and handover import go through
// addShareOf. The handover import passes the key list it read once per
// request, so two requests (or two entries of one page) for one validator
// both passed the duplicate check on their own copy of that list.

// SSI-STORAGE-01: the second share of a validator replaced the first one's
// stored record before the core refused it as a duplicate. The first
// import was reported done, but a restart loaded the second share. Now the
// second is refused before it is stored, and a restart loads the share
// that was reported.
func TestSSIStorage01SecondShareDoesNotReplaceTheFirst(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	stale := oneKey(t, e) // the list a request read before either share
	pk := newPubkey(t)
	a, b := newSecret(t), newSecret(t)
	ka, err := e.srv.addShareOf(pk, &a, 7, nil, "handover", shareOrigin{}, stale)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.addShareOf(pk, &b, 8, nil, "handover", shareOrigin{}, stale); err == nil {
		t.Fatal("a second share of a loaded validator was taken")
	}
	e.restart()
	keys := e.signer.Keys()
	if i := slices.IndexFunc(keys, func(k backend.ValidatorKey) bool { return k.Pubkey == pk }); i < 0 || keys[i].SharePubkey != ka.SharePubkey || keys[i].Index != 7 {
		t.Fatalf("after a restart %+v, the import reported %+v", keys, ka)
	}
}

// APSTATE-01: the key origin of the losing share was noted before its
// load failed, so an imported share counted as generated. Now the origin
// is noted only for a share that loaded.
func TestAPSTATE01LoserOriginNotCounted(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	stale := oneKey(t, e)
	pk := newPubkey(t)
	a, b := newSecret(t), newSecret(t)
	if _, err := e.srv.addShareOf(pk, &a, 7, nil, "handover", shareOrigin{}, stale); err != nil {
		t.Fatal(err)
	}
	gen := shareOrigin{generated: true, order: make([]byte, 32)}
	if _, err := e.srv.addShareOf(pk, &b, 7, nil, "handover", gen, stale); err == nil {
		t.Fatal("a second share of a loaded validator was taken")
	}
	if ko := e.srv.SetupState().KeyOrigin; ko.Generated != 0 || ko.Imported != 2 {
		t.Fatalf("key origin %+v, want two imported", ko)
	}
	e.restart()
	if ko := e.srv.SetupState().KeyOrigin; ko.Generated != 0 || ko.Imported != 2 {
		t.Fatalf("after a restart: key origin %+v, want two imported", ko)
	}
}

// The same under the race detector: many requests at once for one
// validator, each with its own share and origin. One wins; the stored
// record, the loaded share and the key origin all name the winner.
func TestShareAdmissionConcurrent(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	stale := oneKey(t, e)
	pk := newPubkey(t)
	const n = 8
	var wg sync.WaitGroup
	won := make([]*backend.ValidatorKey, n)
	gens := make([]bool, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sec := newSecret(t)
			o := shareOrigin{}
			if i%2 == 1 {
				o = shareOrigin{generated: true}
			}
			if k, err := e.srv.addShareOf(pk, &sec, uint64(i), &testMark, "handover", o, stale); err == nil {
				won[i], gens[i] = &k, o.generated
			}
		}()
	}
	wg.Wait()
	w := -1
	for i, k := range won {
		if k != nil {
			if w >= 0 {
				t.Fatalf("requests %d and %d both stored the validator", w, i)
			}
			w = i
		}
	}
	if w < 0 {
		t.Fatal("no request stored the validator")
	}
	check := func(when string) {
		t.Helper()
		keys := e.signer.Keys()
		i := slices.IndexFunc(keys, func(k backend.ValidatorKey) bool { return k.Pubkey == pk })
		if len(keys) != 2 || i < 0 || keys[i].SharePubkey != won[w].SharePubkey || keys[i].Index != uint64(w) {
			t.Fatalf("%s: loaded %+v, the winner %+v", when, keys, won[w])
		}
		if ko := e.srv.SetupState().KeyOrigin; (ko.Generated == 1) != gens[w] || ko.Generated+ko.Imported != 2 {
			t.Fatalf("%s: key origin %+v, the winner generated %v", when, ko, gens[w])
		}
	}
	check("before a restart")
	e.clock.add(8 * testEpoch)
	if err := e.attestNow(pk); err != nil {
		t.Fatalf("the validator does not sign: %v", err)
	}
	e.restart()
	check("after a restart")
}

// APSTATE-02: a page that names one validator twice. The second copy
// passed the request's duplicate check, reached the core as a duplicate,
// and the runner blocked the validator from signing until a restart. Now
// such a page is refused, and the validator signs once the import ends.
func TestAPSTATE02RepeatedShareInAPage(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	src := newSource(t, 0, 4, nil, testMark)
	order, hash := e.order([]byte{1, 2}, nil)
	pages := src.pages(e.sealTo(), hash, 2)
	e.mustImp(order, pages[0], 0)
	dup := *pages[1]
	dup.Shares = []handover.Share{pages[1].Shares[0], pages[1].Shares[0]}
	_, _ = e.imp(order, &dup, 0) // refused, or taken without harm
	if r := e.mustImp(order, pages[1], 0); !r.Done || r.Held != 4 {
		t.Fatalf("the import: %+v", r)
	}
	e.clock.add(8 * testEpoch)
	if err := e.attestNow(pages[1].Shares[0].Pubkey); err != nil {
		t.Fatalf("the validator named twice does not sign: %v", err)
	}
}

// oneKey loads one imported key on e and returns the key list after it: a
// request's list, read before the shares it adds.
func oneKey(t *testing.T, e *tgtEnv) []backend.ValidatorKey {
	t.Helper()
	sec := newSecret(t)
	if _, err := e.srv.addShareOf(newPubkey(t), &sec, 1, nil, "sealed", shareOrigin{}, nil); err != nil {
		t.Fatal(err)
	}
	return e.signer.Keys()
}

func newSecret(t *testing.T) [32]byte {
	t.Helper()
	sk, err := core.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	return sk
}

func newPubkey(t *testing.T) backend.Pubkey {
	t.Helper()
	sk := newSecret(t)
	pk, err := core.PubkeyOf(sk)
	if err != nil {
		t.Fatal(err)
	}
	return pk
}
