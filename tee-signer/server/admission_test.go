//go:build !debugimport

package server

import (
	"slices"
	"sync"
	"testing"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// Share admission: every import goes through addShare, one share per
// validator at a time.

// SSI-STORAGE-01: the second share of a validator replaced the first one's
// stored record before the core refused it as a duplicate. The first
// import was reported done, but a restart loaded the second share. Now the
// second is refused before it is stored, and a restart loads the share
// that was reported.
func TestSSIStorage01SecondShareDoesNotReplaceTheFirst(t *testing.T) {
	e := newShareTgtEnv(t, "dev", nil)
	oneKey(t, e)
	pk := newPubkey(t)
	a, b := newSecret(t), newSecret(t)
	ka, err := e.srv.addShare(pk, &a, 7, nil, "sealed")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.addShare(pk, &b, 8, nil, "sealed"); err == nil {
		t.Fatal("a second share of a loaded validator was taken")
	}
	e.restart()
	keys := e.signer.Keys()
	if i := slices.IndexFunc(keys, func(k backend.ValidatorKey) bool { return k.Pubkey == pk }); i < 0 || keys[i].SharePubkey != ka.SharePubkey || keys[i].Index != 7 {
		t.Fatalf("after a restart %+v, the import reported %+v", keys, ka)
	}
}

// The same under the race detector: many requests at once for one
// validator, each with its own share. One wins; the stored record and the
// loaded share name the winner, and the key origin counts two keys.
func TestShareAdmissionConcurrent(t *testing.T) {
	e := newShareTgtEnv(t, "dev", nil)
	oneKey(t, e)
	pk := newPubkey(t)
	const n = 8
	var wg sync.WaitGroup
	won := make([]*backend.ValidatorKey, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sec := newSecret(t)
			if k, err := e.srv.addShare(pk, &sec, uint64(i), &testMark, "sealed"); err == nil {
				won[i] = &k
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
		if ko := e.srv.SetupState().KeyOrigin; ko.Imported != 2 {
			t.Fatalf("%s: key origin %+v, want two keys", when, ko)
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

// attestNow signs an attestation of pk for the epoch of the clock.
func (e *tgtEnv) attestNow(pk backend.Pubkey) error {
	ep := (e.now() - testGenesis) / testEpoch
	return e.attest(pk, ep-1, ep)
}

// oneKey loads one imported key on e.
func oneKey(t *testing.T, e *tgtEnv) {
	t.Helper()
	sec := newSecret(t)
	if _, err := e.srv.addShare(newPubkey(t), &sec, 1, nil, "sealed"); err != nil {
		t.Fatal(err)
	}
}

func newSecret(t *testing.T) [32]byte {
	t.Helper()
	sk, err := software.NewSecret()
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
