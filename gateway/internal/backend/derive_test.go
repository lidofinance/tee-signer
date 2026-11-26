package backend

import (
	"context"
	crand "crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"

	proto "github.com/lidofinance/tee-signer/signer-protocol"
)

// reversed is a cluster of n signers for keys split t of n, listed in the
// reverse order of their share indices: the slowest order for a search
// that tries the indices in increasing order.
func reversed(t *testing.T, keys, threshold, n int) ([]*testKey, []*fakeRunner) {
	t.Helper()
	ks := make([]*testKey, keys)
	for i := range ks {
		ks[i] = splitKey(t, threshold, n)
	}
	fakes := cluster(ks, n)
	slices.Reverse(fakes)

	return ks, fakes
}

// 200 keys of a 5-of-6 split, signers listed in reverse index order, load
// in a few seconds.
func TestKeyLoadIsFast(t *testing.T) {
	ks, fakes := reversed(t, 200, 5, 6)
	s := newSigners(names(len(fakes)), runners(fakes), 0, 2*time.Second, discard())
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := s.Refresh(context.Background())
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("200 keys of 5 of 6 not loaded after %s", time.Since(start))
	}
	t.Logf("200 keys of 5 of 6 loaded in %s", time.Since(start))
	for _, k := range ks {
		g, ok := s.keys.lookup(k.pk)
		if !ok || g.threshold != 5 {
			t.Fatalf("group %+v", g)
		}
		for i, sh := range g.shares {
			if want := uint64(6 - sh.node); sh.index != want {
				t.Fatalf("share %d: index %d, want %d", i, sh.index, want)
			}
		}
	}
}

// TestDeriveTimes logs how long deriveGroup takes per key, without and
// with the guess of another key of the same signers. DERIVE_TIMES=1 runs
// it.
func TestDeriveTimes(t *testing.T) {
	if os.Getenv("DERIVE_TIMES") == "" {
		t.Skip("DERIVE_TIMES not set")
	}
	for _, c := range []struct{ t, n int }{{4, 6}, {5, 6}, {6, 8}, {7, 8}} {
		for _, rev := range []bool{false, true} {
			k := splitKey(t, c.t, c.n)
			sh := make([]share, c.n)
			want := make([]uint64, c.n)
			for i := range sh {
				x := i
				if rev {
					x = c.n - 1 - i
				}
				sh[i], want[i] = share{node: i, pub: pubOf(&k.shares[x])}, uint64(x+1)
			}
			start := time.Now()
			g, err := deriveGroup(k.pk, sh, c.n)
			cold := time.Since(start)
			if err != nil || g.threshold != c.t {
				t.Fatalf("%d of %d: %+v %v", c.t, c.n, g, err)
			}
			start = time.Now()
			g, err = deriveGroup(k.pk, sh, c.n, guess{threshold: c.t, index: want})
			warm := time.Since(start)
			if err != nil || g.threshold != c.t {
				t.Fatalf("%d of %d: %+v %v", c.t, c.n, g, err)
			}
			t.Logf("%d of %d reversed=%v: no guess %s, guess %s", c.t, c.n, rev, cold, warm)
		}
	}
	// A key with one foreign share fits nothing: the whole search runs.
	for _, c := range []struct{ t, n int }{{5, 6}, {5, 8}, {7, 8}} {
		k, other := splitKey(t, c.t, c.n), splitKey(t, c.t, c.n)
		sh := shareList(k)
		sh[c.n-1].pub = pubOf(&other.shares[c.n-1])
		right := make([]uint64, c.n)
		for i := range right {
			right[i] = uint64(i + 1)
		}
		start := time.Now()
		if g, err := deriveGroup(k.pk, sh, c.n, guess{threshold: c.t, index: right}); err == nil {
			t.Fatalf("%d of %d with a foreign share: %+v", c.t, c.n, g)
		}
		t.Logf("%d of %d with a foreign share: refused in %s", c.t, c.n, time.Since(start))
	}
}

// shareList is share i of k on signer i.
func shareList(k *testKey) []share {
	sh := make([]share, len(k.shares))
	for i := range sh {
		sh[i] = share{node: i, pub: pubOf(&k.shares[i])}
	}

	return sh
}

// A guess is checked like the search: a wrong one falls back to the
// search, one at or below k/2 is not taken, and a key with a foreign share
// is refused whatever the guess.
func TestDeriveGroupGuesses(t *testing.T) {
	k := splitKey(t, 5, 6)
	sh := shareList(k)
	right := []uint64{1, 2, 3, 4, 5, 6}
	for _, g := range [][]guess{
		nil,
		{{threshold: 5, index: right}},
		{{threshold: 5, index: []uint64{2, 1, 3, 4, 5, 6}}},
		{{threshold: 4, index: right}},
		{{threshold: 6, index: right}},
		{{threshold: 5, index: []uint64{1, 1, 3, 4, 5, 6}}},
		{{threshold: 5, index: []uint64{1, 2, 3}}},
		{{threshold: 5, index: []uint64{2, 1, 3, 4, 5, 6}}, {threshold: 5, index: right}},
	} {
		got, err := deriveGroup(k.pk, sh, 6, g...)
		if err != nil || got.threshold != 5 {
			t.Fatalf("guesses %v: %+v %v", g, got, err)
		}
		for i, s := range got.shares {
			if s.index != right[i] {
				t.Fatalf("guesses %v: share %d index %d", g, i, s.index)
			}
		}
	}

	// A key split 2 of 6 with a guess of 5: refused as by the search.
	low := splitKey(t, 2, 6)
	if got, err := deriveGroup(low.pk, shareList(low), 6, guess{threshold: 5, index: right}); err == nil ||
		!strings.Contains(err.Error(), "threshold 2 of 6") {
		t.Fatalf("2 of 6, guess 5: %+v %v", got, err)
	}

	other := splitKey(t, 5, 6)
	sh[5].pub = pubOf(&other.shares[5])
	for _, g := range [][]guess{nil, {{threshold: 5, index: right}}, {{threshold: 6, index: right}}} {
		if got, err := deriveGroup(k.pk, sh, 6, g...); err == nil {
			t.Fatalf("foreign share, guesses %v: %+v", g, got)
		}
	}
}

// Shares made to fit both a line and a cubic: every 4 of them interpolate
// to the key with indices 1 to 4, and every 2 with indices 1, 3, 4, 2. The
// search finds threshold 2 and refuses it (checkOverlap); a guess of 4
// must not get it served.
func TestDeriveGroupGuessDoesNotHideALowerThreshold(t *testing.T) {
	a0, a1 := randScalar(t), randScalar(t)
	sk := blstKey(a0)
	pk := pubOf(sk)
	y := []int64{1, 3, 4, 2}
	sh := make([]share, len(y))
	for i, yi := range y {
		v := new(big.Int).Mul(a1, big.NewInt(yi))
		v.Add(v, a0).Mod(v, groupR)
		sh[i] = share{node: i, pub: pubOf(blstKey(v))}
	}
	cubic := []uint64{1, 2, 3, 4}
	f, ok := newFit(pk, sh)
	if !ok || !f.everySubset(cubic, 4) || f.everySubset(cubic, 3) {
		t.Fatal("the shares do not fit a cubic at 1 to 4")
	}
	if !f.everySubset([]uint64{1, 3, 4, 2}, 2) {
		t.Fatal("the shares do not fit a line at 1, 3, 4, 2")
	}
	for _, g := range [][]guess{nil, {{threshold: 4, index: cubic}}} {
		got, err := deriveGroup(pk, sh, 4, g...)
		if err == nil || !strings.Contains(err.Error(), "threshold 2 of 4") {
			t.Fatalf("guesses %v: %+v %v", g, got, err)
		}
	}
}

// One key whose signers hold other indices than the rest, one split 6 of
// 6, one with a foreign share, and a whole key on a signer of its own: the
// first is served with its own indices, the second with threshold 6, the
// third refused, the fourth served.
func TestKeyLoadMixedIndices(t *testing.T) {
	keys := make([]*testKey, 20)
	for i := range keys {
		keys[i] = splitKey(t, 5, 6)
	}
	fakes := cluster(keys, 6)
	odd, bad, other, w := splitKey(t, 5, 6), splitKey(t, 5, 6), splitKey(t, 5, 6), splitKey(t, 1, 1)
	all := splitKey(t, 6, 6)
	for i, f := range fakes {
		f.keys = append(f.keys, proto.ValidatorKey{Pubkey: proto.Pubkey(all.pk), SharePubkey: proto.Pubkey(pubOf(&all.shares[i])), Index: proto.IndexUnknown})
		f.secret[proto.Pubkey(all.pk)] = &all.shares[i]
		x := (i + 1) % 6
		f.keys = append(f.keys, proto.ValidatorKey{Pubkey: proto.Pubkey(odd.pk), SharePubkey: proto.Pubkey(pubOf(&odd.shares[x])), Index: proto.IndexUnknown})
		f.secret[proto.Pubkey(odd.pk)] = &odd.shares[x]
		from := bad
		if i == 5 {
			from = other
		}
		f.keys = append(f.keys, proto.ValidatorKey{Pubkey: proto.Pubkey(bad.pk), SharePubkey: proto.Pubkey(pubOf(&from.shares[i])), Index: proto.IndexUnknown})
	}
	fakes = append(fakes, cluster([]*testKey{w}, 1)...)
	setRoot(fakes)
	s := newTestSigners(t, fakes)
	searched(t, s)
	for _, k := range keys {
		g, ok := s.keys.lookup(k.pk)
		if !ok || g.threshold != 5 {
			t.Fatalf("group %+v", g)
		}
		for _, sh := range g.shares {
			if sh.index != uint64(sh.node+1) {
				t.Fatalf("signer %d: index %d", sh.node, sh.index)
			}
		}
	}
	g, ok := s.keys.lookup(odd.pk)
	if !ok || g.threshold != 5 {
		t.Fatalf("odd key: group %+v", g)
	}
	for _, sh := range g.shares {
		if want := uint64((sh.node+1)%6 + 1); sh.index != want {
			t.Fatalf("odd key, signer %d: index %d, want %d", sh.node, sh.index, want)
		}
	}
	if _, err := signWith(t, s, odd.pk); err != nil {
		t.Fatal(err)
	}
	if g, ok := s.keys.lookup(all.pk); !ok || g.threshold != 6 {
		t.Fatalf("6 of 6 key: group %+v", g)
	}
	if _, ok := s.keys.lookup(bad.pk); ok {
		t.Fatal("the key with a foreign share is served")
	}
	if g, ok := s.keys.lookup(w.pk); !ok || g.threshold != 1 {
		t.Fatalf("whole key: group %+v", g)
	}
	if _, err := signWith(t, s, w.pk); err != nil {
		t.Fatal(err)
	}
}

// A whole key signs, and its mode reads, while a refresh derives the
// group of a new key.
func TestRefreshDoesNotBlockSigning(t *testing.T) {
	k2, w := splitKey(t, 2, 3), splitKey(t, 1, 1)
	fakes := append(cluster(nil, 3), cluster([]*testKey{w}, 1)...)
	setRoot(fakes)
	s := newTestSigners(t, fakes)
	for i, f := range fakes[:3] {
		f.set(func(f *fakeRunner) {
			f.keys = append(f.keys, proto.ValidatorKey{Pubkey: proto.Pubkey(k2.pk), SharePubkey: proto.Pubkey(pubOf(&k2.shares[i])), Index: proto.IndexUnknown})
			f.secret[proto.Pubkey(k2.pk)] = &k2.shares[i]
		})
	}
	entered, release := make(chan struct{}), make(chan struct{})
	s.derive = func(pk phase0.BLSPubKey, shares []share, maxIndex int, guesses ...guess) (group, error) {
		close(entered)
		<-release

		return deriveGroup(pk, shares, maxIndex, guesses...)
	}
	done := make(chan error, 1)
	go func() {
		_, err := s.Refresh(context.Background())
		done <- err
	}()
	<-entered
	signed := make(chan error, 1)
	go func() {
		s.DVShare(context.Background(), w.pk)
		_, err := signWith(t, s, w.pk)
		signed <- err
	}()
	select {
	case err := <-signed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("the whole key waits for the refresh")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := signWith(t, s, k2.pk); err != nil {
		t.Fatal(err)
	}
}

// A load whose context ends while it derives fails, keeps the old list,
// and keeps the groups derived by then: the next load derives only the
// rest.
func TestKeyLoadStopsAtContextEnd(t *testing.T) {
	keys := make([]*testKey, 40)
	for i := range keys {
		keys[i] = splitKey(t, 2, 3)
	}
	fakes := cluster(keys, 3)
	s := newSigners(names(len(fakes)), runners(fakes), 0, 2*time.Second, discard())
	ctx, cancel := context.WithCancel(context.Background())
	s.derive = func(pk phase0.BLSPubKey, shares []share, maxIndex int, guesses ...guess) (group, error) {
		cancel()

		return deriveGroup(pk, shares, maxIndex, guesses...)
	}
	if _, err := s.Refresh(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if s.keys.size() != 0 {
		t.Fatal("keys served from a failed load")
	}
	s.mu.Lock()
	kept := len(s.derived)
	s.mu.Unlock()
	if kept == 0 || kept >= len(keys) {
		t.Fatalf("%d of %d groups kept from the failed load", kept, len(keys))
	}
	n, err := s.Refresh(context.Background())
	if err != nil || n != len(keys) {
		t.Fatalf("%d keys, %v", n, err)
	}
}

// TestKeyLoadTimes logs how long the first load of 1,000 keys takes, with
// the signers in reverse index order. DERIVE_TIMES=1 runs it.
func TestKeyLoadTimes(t *testing.T) {
	if os.Getenv("DERIVE_TIMES") == "" {
		t.Skip("DERIVE_TIMES not set")
	}
	for _, c := range []struct{ t, n int }{{4, 6}, {5, 6}, {6, 8}, {7, 8}} {
		_, fakes := reversed(t, 1000, c.t, c.n)
		s := newSigners(names(len(fakes)), runners(fakes), 0, 10*time.Second, discard())
		start := time.Now()
		if n, err := s.Refresh(context.Background()); err != nil || n != 1000 {
			t.Fatalf("%d keys, %v", n, err)
		}
		t.Logf("1000 keys of %d of %d: %s", c.t, c.n, time.Since(start))
	}
	// 1,000 keys and 8 with a foreign share: the 1,000 are served first.
	for _, c := range []struct{ t, n int }{{5, 6}, {7, 8}} {
		_, fakes := reversed(t, 1000, c.t, c.n)
		for range 8 {
			bad, other := splitKey(t, c.t, c.n), splitKey(t, c.t, c.n)
			for i, f := range fakes {
				from := bad
				if i == 0 {
					from = other
				}
				f.keys = append(f.keys, proto.ValidatorKey{Pubkey: proto.Pubkey(bad.pk), SharePubkey: proto.Pubkey(pubOf(&from.shares[i])), Index: proto.IndexUnknown})
			}
		}
		s := newSigners(names(len(fakes)), runners(fakes), 0, 10*time.Second, discard())
		start := time.Now()
		if n, err := s.Refresh(context.Background()); err != nil || n != 1000 {
			t.Fatalf("%d keys, %v", n, err)
		}
		served := time.Since(start)
		searched(t, s)
		t.Logf("1000 keys of %d of %d and 8 with a foreign share: served in %s, all searched in %s", c.t, c.n, served, time.Since(start))
	}
}

// The integer check of fit.interpolates gives the same answer as
// recoverPubkey compared with the key, for right, wrong and swapped
// indices and for foreign shares.
func TestInterpolatesMatchesRecoverPubkey(t *testing.T) {
	for range 40 {
		n := 2 + randInt(t, 7) // 2 to 8
		th := 1 + randInt(t, n)
		k, other := splitKey(t, th, n), splitKey(t, th, n)
		sh := shareList(k)
		if randScalar(t).Bit(0) == 1 {
			x := randInt(t, n)
			sh[x].pub = pubOf(&other.shares[x])
		}
		f, ok := newFit(k.pk, sh)
		if !ok {
			t.Fatal("decode")
		}
		for range 50 {
			m := 1 + randInt(t, n)
			pos := make([]int, m)
			idx := make([]uint64, m)
			perm := randPerm(t, n)
			for i := range pos {
				pos[i] = perm[i]
				idx[i] = uint64(perm[i] + 1)
			}
			if randScalar(t).Bit(0) == 1 { // other indices from 1 to 8
				p := randPerm(t, maxShareIndex)
				for i := range idx {
					idx[i] = uint64(p[i] + 1)
				}
			}
			keys := make([]phase0.BLSPubKey, m)
			for i, p := range pos {
				keys[i] = sh[p].pub
			}
			got, err := recoverPubkey(idx, keys)
			want := err == nil && got == k.pk
			if f.interpolates(pos, idx) != want {
				t.Fatalf("%d of %d, shares %v, indices %v: interpolates %v, recoverPubkey %v",
					th, n, pos, idx, !want, want)
			}
		}
	}
}

// randInt is a random int from 0 to n-1.
func randInt(t *testing.T, n int) int {
	t.Helper()

	return int(new(big.Int).Mod(randScalar(t), big.NewInt(int64(n))).Int64())
}

// randPerm is a random order of 0 to n-1.
func randPerm(t *testing.T, n int) []int {
	t.Helper()
	p := make([]int, n)
	for i := range p {
		p[i] = i
	}
	for i := n - 1; i > 0; i-- {
		j := randInt(t, i+1)
		p[i], p[j] = p[j], p[i]
	}

	return p
}

// Share keys P and 2P interpolate with indices 1 and 2 to the point at
// infinity; a key listed at infinity is refused. So is a whole key at
// infinity on a single-mode signer: no signature verifies under it.
func TestDeriveGroupRefusesKeyAtInfinity(t *testing.T) {
	a := randScalar(t)
	twice := new(big.Int).Lsh(a, 1)
	twice.Mod(twice, groupR)
	var inf phase0.BLSPubKey
	inf[0] = 0xc0
	sh := []share{{node: 0, pub: pubOf(blstKey(a))}, {node: 1, pub: pubOf(blstKey(twice))}}
	if g, err := deriveGroup(inf, sh, 2); err == nil {
		t.Fatalf("served %+v", g)
	}
	if g, err := deriveGroup(inf, []share{{node: 0, pub: inf}}, 1); err == nil {
		t.Fatalf("whole key at infinity served: %+v", g)
	}
}

// searched waits until no key waits for its search and no load runs.
func searched(t *testing.T, s *Signers) {
	t.Helper()
	for deadline := time.Now().Add(time.Minute); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		s.mu.Lock()
		waiting := len(s.deferred)
		s.mu.Unlock()
		if waiting == 0 && len(s.keys.loading) == 0 {
			return
		}
	}
	t.Fatal("keys still wait for their search")
}

// A key that no guess fits waits for a load of its own: the load that
// finds it serves the keys that fit a guess, and the key with a foreign
// share is searched after, once.
func TestKeyLoadServesGoodKeysFirst(t *testing.T) {
	keys := make([]*testKey, 20)
	for i := range keys {
		keys[i] = splitKey(t, 5, 6)
	}
	fakes := cluster(keys[:10], 6)
	setRoot(fakes)
	s := newTestSigners(t, fakes)
	bad, other := splitKey(t, 5, 6), splitKey(t, 5, 6)
	for i, f := range fakes {
		f.set(func(f *fakeRunner) {
			for _, k := range keys[10:] {
				f.keys = append(f.keys, proto.ValidatorKey{Pubkey: proto.Pubkey(k.pk), SharePubkey: proto.Pubkey(pubOf(&k.shares[i])), Index: proto.IndexUnknown})
				f.secret[proto.Pubkey(k.pk)] = &k.shares[i]
			}
			from := bad
			if i == 5 {
				from = other
			}
			f.keys = append(f.keys, proto.ValidatorKey{Pubkey: proto.Pubkey(bad.pk), SharePubkey: proto.Pubkey(pubOf(&from.shares[i])), Index: proto.IndexUnknown})
		})
	}
	release := make(chan struct{})
	var calls atomic.Int64
	s.derive = func(pk phase0.BLSPubKey, shares []share, maxIndex int, guesses ...guess) (group, error) {
		if pk == bad.pk {
			calls.Add(1)
			<-release
		}

		return deriveGroup(pk, shares, maxIndex, guesses...)
	}
	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, err := s.Refresh(context.Background())
		done <- result{n, err}
	}()
	select {
	case r := <-done:
		if r.err != nil || r.n != 20 {
			close(release)
			t.Fatalf("%d keys, %v", r.n, r.err)
		}
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("the load waits for the search of the key with a foreign share")
	}
	if _, err := signWith(t, s, keys[15].pk); err != nil {
		t.Fatal(err)
	}
	close(release)
	searched(t, s)
	if _, ok := s.keys.lookup(bad.pk); ok {
		t.Fatal("the key with a foreign share is served")
	}
	if _, err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("the key with a foreign share searched %d times", got)
	}
}

// sharesAt is share x_i of k on signer i: the key split with index x_i
// on signer i.
func sharesAt(k *testKey, x ...uint64) []share {
	sh := make([]share, len(x))
	for i, xi := range x {
		sh[i] = share{node: i, pub: pubOf(&k.shares[xi-1])}
	}

	return sh
}

// Honest shares of a t-of-n split also fit n-of-n at other indices, or at
// a multiple of those. A guess with such indices must not serve the key
// as n-of-n: deriveGroup ends at the real threshold.
func TestDeriveGroupNOfNGuessKeepsTheRealThreshold(t *testing.T) {
	for _, c := range []struct {
		name     string
		t, n     int
		maxIndex int
		real     []uint64 // the index of the split on each signer
		guess    []uint64 // n-of-n indices that every share fits
	}{
		{"3 of 4", 3, 4, 4, []uint64{3, 2, 1, 4}, []uint64{1, 2, 3, 4}},
		{"3 of 4, guess at twice the indices", 3, 4, 8, []uint64{3, 2, 1, 4}, []uint64{2, 4, 6, 8}},
		{"3 of 4, guess at twice the real indices", 3, 4, 8, []uint64{3, 2, 1, 4}, []uint64{6, 4, 2, 8}},
		{"5 of 6", 5, 6, 6, []uint64{1, 2, 3, 4, 5, 6}, []uint64{5, 4, 3, 2, 1, 6}},
		{"4 of 6", 4, 6, 6, []uint64{1, 2, 3, 4, 5, 6}, []uint64{1, 4, 3, 2, 5, 6}},
	} {
		t.Run(c.name, func(t *testing.T) {
			k := splitKey(t, c.t, c.n)
			sh := sharesAt(k, c.real...)
			f, ok := newFit(k.pk, sh)
			if !ok || !f.everySubset(c.guess, c.n) {
				t.Fatalf("the shares do not fit %d of %d at %v", c.n, c.n, c.guess)
			}
			got, err := deriveGroup(k.pk, sh, c.maxIndex, guess{threshold: c.n, index: c.guess})
			if err != nil || got.threshold != c.t {
				t.Fatalf("group %+v, %v; want threshold %d", got, err, c.t)
			}
			idx := make([]uint64, len(got.shares))
			for i, s := range got.shares {
				idx[i] = s.index
			}
			if !f.everySubset(idx, c.t) {
				t.Fatalf("indices %v do not fit %d of %d", idx, c.t, c.n)
			}
		})
	}
}

// A 4-of-6 guess on a 4-of-5 key held by 5 of those signers: the key is
// served 4 of 5 with indices that fit, whether they are the indices of
// the guess or not.
func TestDeriveGroupGuessOfALargerSplit(t *testing.T) {
	g6 := []uint64{2, 3, 4, 5, 6} // the 4-of-6 indices of signers 2 to 6
	for _, real := range [][]uint64{{2, 3, 4, 5, 6}, {1, 2, 3, 4, 5}, {5, 4, 3, 2, 1}} {
		k := splitKey(t, 4, 6)
		sh := sharesAt(k, real...)
		got, err := deriveGroup(k.pk, sh, 6, guess{threshold: 4, index: g6})
		if err != nil || got.threshold != 4 {
			t.Fatalf("real %v: group %+v, %v", real, got, err)
		}
		f, _ := newFit(k.pk, sh)
		idx := make([]uint64, len(got.shares))
		for i, s := range got.shares {
			idx[i] = s.index
		}
		if !f.everySubset(idx, 4) || f.everySubset(idx, 3) {
			t.Fatalf("real %v: indices %v do not fit 4 of 5", real, idx)
		}
	}
}

// Through the load: a 6-of-6 key at 1 to 6 first, then a 5-of-6 key at
// 5,4,3,2,1,6 on the same signers, whose shares also fit 6 of 6 at 1 to
// 6. The second is served 5 of 6 and signs with one signer down.
func TestKeyLoadNOfNGuessKeepsTheRealThreshold(t *testing.T) {
	all := splitKey(t, 6, 6)
	fakes := cluster([]*testKey{all}, 6)
	setRoot(fakes)
	s := newTestSigners(t, fakes)
	defer s.Close()
	if g, ok := s.keys.lookup(all.pk); !ok || g.threshold != 6 {
		t.Fatalf("6 of 6 key: group %+v", g)
	}
	k := splitKey(t, 5, 6)
	x := []int{5, 4, 3, 2, 1, 6}
	for i, f := range fakes {
		f.set(func(f *fakeRunner) {
			f.keys = append(f.keys, proto.ValidatorKey{Pubkey: proto.Pubkey(k.pk), SharePubkey: proto.Pubkey(pubOf(&k.shares[x[i]-1])), Index: proto.IndexUnknown})
			f.secret[proto.Pubkey(k.pk)] = &k.shares[x[i]-1]
		})
	}
	if _, err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	searched(t, s)
	if g, ok := s.keys.lookup(k.pk); !ok || g.threshold != 5 {
		t.Fatalf("5 of 6 key: group %+v", g)
	}
	fakes[5].set(func(f *fakeRunner) { f.err = errors.New("down") })
	if _, err := signWith(t, s, k.pk); err != nil {
		t.Fatal(err)
	}
}

// churnRunner lists one more key than its fakeRunner, with a new random
// share key at each PUBLIC_KEYS.
type churnRunner struct {
	*fakeRunner
	pk  phase0.BLSPubKey
	off atomic.Bool // lists no share of pk while set
}

func (c *churnRunner) PublicKeys(ctx context.Context) ([]proto.ValidatorKey, error) {
	keys, err := c.fakeRunner.PublicKeys(ctx)
	if err != nil || c.off.Load() {
		return keys, err
	}
	x, err := crand.Int(crand.Reader, groupR)
	if err != nil || x.Sign() == 0 {
		return nil, errors.New("no random share")
	}

	return append(keys, proto.ValidatorKey{Pubkey: proto.Pubkey(c.pk), SharePubkey: proto.Pubkey(pubOf(blstKey(x))), Index: proto.IndexUnknown}), nil
}

// followUpFails is a signer that lists no key in a follow-up load while
// fail is set, so that load fails (the signers hold no key the gateway
// can sign for); calls counts those answers. A signer that does not
// answer would not do: the load keeps its last list.
type followUpFails struct {
	runner
	fail  *atomic.Bool
	calls *atomic.Int64
}

func (f followUpFails) PublicKeys(ctx context.Context) ([]proto.ValidatorKey, error) {
	if f.fail.Load() && ctx.Value(followUpKey{}) != nil {
		f.calls.Add(1)

		return nil, nil
	}

	return f.runner.PublicKeys(ctx)
}

// churnCluster is 3 signers with two 2-of-3 keys. Once the churn starts,
// the first signer lists a new share key of a third key at every
// PUBLIC_KEYS, and the other two the real shares of that key. The first
// load runs before the churn starts, so the two good keys give the guess
// that the churning key then fails. searches counts the full searches of
// the churning key. wrap, if not nil, wraps each runner.
func churnCluster(t *testing.T, maxAge time.Duration, log *slog.Logger, wrap func(runner) runner) (s *Signers, good []*testKey, churn *churnRunner, fakes []*fakeRunner, searches *atomic.Int64) {
	t.Helper()
	good = []*testKey{splitKey(t, 2, 3), splitKey(t, 2, 3)}
	extra := splitKey(t, 2, 3)
	fakes = cluster(good, 3)
	churn = &churnRunner{fakeRunner: fakes[0], pk: extra.pk}
	churn.off.Store(true)
	rs := []runner{churn, fakes[1], fakes[2]}
	if wrap != nil {
		for i := range rs {
			rs[i] = wrap(rs[i])
		}
	}
	s = newSigners(names(3), rs, 0, 2*time.Second, log)
	t.Cleanup(func() { s.Close() })
	s.keys.maxAge = maxAge
	searches = new(atomic.Int64)
	s.derive = func(pk phase0.BLSPubKey, shares []share, maxIndex int, guesses ...guess) (group, error) {
		if pk == extra.pk {
			searches.Add(1)
		}

		return deriveGroup(pk, shares, maxIndex, guesses...)
	}
	if _, err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i, f := range fakes[1:] {
		f.set(func(f *fakeRunner) {
			f.keys = append(f.keys, proto.ValidatorKey{Pubkey: proto.Pubkey(extra.pk), SharePubkey: proto.Pubkey(pubOf(&extra.shares[i+1])), Index: proto.IndexUnknown})
		})
	}
	churn.off.Store(false)

	return s, good, churn, fakes, searches
}

// refusals is the number of "key refused" lines that name pk.
func refusals(log string, pk phase0.BLSPubKey) int {
	n := 0
	for _, l := range strings.Split(log, "\n") {
		if strings.Contains(l, "key refused") && strings.Contains(l, fmt.Sprintf("%#x", pk)) {
			n++
		}
	}

	return n
}

// A signer that lists a new share key for one key at every PUBLIC_KEYS
// keeps that key waiting for its search at every load. The loads stay
// bounded: the load that finds the key defers it, the follow-up load
// searches it and refuses it, once, and starts no other load.
func TestKeyLoadChurnIsBounded(t *testing.T) {
	var log syncBuilder
	s, good, churn, fakes, _ := churnCluster(t, keysMaxAge, slog.New(slog.NewTextHandler(&log, nil)), nil)
	from := len(log.String())
	if _, err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	loads := func() int {
		fakes[1].mu.Lock()
		defer fakes[1].mu.Unlock()

		return fakes[1].health
	}
	before := loads()
	time.Sleep(2 * time.Second)
	if n := loads() - before; n > 1 {
		t.Fatalf("%d loads in 2 s after the last refresh; want at most 1", n)
	}
	if n := refusals(log.String()[from:], churn.pk); n != 1 {
		t.Fatalf("%d key refused lines for the churning key; want 1, from the follow-up load:\n%s", n, log.String()[from:])
	}
	for _, k := range good {
		if _, ok := s.keys.lookup(k.pk); !ok {
			t.Fatal("a good key is not served")
		}
	}
}

// Refresh in a loop with a churning signer: every load defers the
// churning key, and each follow-up load searches it once. Follow-up
// loads start at most once per keysMaxAge.
func TestKeyLoadFollowUpsWaitKeysMaxAge(t *testing.T) {
	const maxAge, run = 300 * time.Millisecond, 1500 * time.Millisecond
	s, _, _, _, searches := churnCluster(t, maxAge, discard(), nil)
	for end := time.Now().Add(run); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if _, err := s.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	n := searches.Load()
	if most := int64(run/maxAge) + 1; n < 2 || n > most {
		t.Fatalf("%d follow-up loads in %s with keysMaxAge %s; want 2 to %d", n, run, maxAge, most)
	}
	t.Logf("%d follow-up loads in %s, keysMaxAge %s", n, run, maxAge)
}

// An honest key that fits no guess, next to a churning signer, is served
// by the follow-up load: the churn does not starve it.
func TestKeyLoadServesADeferredKeyNextToChurn(t *testing.T) {
	s, _, _, fakes, _ := churnCluster(t, keysMaxAge, discard(), nil)
	setRoot(fakes)
	// Signers 1, 2, 3 hold the shares at indices 3, 1, 2: the indices of
	// the good keys do not fit, so the key waits for the follow-up load.
	odd := splitKey(t, 2, 3)
	for i, x := range []int{2, 0, 1} {
		fakes[i].set(func(f *fakeRunner) {
			f.keys = append(f.keys, proto.ValidatorKey{Pubkey: proto.Pubkey(odd.pk), SharePubkey: proto.Pubkey(pubOf(&odd.shares[x])), Index: proto.IndexUnknown})
			f.secret[proto.Pubkey(odd.pk)] = &odd.shares[x]
		})
	}
	if _, err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if g, ok := s.keys.lookup(odd.pk); ok {
			if g.threshold != 2 {
				t.Fatalf("group %+v", g)
			}

			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the key that fits no guess is not served after the follow-up load")
		}
	}
	if _, err := signWith(t, s, odd.pk); err != nil {
		t.Fatal(err)
	}
}

// A follow-up load that fails (no key is left) leaves no follow-up
// pending for good: the next load that defers a key starts a new one.
func TestKeyLoadFollowUpFailsThenRunsAgain(t *testing.T) {
	const maxAge = 200 * time.Millisecond
	var fail atomic.Bool
	var calls atomic.Int64
	fail.Store(true)
	s, _, _, _, searches := churnCluster(t, maxAge, discard(), func(r runner) runner {
		return followUpFails{runner: r, fail: &fail, calls: &calls}
	})
	if _, err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(10 * time.Second); calls.Load() < 3 || len(s.keys.loading) > 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no follow-up load ran to its end")
		}
	}
	if n := searches.Load(); n != 0 {
		t.Fatalf("the failed follow-up load searched %d times", n)
	}
	fail.Store(false)
	if _, err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(10 * time.Second); searches.Load() == 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no follow-up load after a failed one")
		}
	}
}

// A signer that lists a validator key twice would count as two signers,
// so the gateway refuses the key: an honest 3-of-4 key that signer 4 lists
// again with the share at index 5, and a key whose two shares are both on
// signer 4. The other keys stay served, and the log names the signer.
func TestKeyListedTwiceBySignerRefused(t *testing.T) {
	good, a, line := splitKey(t, 3, 4), splitKey(t, 3, 5), splitKey(t, 2, 2)
	fakes := cluster([]*testKey{good}, 4)
	for i, f := range fakes {
		f.keys = append(f.keys, proto.ValidatorKey{Pubkey: proto.Pubkey(a.pk), SharePubkey: proto.Pubkey(pubOf(&a.shares[i])), Index: proto.IndexUnknown})
		f.secret[proto.Pubkey(a.pk)] = &a.shares[i]
	}
	fakes[3].keys = append(fakes[3].keys,
		proto.ValidatorKey{Pubkey: proto.Pubkey(a.pk), SharePubkey: proto.Pubkey(pubOf(&a.shares[4])), Index: proto.IndexUnknown},
		proto.ValidatorKey{Pubkey: proto.Pubkey(line.pk), SharePubkey: proto.Pubkey(pubOf(&line.shares[0])), Index: proto.IndexUnknown},
		proto.ValidatorKey{Pubkey: proto.Pubkey(line.pk), SharePubkey: proto.Pubkey(pubOf(&line.shares[1])), Index: proto.IndexUnknown})
	setRoot(fakes)
	var log syncBuilder
	s := newSigners(names(4), runners(fakes), 5, 2*time.Second, slog.New(slog.NewTextHandler(&log, nil)))
	defer s.Close()
	if _, err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	searched(t, s)
	if g, ok := s.keys.lookup(a.pk); ok {
		t.Fatalf("the key signer-4 lists twice is served: %+v", g)
	}
	if g, ok := s.keys.lookup(line.pk); ok {
		t.Fatalf("the key with both shares on signer-4 is served: %+v", g)
	}
	if _, err := signWith(t, s, good.pk); err != nil {
		t.Fatal(err)
	}
	for _, k := range []*testKey{a, line} {
		want := fmt.Sprintf("%#x", k.pk)
		found := false
		for _, l := range strings.Split(log.String(), "\n") {
			if strings.Contains(l, "key refused") && strings.Contains(l, want) && strings.Contains(l, "signer-4") {
				found = true
			}
		}
		if !found {
			t.Fatalf("no key refused line names signer-4 for %s:\n%s", want, log.String())
		}
	}
	// The refusal is logged once while the listing stays.
	if _, err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(log.String(), fmt.Sprintf("%#x", line.pk)); n != 1 {
		t.Fatalf("%d log lines name the key with both shares on signer-4; want 1:\n%s", n, log.String())
	}
}
