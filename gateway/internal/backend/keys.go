package backend

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// maxShareIndex bounds the share indices the gateway tries.
const maxShareIndex = 64

// share is one signer's share of a validator key.
type share struct {
	node  int              // position of the signer in the configuration
	pub   phase0.BLSPubKey // share public key, from the signer's PUBLIC_KEYS
	index uint64           // share index (x coordinate), from deriveGroup
}

// group is a validator key's shares and the number of partial signatures
// that make its signature.
type group struct {
	threshold int
	shares    []share
}

// deriveGroup finds the share index of each share and the threshold from
// the public keys alone: the smallest t, and distinct indices from 1 to
// maxIndex, for which every t of the share keys interpolate to the
// validator key pk. That is the split the shares come from, so partial
// signatures of any t of them combine with those indices into pk's
// signature. A key that fits no t and no indices is refused: its
// signatures would never combine. t = 1 means every share is pk itself.
//
// The search tries the indices in increasing order, so signers listed in
// the order of their indices match at the first try.
func deriveGroup(pk phase0.BLSPubKey, shares []share, maxIndex int) (group, error) {
	k := len(shares)
	if k == 0 {
		return group{}, errors.New("no share")
	}
	if maxIndex < k {
		return group{}, fmt.Errorf("%d shares, but share indices go to %d only", k, maxIndex)
	}
	out := append([]share(nil), shares...)
	whole := true
	for _, s := range shares {
		whole = whole && s.pub == pk
	}
	if whole {
		for i := range out {
			out[i].index = uint64(i + 1)
		}

		return group{threshold: 1, shares: out}, nil
	}
	idx := make([]uint64, k)
	used := make([]bool, maxIndex+1)
	for t := 2; t <= k; t++ {
		var try func(i int) bool
		try = func(i int) bool {
			// The first t shares decide most wrong indices at once.
			if i == t && !interpolates(pk, shares[:t], idx[:t]) {
				return false
			}
			if i == k {
				return everySubset(pk, shares, idx, t)
			}
			for x := 1; x <= maxIndex; x++ {
				if used[x] {
					continue
				}
				used[x], idx[i] = true, uint64(x)
				if try(i + 1) {
					return true
				}
				used[x] = false
			}

			return false
		}
		if try(0) {
			for i := range out {
				out[i].index = idx[i]
			}

			return group{threshold: t, shares: out}, nil
		}
		clear(used)
	}

	return group{}, fmt.Errorf("no threshold up to %d and no share indices 1 to %d make the %d share keys interpolate to the key", k, maxIndex, k)
}

// interpolates reports whether the share keys with these indices give pk.
func interpolates(pk phase0.BLSPubKey, shares []share, idx []uint64) bool {
	keys := make([]phase0.BLSPubKey, len(shares))
	for i, s := range shares {
		keys[i] = s.pub
	}
	got, err := recoverPubkey(idx, keys)

	return err == nil && got == pk
}

// everySubset reports whether every t of the shares interpolate to pk.
func everySubset(pk phase0.BLSPubKey, shares []share, idx []uint64, t int) bool {
	pick := make([]int, t)
	var walk func(from, depth int) bool
	walk = func(from, depth int) bool {
		if depth == t {
			s, x := make([]share, t), make([]uint64, t)
			for i, p := range pick {
				s[i], x[i] = shares[p], idx[p]
			}

			return interpolates(pk, s, x)
		}
		for p := from; p <= len(shares)-(t-depth); p++ {
			pick[depth] = p
			if !walk(p+1, depth+1) {
				return false
			}
		}

		return true
	}

	return walk(0, 0)
}

// keyList is the gateway's list of keys. A reader that finds it older
// than maxAge loads it again first, so keys the signers get after the
// gateway started show up without a restart. One load runs at a time;
// readers that arrive during a load wait for it and use its result. A
// failed load keeps the old list, and the next try waits maxAge again, so
// signers that are down, or unknown keys in sign requests, cause at most
// one load per maxAge.
type keyList struct {
	load   func(context.Context) (map[phase0.BLSPubKey]group, error)
	maxAge time.Duration
	now    func() time.Time
	log    *slog.Logger

	loading chan struct{} // holds a token while a load runs

	mu    sync.RWMutex
	keys  map[phase0.BLSPubKey]group
	tried time.Time // end of the last load, whatever its result
}

func newKeyList(load func(context.Context) (map[phase0.BLSPubKey]group, error), maxAge time.Duration, log *slog.Logger) *keyList {
	return &keyList{load: load, maxAge: maxAge, now: time.Now, log: log, loading: make(chan struct{}, 1)}
}

// reload loads the list now, after a load that is running ends.
func (l *keyList) reload(ctx context.Context) (int, error) {
	select {
	case l.loading <- struct{}{}:
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	defer func() { <-l.loading }()

	return l.loadLocked(ctx)
}

// fresh loads the list when it is older than maxAge. A reader whose request
// ends while it waits for a running load goes on with the list as it is.
func (l *keyList) fresh(ctx context.Context) {
	if !l.stale() {
		return
	}
	select {
	case l.loading <- struct{}{}:
	case <-ctx.Done():
		return
	}
	defer func() { <-l.loading }()
	if !l.stale() {
		return // the load this reader waited for was enough
	}
	// The load serves every waiting reader, so it does not end with the
	// request that started it. Each signer call has its own timeout.
	if _, err := l.loadLocked(context.WithoutCancel(ctx)); err != nil {
		l.log.Warn("key refresh failed; keeping the current list", "keys", l.size(), "err", err.Error())
	}
}

// loadLocked runs the load and logs the keys it adds or drops; the caller
// holds the loading token.
func (l *keyList) loadLocked(ctx context.Context) (int, error) {
	keys, err := l.load(ctx)
	if err != nil {
		l.mu.Lock()
		l.tried = l.now()
		l.mu.Unlock()

		return 0, err
	}
	// Only the holder of the loading token writes l.keys, so it reads the
	// old list without the lock.
	old := l.keys
	added, removed := 0, 0
	for k, g := range keys {
		if _, ok := old[k]; !ok {
			added++
			l.log.Info("key", "pubkey", fmt.Sprintf("%#x", k), "threshold", g.threshold, "shares", len(g.shares))
		}
	}
	for k := range old {
		if _, ok := keys[k]; !ok {
			removed++
			l.log.Info("key gone", "pubkey", fmt.Sprintf("%#x", k))
		}
	}
	l.mu.Lock()
	l.keys = keys
	l.tried = l.now()
	l.mu.Unlock()
	if old != nil && added+removed > 0 {
		l.log.Info("keys changed", "count", len(keys), "added", added, "removed", removed)
	}

	return len(keys), nil
}

func (l *keyList) stale() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()

	return l.now().Sub(l.tried) > l.maxAge
}

func (l *keyList) size() int {
	l.mu.RLock()
	defer l.mu.RUnlock()

	return len(l.keys)
}

// list returns the validator keys in byte order, after loading the list if
// it is older than maxAge.
func (l *keyList) list(ctx context.Context) []phase0.BLSPubKey {
	l.fresh(ctx)
	l.mu.RLock()
	keys := make([]phase0.BLSPubKey, 0, len(l.keys))
	for k := range l.keys {
		keys = append(keys, k)
	}
	l.mu.RUnlock()
	sort.Slice(keys, func(i, j int) bool { return string(keys[i][:]) < string(keys[j][:]) })

	return keys
}

// get finds the group of pubkey. A key the list lacks may be one the
// signers got since the last load: when the list is older than maxAge,
// get loads it and looks again.
func (l *keyList) get(ctx context.Context, pubkey phase0.BLSPubKey) (group, bool) {
	if g, ok := l.lookup(pubkey); ok {
		return g, true
	}
	l.fresh(ctx)

	return l.lookup(pubkey)
}

func (l *keyList) lookup(pubkey phase0.BLSPubKey) (group, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	g, ok := l.keys[pubkey]

	return g, ok
}
