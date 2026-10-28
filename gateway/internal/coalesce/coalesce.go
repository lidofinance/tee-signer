// Package coalesce lets identical signing requests share one signer call.
//
// A request that arrives while the same call is in flight waits for that
// call's result instead of making its own. A request that arrives after the
// call succeeded gets the stored result until it expires. Errors are never
// stored: the next request makes a new call.
//
// Only the types Shareable lists may use this. For them the signers keep no
// state between requests and the BLS signature is deterministic, so the same
// key and signing root always give the same signature: a repeat gets the
// answer the signers already gave, and the gateway gains no signature it did
// not already hold. Slashable types never come here: the signers must see
// every one of them (DESIGN-INVARIANTS.md, rules 3 and 7).
package coalesce

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// shareable lists the Web3Signer request types that may share a result. It is
// an allowlist: a type added later stays out until someone classifies it.
// Attestations, blocks, exits, registrations and the Gloas types are not
// here and never will be.
var shareable = map[string]bool{
	"RANDAO_REVEAL":                         true,
	"AGGREGATION_SLOT":                      true,
	"AGGREGATE_AND_PROOF":                   true,
	"AGGREGATE_AND_PROOF_V2":                true,
	"SYNC_COMMITTEE_MESSAGE":                true,
	"SYNC_COMMITTEE_SELECTION_PROOF":        true,
	"SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF": true,
}

// Shareable reports whether requests of type typ may share a call or a
// stored result.
func Shareable(typ string) bool { return shareable[typ] }

// Key names one signature: the validator key, the signing root the gateway
// computed from the full message, and the request type. Aggregates and
// contributions carry content that varies, so only exact repeats (same
// root) share.
type Key struct {
	Pubkey phase0.BLSPubKey
	Root   phase0.Root
	Type   string
}

// How says where a request's answer came from.
type How int

const (
	// Called: this request made the signer call.
	Called How = iota
	// Coalesced: it waited for a call an identical request had started.
	Coalesced
	// Cached: it got the stored result of a finished call.
	Cached
)

// Group holds the calls in flight and the stored results.
type Group[V any] struct {
	ttl     time.Duration
	timeout time.Duration
	now     func() time.Time

	mu        sync.Mutex
	calls     map[Key]*call[V]
	nextSweep time.Time
}

type call[V any] struct {
	done chan struct{}
	// val and err are written once, before done closes.
	val V
	err error
	// finished, expires and joined are guarded by Group.mu. A finished call
	// stays in the map only if it succeeded, until expires. joined counts
	// the requests that waited for the call (tests read it).
	finished bool
	expires  time.Time
	joined   int
}

// New makes a Group. ttl is how long a successful result stays stored (0
// stores nothing, so only calls in flight are shared). timeout bounds each
// shared call.
func New[V any](ttl, timeout time.Duration) *Group[V] {
	return &Group[V]{ttl: ttl, timeout: timeout, now: time.Now, calls: map[Key]*call[V]{}}
}

// Do returns the result for k: a stored one, the one of a call in flight, or
// that of a new call to fn. The call runs on its own context with the
// Group's timeout, so a request whose client hangs up does not fail the
// others that wait for the same call. A request whose own ctx ends first
// returns ctx's error and leaves the call running.
func (g *Group[V]) Do(ctx context.Context, k Key, fn func(context.Context) (V, error)) (V, How, error) {
	now := g.now()
	g.mu.Lock()
	g.sweep(now)
	if c, ok := g.calls[k]; ok {
		if !c.finished {
			c.joined++
			g.mu.Unlock()

			return wait(ctx, c, Coalesced)
		}
		if now.Before(c.expires) {
			v := c.val
			g.mu.Unlock()

			return v, Cached, nil
		}
	}
	c := &call[V]{done: make(chan struct{})}
	g.calls[k] = c
	g.mu.Unlock()

	go g.run(context.WithoutCancel(ctx), k, c, fn)

	return wait(ctx, c, Called)
}

func wait[V any](ctx context.Context, c *call[V], how How) (V, How, error) {
	select {
	case <-c.done:
		return c.val, how, c.err
	case <-ctx.Done():
		var zero V

		return zero, how, ctx.Err()
	}
}

func (g *Group[V]) run(ctx context.Context, k Key, c *call[V], fn func(context.Context) (V, error)) {
	ctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()
	v, err := protect(ctx, fn)

	g.mu.Lock()
	c.val, c.err, c.finished = v, err, true
	if err == nil && g.ttl > 0 {
		c.expires = g.now().Add(g.ttl)
	} else if g.calls[k] == c {
		delete(g.calls, k)
	}
	g.mu.Unlock()
	close(c.done)
}

// protect turns a panic in fn into an error. The call runs on its own
// goroutine, where net/http's recovery of handler panics does not reach.
func protect[V any](ctx context.Context, fn func(context.Context) (V, error)) (v V, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("coalesce: signer call panicked: %v", p)
		}
	}()

	return fn(ctx)
}

// sweep drops expired results, at most once per ttl. Called with g.mu held.
func (g *Group[V]) sweep(now time.Time) {
	if g.ttl <= 0 || now.Before(g.nextSweep) {
		return
	}
	for k, c := range g.calls {
		if c.finished && !now.Before(c.expires) {
			delete(g.calls, k)
		}
	}
	g.nextSweep = now.Add(g.ttl)
}

// size is the number of calls in flight plus stored results, for tests.
func (g *Group[V]) size() int {
	g.mu.Lock()
	defer g.mu.Unlock()

	return len(g.calls)
}

// joinedCall is the number of requests that waited for k's call while it was
// in flight, for tests.
func (g *Group[V]) joinedCall(k Key) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	if c, ok := g.calls[k]; ok {
		return c.joined
	}

	return 0
}
