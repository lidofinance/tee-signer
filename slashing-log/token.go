package markstore

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// A store request uses the cached token until TokenMaxAge; from
// TokenRefreshAfter on, the next request starts a refresh in the background
// and still goes out with the cached token, so no request waits for a token
// exchange (on GCP an attestation token, STS and the service account take
// seconds, against about 0.1 s for the store write itself). These ages assume a token that lasts an hour from the fetch. A
// source that gives the expiry (Azure IMDS) moves both earlier when the
// token expires sooner: IMDS caches tokens and can hand out one with
// minutes left, and writes with it then fail with InvalidAuthenticationInfo.
const (
	TokenRefreshAfter = 30 * time.Minute
	TokenMaxAge       = 50 * time.Minute
	// tokenRefreshBefore: a refresh starts this long before the expiry at
	// the latest.
	tokenRefreshBefore = 10 * time.Minute
	// tokenServeBefore: no request gets a token this close to its expiry;
	// it waits for a fresh one instead.
	tokenServeBefore = 2 * time.Minute
	// tokenShortLived: a fetched token with less than this left is fetched
	// again, tokenShortRetries times, a second apart and then doubling.
	tokenShortLived   = 5 * time.Minute
	tokenShortRetries = 3
	// tokenFetchTimeout bounds a background refresh, which has no request
	// context.
	tokenFetchTimeout = time.Minute
)

// TokenCache reuses a bearer token from a source. A request finds the
// token in one of three states:
//   - fresh: it gets the cached token;
//   - due for a refresh (older than refreshAfter, or within 10 minutes of
//     its expiry): it gets the cached token, and a background refresh
//     starts unless one is running; a failed refresh keeps the old token,
//     and a later request tries again;
//   - none, older than maxAge, within 2 minutes of its expiry, or refused
//     by the store (Invalidate): it waits for a fetch.
//
// Only one fetch runs at a time. A request that waited for another's fetch
// takes its token and fetches nothing.
//
// A source that gives no expiry (zero time) gets the fixed ages only;
// maxAge must then stay below the token's lifetime.
type TokenCache struct {
	fetch                func(ctx context.Context) (string, time.Time, error)
	refreshAfter, maxAge time.Duration
	now                  func() time.Time
	sleep                func(ctx context.Context, d time.Duration) error
	slot                 chan struct{} // held by the one running fetch

	mu         sync.Mutex
	tok        string
	at, exp    time.Time
	refreshing bool
	refused    string // the last token Invalidate dropped
}

// NewTokenCache makes a cache over fetch, which returns a token and its
// expiry (zero: unknown).
func NewTokenCache(fetch func(ctx context.Context) (string, time.Time, error), refreshAfter, maxAge time.Duration) *TokenCache {
	return newTokenCache(fetch, refreshAfter, maxAge, time.Now, sleepCtx)
}

func newTokenCache(fetch func(ctx context.Context) (string, time.Time, error), refreshAfter, maxAge time.Duration,
	now func() time.Time, sleep func(ctx context.Context, d time.Duration) error) *TokenCache {
	return &TokenCache{fetch: fetch, refreshAfter: refreshAfter, maxAge: maxAge, now: now, sleep: sleep, slot: make(chan struct{}, 1)}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// usable: the cached token may go out. Call with mu held.
func (c *TokenCache) usable(now time.Time) bool {
	return c.tok != "" && now.Sub(c.at) < c.maxAge && (c.exp.IsZero() || now.Before(c.exp.Add(-tokenServeBefore)))
}

// due: the cached token wants a refresh. Call with mu held.
func (c *TokenCache) due(now time.Time) bool {
	return now.Sub(c.at) >= c.refreshAfter || (!c.exp.IsZero() && !now.Before(c.exp.Add(-tokenRefreshBefore)))
}

// Token returns a token for a request.
func (c *TokenCache) Token(ctx context.Context) (string, error) {
	if tok, ok := c.cached(); ok {
		return tok, nil
	}
	select {
	case c.slot <- struct{}{}:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	defer func() { <-c.slot }()
	// A fetch that ran while this request waited may have left a token.
	if tok, ok := c.cached(); ok {
		return tok, nil
	}
	c.mu.Lock()
	refused := c.refused
	c.mu.Unlock()
	tok, exp, err := c.get(ctx, refused)
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	c.tok, c.at, c.exp = tok, c.now(), exp
	c.mu.Unlock()
	return tok, nil
}

// cached returns the cached token if it may go out, and starts a
// background refresh when one is due.
func (c *TokenCache) cached() (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if !c.usable(now) {
		return "", false
	}
	if c.due(now) && !c.refreshing {
		c.refreshing = true
		go c.refresh(c.tok)
	}
	return c.tok, true
}

func (c *TokenCache) refresh(old string) {
	ctx, cancel := context.WithTimeout(context.Background(), tokenFetchTimeout)
	defer cancel()
	defer func() {
		c.mu.Lock()
		c.refreshing = false
		c.mu.Unlock()
	}()
	select {
	case c.slot <- struct{}{}:
	case <-ctx.Done():
		return
	}
	defer func() { <-c.slot }()
	c.mu.Lock()
	// A request's fetch replaced the token while this one waited.
	replaced := c.tok != old
	refused := c.refused
	c.mu.Unlock()
	if replaced {
		return
	}
	tok, exp, err := c.get(ctx, refused)
	if err != nil {
		return
	}
	c.mu.Lock()
	c.tok, c.at, c.exp = tok, c.now(), exp
	c.mu.Unlock()
}

// get fetches a token. A token with less than tokenShortLived left, or the
// one the store refused, is fetched again after a short wait; after
// tokenShortRetries the last one is taken unless it is within
// tokenServeBefore of its expiry. Call with the slot held.
func (c *TokenCache) get(ctx context.Context, refused string) (string, time.Time, error) {
	wait := time.Second
	for i := 0; ; i++ {
		tok, exp, err := c.fetch(ctx)
		if err != nil {
			return "", time.Time{}, err
		}
		left := exp.Sub(c.now())
		if tok != refused && (exp.IsZero() || left >= tokenShortLived) {
			return tok, exp, nil
		}
		if i == tokenShortRetries {
			if !exp.IsZero() && left <= tokenServeBefore {
				return "", time.Time{}, fmt.Errorf("markstore: the token source gives a token that expires in %v", left.Round(time.Second))
			}
			return tok, exp, nil
		}
		if err := c.sleep(ctx, wait); err != nil {
			return "", time.Time{}, err
		}
		wait *= 2
	}
}

// Invalidate drops tok if it is still the cached token: the store refused
// it (401). The next request fetches a fresh one, and a source that hands
// out the same token again is asked again after a short wait. A token
// already replaced is left alone, so concurrent requests refused with the
// same token cause one fetch.
func (c *TokenCache) Invalidate(tok string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if tok != "" && c.tok == tok {
		c.tok, c.refused = "", tok
	}
}
