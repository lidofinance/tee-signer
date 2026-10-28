package markstore

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock is a clock the tests move by hand. A cache's sleep moves it
// too.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func (c *fakeClock) sleep(ctx context.Context, d time.Duration) error {
	c.add(d)
	return ctx.Err()
}

// fakeSource counts fetches and can block or fail them. lifetime > 0 gives
// each token that expiry from the fake clock. A token in queue goes out
// first, with its own expiry.
type fakeSource struct {
	clock    *fakeClock
	mu       sync.Mutex
	n        int
	fail     bool
	gate     chan struct{} // non-nil: a fetch waits for a value
	token    string
	lifetime time.Duration
	queue    []queued
	running  atomic.Int32
	overlap  atomic.Bool // two fetches ran at once
}

type queued struct {
	token string
	left  time.Duration
}

func (s *fakeSource) fetch(ctx context.Context) (string, time.Time, error) {
	if s.running.Add(1) > 1 {
		s.overlap.Store(true)
	}
	defer s.running.Add(-1)
	s.mu.Lock()
	gate := s.gate
	s.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return "", time.Time{}, ctx.Err()
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	if s.fail {
		return "", time.Time{}, errors.New("token endpoint down")
	}
	if len(s.queue) > 0 {
		q := s.queue[0]
		s.queue = s.queue[1:]
		return q.token, s.clock.now().Add(q.left), nil
	}
	var exp time.Time
	if s.lifetime > 0 {
		exp = s.clock.now().Add(s.lifetime)
	}
	return s.token, exp, nil
}

func (s *fakeSource) set(f func(s *fakeSource)) {
	s.mu.Lock()
	f(s)
	s.mu.Unlock()
}

func (s *fakeSource) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n
}

// waitCount waits until the source has made n fetches (a background
// refresh runs in its own goroutine).
func waitCount(t *testing.T, s *fakeSource, n int) {
	t.Helper()
	for i := 0; i < 400 && s.count() < n; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if got := s.count(); got != n {
		t.Fatalf("fetches = %d, want %d", got, n)
	}
}

// waitToken waits until the cache hands out want (after a background
// refresh).
func waitToken(t *testing.T, c *TokenCache, want string) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if tok, _ := c.Token(context.Background()); tok == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("the cache never handed out %q", want)
}

func newTestCache(src *fakeSource) *TokenCache {
	return newTokenCache(src.fetch, 30*time.Minute, 50*time.Minute, src.clock.now, src.clock.sleep)
}

func TestTokenCacheRefreshesInBackground(t *testing.T) {
	clk := &fakeClock{}
	src := &fakeSource{clock: clk, token: "t1"}
	c := newTestCache(src)
	ctx := context.Background()

	if tok, err := c.Token(ctx); err != nil || tok != "t1" || src.count() != 1 {
		t.Fatalf("first request: %q %v, %d fetches", tok, err, src.count())
	}
	// Younger than refreshAfter: cached, no fetch.
	clk.add(29 * time.Minute)
	if tok, _ := c.Token(ctx); tok != "t1" || src.count() != 1 {
		t.Fatalf("at 29 min: %q, %d fetches", tok, src.count())
	}
	// Past refreshAfter: the request gets the cached token at once, even
	// while the refresh is blocked, and only one refresh runs.
	gate := make(chan struct{})
	src.set(func(s *fakeSource) { s.gate, s.token = gate, "t2" })
	clk.add(2 * time.Minute)
	for i := 0; i < 3; i++ {
		if tok, err := c.Token(ctx); err != nil || tok != "t1" {
			t.Fatalf("during the refresh: %q %v", tok, err)
		}
	}
	close(gate)
	waitCount(t, src, 2)
	src.set(func(s *fakeSource) { s.gate = nil })
	waitToken(t, c, "t2")
	if src.count() != 2 {
		t.Fatalf("after the refresh: %d fetches", src.count())
	}
}

func TestTokenCacheKeepsTheOldTokenWhenARefreshFails(t *testing.T) {
	clk := &fakeClock{}
	src := &fakeSource{clock: clk, token: "t1"}
	c := newTestCache(src)
	ctx := context.Background()
	if _, err := c.Token(ctx); err != nil {
		t.Fatal(err)
	}
	src.set(func(s *fakeSource) { s.fail = true })
	clk.add(40 * time.Minute)
	if tok, err := c.Token(ctx); err != nil || tok != "t1" {
		t.Fatalf("refresh window: %q %v", tok, err)
	}
	waitCount(t, src, 2)
	// The failed refresh left the old token; a later request tries again.
	for i := 0; i < 400 && src.count() < 3; i++ {
		if tok, err := c.Token(ctx); err != nil || tok != "t1" {
			t.Fatalf("after a failed refresh: %q %v", tok, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	waitCount(t, src, 3)
	// Past maxAge the request waits for the source and sees its error.
	clk.add(11 * time.Minute)
	if _, err := c.Token(ctx); err == nil {
		t.Fatal("past maxAge with the source down: want the error")
	}
	src.set(func(s *fakeSource) { s.fail, s.token = false, "t3" })
	if tok, err := c.Token(ctx); err != nil || tok != "t3" {
		t.Fatalf("past maxAge, source back: %q %v", tok, err)
	}
}

func TestTokenCacheFetchesWhenEmptyOrTooOld(t *testing.T) {
	clk := &fakeClock{}
	src := &fakeSource{clock: clk, token: "t1"}
	c := newTestCache(src)
	ctx := context.Background()
	if _, err := c.Token(ctx); err != nil {
		t.Fatal(err)
	}
	clk.add(51 * time.Minute)
	src.set(func(s *fakeSource) { s.token = "t2" })
	if tok, err := c.Token(ctx); err != nil || tok != "t2" || src.count() != 2 {
		t.Fatalf("past maxAge: %q %v, %d fetches", tok, err, src.count())
	}
}

// IMDS hands out a cached token that expires 20 minutes after the fetch.
// The refresh starts 10 minutes before the expiry, not at 30 minutes.
func TestTokenCacheRefreshesByExpiry(t *testing.T) {
	clk := &fakeClock{}
	src := &fakeSource{clock: clk, token: "t1", lifetime: 20 * time.Minute}
	c := newTestCache(src)
	ctx := context.Background()
	if _, err := c.Token(ctx); err != nil {
		t.Fatal(err)
	}
	clk.add(9 * time.Minute)
	if tok, _ := c.Token(ctx); tok != "t1" || src.count() != 1 {
		t.Fatalf("11 min before the expiry: %q, %d fetches", tok, src.count())
	}
	src.set(func(s *fakeSource) { s.token, s.lifetime = "t2", time.Hour })
	clk.add(time.Minute)
	if tok, _ := c.Token(ctx); tok != "t1" {
		t.Fatalf("10 min before the expiry: %q, want the cached token", tok)
	}
	waitCount(t, src, 2)
	waitToken(t, c, "t2")
}

// The near-expiry rule: within 2 minutes of the expiry no request gets the
// cached token. It waits for a fresh one, and sees the source's error if
// there is none.
func TestTokenCacheNeverServesANearlyExpiredToken(t *testing.T) {
	clk := &fakeClock{}
	src := &fakeSource{clock: clk, token: "t1", lifetime: 20 * time.Minute}
	c := newTestCache(src)
	ctx := context.Background()
	if _, err := c.Token(ctx); err != nil {
		t.Fatal(err)
	}
	src.set(func(s *fakeSource) { s.fail = true })
	clk.add(15 * time.Minute) // due: a background refresh fails
	if tok, err := c.Token(ctx); err != nil || tok != "t1" {
		t.Fatalf("5 min before the expiry: %q %v", tok, err)
	}
	waitCount(t, src, 2)
	clk.add(3*time.Minute + time.Second) // 1:59 before the expiry
	if tok, err := c.Token(ctx); err == nil {
		t.Fatalf("1:59 before the expiry with the source down: got %q, want an error", tok)
	}
	src.set(func(s *fakeSource) { s.fail, s.token, s.lifetime = false, "t2", time.Hour })
	if tok, err := c.Token(ctx); err != nil || tok != "t2" {
		t.Fatalf("1:59 before the expiry: %q %v, want a fresh token", tok, err)
	}
}

// A fetch that gives a token with under 5 minutes left is fetched again
// after a short wait, and a fresher one wins.
func TestTokenCacheRetriesAShortLivedToken(t *testing.T) {
	clk := &fakeClock{}
	src := &fakeSource{clock: clk, token: "fresh", lifetime: time.Hour,
		queue: []queued{{"old-1", 3 * time.Minute}, {"old-2", 4 * time.Minute}}}
	start := clk.now()
	tok, err := newTestCache(src).Token(context.Background())
	if err != nil || tok != "fresh" || src.count() != 3 {
		t.Fatalf("got %q %v after %d fetches, want fresh after 3", tok, err, src.count())
	}
	if waited := clk.now().Sub(start); waited != 3*time.Second {
		t.Fatalf("waited %v, want 1 s + 2 s", waited)
	}

	// The source keeps handing out a token with 4 minutes left. After the
	// retries the cache takes it.
	src2 := &fakeSource{clock: &fakeClock{}, token: "short", lifetime: 4 * time.Minute}
	if tok, err := newTestCache(src2).Token(context.Background()); err != nil || tok != "short" || src2.count() != 1+tokenShortRetries {
		t.Fatalf("short-lived source: %q %v, %d fetches", tok, err, src2.count())
	}

	// A token with 2 minutes left or less is refused.
	src3 := &fakeSource{clock: &fakeClock{}, token: "dying", lifetime: 90 * time.Second}
	if tok, err := newTestCache(src3).Token(context.Background()); err == nil {
		t.Fatalf("a token with 90 s left: got %q, want an error", tok)
	}
}

// After Invalidate the next request fetches. A source that hands back the
// refused token is asked again; a token already replaced stays.
func TestTokenCacheInvalidate(t *testing.T) {
	clk := &fakeClock{}
	src := &fakeSource{clock: clk, token: "t1", lifetime: time.Hour}
	c := newTestCache(src)
	ctx := context.Background()
	if _, err := c.Token(ctx); err != nil {
		t.Fatal(err)
	}
	src.set(func(s *fakeSource) { s.queue, s.token = []queued{{"t1", time.Hour}}, "t2" })
	c.Invalidate("t1")
	if tok, err := c.Token(ctx); err != nil || tok != "t2" || src.count() != 3 {
		t.Fatalf("after Invalidate: %q %v, %d fetches; want t2 after the source handed back t1 once", tok, err, src.count())
	}
	c.Invalidate("t1") // a late 401 for the old token
	if tok, _ := c.Token(ctx); tok != "t2" || src.count() != 3 {
		t.Fatalf("Invalidate of a replaced token: %q, %d fetches", tok, src.count())
	}
}

// Many requests on an empty, refused or expired cache cause one fetch, and
// those that waited take its token: no thundering herd at IMDS.
func TestTokenCacheOneFetchAtATime(t *testing.T) {
	clk := &fakeClock{}
	src := &fakeSource{clock: clk, token: "t1", lifetime: time.Hour}
	c := newTestCache(src)
	gate := make(chan struct{})
	src.set(func(s *fakeSource) { s.gate = gate })
	run := func(want string) {
		t.Helper()
		var wg sync.WaitGroup
		errs := make(chan error, 50)
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				tok, err := c.Token(context.Background())
				if err == nil && tok != want {
					err = errors.New("got " + tok + ", want " + want)
				}
				if err != nil {
					errs <- err
				}
			}()
		}
		time.Sleep(50 * time.Millisecond)
		gate <- struct{}{}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatal(err)
		}
	}
	run("t1")
	if src.count() != 1 {
		t.Fatalf("50 requests on an empty cache: %d fetches", src.count())
	}
	// 50 requests refused with t1 at once: one fetch.
	src.set(func(s *fakeSource) { s.token = "t2" })
	for i := 0; i < 50; i++ {
		c.Invalidate("t1")
	}
	run("t2")
	if src.count() != 2 {
		t.Fatalf("50 refused requests: %d fetches", src.count())
	}
	// Past maxAge: still one fetch.
	src.set(func(s *fakeSource) { s.token = "t3" })
	clk.add(51 * time.Minute)
	run("t3")
	if src.count() != 3 || src.overlap.Load() {
		t.Fatalf("past maxAge: %d fetches, overlap %v", src.count(), src.overlap.Load())
	}
}

// A source without expiry (GCP) keeps the fixed ages: a token 49 minutes
// old still goes out.
func TestTokenCacheWithoutExpiry(t *testing.T) {
	clk := &fakeClock{}
	src := &fakeSource{clock: clk, token: "t1"}
	c := newTestCache(src)
	if _, err := c.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	src.set(func(s *fakeSource) { s.fail = true })
	clk.add(49 * time.Minute)
	if tok, err := c.Token(context.Background()); err != nil || tok != "t1" {
		t.Fatalf("49 min old, no expiry: %q %v", tok, err)
	}
}
