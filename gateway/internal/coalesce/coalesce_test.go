package coalesce

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// clock is a settable time source.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newGroup(ttl time.Duration) (*Group[int], *clock) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	g := New[int](ttl, 5*time.Second)
	g.now = c.now

	return g, c
}

func key(pk byte, root byte, typ string) Key {
	var k Key
	k.Pubkey[0], k.Root[0], k.Type = pk, root, typ

	return k
}

// gatedCall counts calls and blocks each one until release is closed.
type gatedCall struct {
	calls   atomic.Int32
	started chan struct{}
	release chan struct{}
	val     int
	err     error
}

func newGated(val int, err error) *gatedCall {
	return &gatedCall{started: make(chan struct{}, 16), release: make(chan struct{}), val: val, err: err}
}

func (c *gatedCall) fn(context.Context) (int, error) {
	c.calls.Add(1)
	c.started <- struct{}{}
	<-c.release

	return c.val, c.err
}

// waitFor polls cond for up to two seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

type answer struct {
	v   int
	how How
	err error
}

// Requests that arrive while the call is in flight wait for it and get its
// result; the signer sees one call.
func TestInFlightDuplicatesShareOneCall(t *testing.T) {
	g, _ := newGroup(0)
	k := key(1, 1, "SYNC_COMMITTEE_SELECTION_PROOF")
	gc := newGated(42, nil)

	answers := make(chan answer, 6)
	ask := func() {
		v, how, err := g.Do(context.Background(), k, gc.fn)
		answers <- answer{v, how, err}
	}
	go ask()
	<-gc.started
	for range 5 {
		go ask()
	}
	waitFor(t, "five requests to join the call", func() bool { return g.joinedCall(k) == 5 })
	close(gc.release)

	count := map[How]int{}
	for range 6 {
		a := <-answers
		if a.err != nil || a.v != 42 {
			t.Fatalf("answer %+v", a)
		}
		count[a.how]++
	}
	if count[Called] != 1 || count[Coalesced] != 5 {
		t.Fatalf("answers by source %v, want 1 called and 5 coalesced", count)
	}
	if n := gc.calls.Load(); n != 1 {
		t.Fatalf("%d calls, want 1", n)
	}
	// ttl 0 stores nothing.
	if n := g.size(); n != 0 {
		t.Fatalf("%d entries left, want 0", n)
	}
}

// A finished result answers repeats until the ttl (two slots in the
// gateway) runs out; then a repeat makes a new call.
func TestCachedUntilExpiry(t *testing.T) {
	slot := 12 * time.Second
	g, clk := newGroup(2 * slot)
	k := key(1, 1, "SYNC_COMMITTEE_MESSAGE")
	calls := 0
	fn := func(context.Context) (int, error) { calls++; return calls, nil }

	if v, how, err := g.Do(context.Background(), k, fn); err != nil || v != 1 || how != Called {
		t.Fatalf("first: %d %v %v", v, how, err)
	}
	clk.add(2*slot - time.Millisecond)
	if v, how, err := g.Do(context.Background(), k, fn); err != nil || v != 1 || how != Cached {
		t.Fatalf("within two slots: %d %v %v", v, how, err)
	}
	clk.add(time.Millisecond)
	if v, how, err := g.Do(context.Background(), k, fn); err != nil || v != 2 || how != Called {
		t.Fatalf("after two slots: %d %v %v, want a new call", v, how, err)
	}
	if calls != 2 {
		t.Fatalf("%d calls, want 2", calls)
	}
}

// Expired results leave the map without a request for their key.
func TestSweepDropsExpired(t *testing.T) {
	g, clk := newGroup(time.Second)
	ok := func(context.Context) (int, error) { return 1, nil }
	for i := range 10 {
		if _, _, err := g.Do(context.Background(), key(byte(i), 0, "RANDAO_REVEAL"), ok); err != nil {
			t.Fatal(err)
		}
	}
	if n := g.size(); n != 10 {
		t.Fatalf("%d entries, want 10", n)
	}
	clk.add(2 * time.Second)
	if _, _, err := g.Do(context.Background(), key(99, 0, "RANDAO_REVEAL"), ok); err != nil {
		t.Fatal(err)
	}
	if n := g.size(); n != 1 {
		t.Fatalf("%d entries after the sweep, want 1", n)
	}
}

// An error goes to every request that waited for the call, and is not
// stored: the next request calls again.
func TestErrorsAreNotCached(t *testing.T) {
	g, _ := newGroup(time.Hour)
	k := key(1, 1, "AGGREGATION_SLOT")
	boom := errors.New("not enough signatures")
	gc := newGated(0, boom)

	answers := make(chan answer, 2)
	go func() { v, how, err := g.Do(context.Background(), k, gc.fn); answers <- answer{v, how, err} }()
	<-gc.started
	go func() { v, how, err := g.Do(context.Background(), k, gc.fn); answers <- answer{v, how, err} }()
	waitFor(t, "the second request to join", func() bool { return g.joinedCall(k) == 1 })
	close(gc.release)
	for range 2 {
		if a := <-answers; !errors.Is(a.err, boom) {
			t.Fatalf("answer %+v, want the call's error", a)
		}
	}
	if n := g.size(); n != 0 {
		t.Fatalf("%d entries after an error, want 0", n)
	}

	calls := 0
	if v, how, err := g.Do(context.Background(), k, func(context.Context) (int, error) { calls++; return 7, nil }); err != nil || v != 7 || how != Called || calls != 1 {
		t.Fatalf("after the error: %d %v %v calls %d, want a new call", v, how, err, calls)
	}
}

// Another key, another root or another type is another signature.
func TestDifferentKeysDoNotMerge(t *testing.T) {
	g, _ := newGroup(time.Hour)
	calls := 0
	fn := func(context.Context) (int, error) { calls++; return calls, nil }
	keys := []Key{
		key(1, 1, "SYNC_COMMITTEE_SELECTION_PROOF"),
		key(2, 1, "SYNC_COMMITTEE_SELECTION_PROOF"), // other validator
		key(1, 2, "SYNC_COMMITTEE_SELECTION_PROOF"), // other root (subcommittee)
		key(1, 1, "AGGREGATION_SLOT"),               // other type
	}
	for i, k := range keys {
		v, how, err := g.Do(context.Background(), k, fn)
		if err != nil || how != Called || v != i+1 {
			t.Fatalf("key %d: %d %v %v, want its own call", i, v, how, err)
		}
	}
	for i, k := range keys {
		if v, how, _ := g.Do(context.Background(), k, fn); how != Cached || v != i+1 {
			t.Fatalf("key %d again: %d %v, want its own stored result", i, v, how)
		}
	}
}

// The request that started the call may give up (its client hung up); the
// call goes on for the others and its result is stored.
func TestLeaderGivingUpDoesNotFailOthers(t *testing.T) {
	g, _ := newGroup(time.Hour)
	k := key(1, 1, "SYNC_COMMITTEE_MESSAGE")
	gc := newGated(5, nil)

	leaderCtx, hangUp := context.WithCancel(context.Background())
	leader := make(chan answer, 1)
	go func() { v, how, err := g.Do(leaderCtx, k, gc.fn); leader <- answer{v, how, err} }()
	<-gc.started
	other := make(chan answer, 1)
	go func() { v, how, err := g.Do(context.Background(), k, gc.fn); other <- answer{v, how, err} }()
	waitFor(t, "the second request to join", func() bool { return g.joinedCall(k) == 1 })

	hangUp()
	if a := <-leader; !errors.Is(a.err, context.Canceled) || a.how != Called {
		t.Fatalf("leader %+v, want its own cancellation", a)
	}
	close(gc.release)
	if a := <-other; a.err != nil || a.v != 5 || a.how != Coalesced {
		t.Fatalf("other %+v, want the call's result", a)
	}
	if _, how, _ := g.Do(context.Background(), k, gc.fn); how != Cached {
		t.Fatalf("after: %v, want the stored result", how)
	}
}

// The shared call has its own deadline, the Group's timeout.
func TestSharedCallHasItsOwnTimeout(t *testing.T) {
	g := New[int](0, 30*time.Millisecond)
	var deadline time.Time
	_, _, err := g.Do(context.Background(), key(1, 1, "RANDAO_REVEAL"), func(ctx context.Context) (int, error) {
		deadline, _ = ctx.Deadline()
		<-ctx.Done()

		return 0, ctx.Err()
	})
	if !errors.Is(err, context.DeadlineExceeded) || deadline.IsZero() {
		t.Fatalf("err %v, deadline %v", err, deadline)
	}
}

// A panic in the call becomes an error for every waiter.
func TestPanicBecomesError(t *testing.T) {
	g, _ := newGroup(time.Hour)
	_, _, err := g.Do(context.Background(), key(1, 1, "RANDAO_REVEAL"), func(context.Context) (int, error) { panic("boom") })
	if err == nil {
		t.Fatal("no error from a panicking call")
	}
	if n := g.size(); n != 0 {
		t.Fatalf("%d entries after a panic, want 0", n)
	}
}

// Only the non-slashable duty types may share; everything slashable or with
// policy stays out.
func TestShareable(t *testing.T) {
	for _, typ := range []string{"RANDAO_REVEAL", "AGGREGATION_SLOT", "AGGREGATE_AND_PROOF", "AGGREGATE_AND_PROOF_V2",
		"SYNC_COMMITTEE_MESSAGE", "SYNC_COMMITTEE_SELECTION_PROOF", "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF"} {
		if !Shareable(typ) {
			t.Errorf("%s is not shareable", typ)
		}
	}
	for _, typ := range []string{"ATTESTATION", "BLOCK_V2", "VOLUNTARY_EXIT", "VALIDATOR_REGISTRATION", "DEPOSIT",
		"PAYLOAD_ATTESTATION_MESSAGE", "EXECUTION_PAYLOAD_ENVELOPE", "PROPOSER_PREFERENCES", "EXECUTION_PAYLOAD_BID",
		"BUILDER_REQUEST_AUTH", "BLOCK", ""} {
		if Shareable(typ) {
			t.Errorf("%s is shareable", typ)
		}
	}
}
