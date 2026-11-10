//go:build nts

package clock

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/trusted-time/nts/ntstest"
)

// Follow-up 2026-11-09: seed set later, RATE, start retries, DNS.

func newFollowWorld(seed uint64) *shiftWorld {
	return &shiftWorld{off: 1_800_000_000 * int64(time.Second), seed: seed, loss: map[string]float64{}, down: map[string]bool{},
		wrong: map[string]time.Duration{}, contacts: map[string][]int64{}, downUntil: map[string]int64{}, rateUntil: map[string]int64{}}
}

func newFollowNTS(w *shiftWorld, catalog int, seed []byte) *NTS {
	n := &NTS{Coarse: w, Local: w.local, Shifts: true, ScheduleSeed: seed, testQuery: w.queryCtx, noStartDelay: true}
	for i := range catalog {
		n.Servers = append(n.Servers, NTSServer{Host: fmt.Sprintf("op%d.test", i), Operator: fmt.Sprintf("op%d", i)})
	}
	n.init()
	w.inStart = inStartOf(n)
	return n
}

// at sets the world to local time shiftBase+d and starts a tick there.
func (w *shiftWorld) at(d time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.now = max(w.now, int64(shiftBase+d))
	w.tickAt = w.now
}

func minGapOf(w *shiftWorld) (time.Duration, string) { return gapsOf(w) }

// Without a seed every operator is active, once per 60 s; the seed set
// later moves to 5 actives at their next slot, with the 60 s minimum kept
// across the switch and no blocking.
func TestNTSShiftSeedSetLater(t *testing.T) {
	w := newFollowWorld(1)
	n := newFollowNTS(w, 8, nil)
	ctx := context.Background()
	count := func(from, to time.Duration) int {
		c := 0
		for _, cs := range w.contacts {
			for _, x := range cs {
				if x >= int64(shiftBase+from) && x < int64(shiftBase+to) {
					c++
				}
			}
		}
		return c
	}
	blocked := 0
	for sec := time.Duration(0); sec < 30*time.Minute; sec += time.Second {
		if sec%testTick == 0 {
			w.at(sec)
			if sec == 10*time.Minute {
				n.SetScheduleSeed([]byte("released key"))
			}
			_ = n.Refresh(ctx)
		}
		if _, err := n.Now(); err != nil && sec > 0 {
			blocked++
		}
	}
	if g, op := minGapOf(w); g < NTSShiftMinGap {
		t.Fatalf("%s contacted twice %v apart", op, g)
	}
	before, after := count(2*time.Minute, 10*time.Minute), count(12*time.Minute, 28*time.Minute)
	// 8 operators at 60 per hour for 8 minutes; then 5 actives for 16
	// minutes plus at most one incoming at a handover.
	if before < 62 || before > 66 || after < 78 || after > 83 {
		t.Fatalf("contacts: %d before the seed (want about 64), %d after (want about 80)", before, after)
	}
	if blocked != 0 || len(n.NTSSummary().Actives) != 5 {
		t.Fatalf("blocked %d s, actives %v", blocked, n.NTSSummary().Actives)
	}
	t.Logf("contacts %d in 8 min before the seed, %d in 16 min after; min gap %v", before, after, func() time.Duration { g, _ := minGapOf(w); return g }())
}

// A Kiss-o'-Death RATE doubles the operator's gap each time (60, 120,
// 240 s ...); no contact comes sooner than its gap, fallbacks and bursts
// included. After RATE stops, each answer halves the gap back to 60 s.
func TestNTSShiftRate(t *testing.T) {
	w := newFollowWorld(2)
	n := newFollowNTS(w, 8, []byte("rate"))
	// The last of the first window: active for the first five shifts.
	vi := n.shifts.order[4]
	victim := n.Servers[vi].Operator
	w.rateUntil[victim] = int64(shiftBase + 20*time.Minute)
	ctx := context.Background()
	for sec := time.Duration(0); sec < 40*time.Minute; sec += testTick {
		w.at(sec)
		_ = n.Refresh(ctx)
	}
	cs := w.contacts[victim]
	var gaps []time.Duration
	for i := 1; i < len(cs); i++ {
		gaps = append(gaps, time.Duration(cs[i]-cs[i-1]))
	}
	c := n.NTSSummary().Operators[victim]
	t.Logf("%s: %d contacts, gaps %v, %+v", victim, len(cs), gaps, c)
	// Each contact during RATE answered RATE: the k-th gap is at least
	// 60 s x 2^k (the start contact gets the first RATE).
	want := NTSShiftMinGap
	for i, g := range gaps {
		if cs[i] >= w.rateUntil[victim] {
			break
		}
		want = min(2*want, 1024*time.Second)
		if g < want {
			t.Fatalf("gap %d is %v, want at least %v", i, g, want)
		}
	}
	if c.Rates < 3 {
		t.Fatalf("rates %d", c.Rates)
	}
	// Each answer after RATE stopped halves the gap.
	if c.Answers == 0 || n.shifts.gaps[vi] > n.shifts.maxGap>>c.Answers {
		t.Fatalf("gap after RATE stopped: %d ticks after %d answers", n.shifts.gaps[vi], c.Answers)
	}
	if g, op := minGapOf(w); g < NTSShiftMinGap {
		t.Fatalf("%s contacted twice %v apart", op, g)
	}
}

// startQuorum runs the runner's start loop (Refresh, and 5 s after it ends
// again, until a quorum) and returns when Now first worked, from the start
// round; -1 if not within limit.
func startQuorum(t *testing.T, w *shiftWorld, n *NTS, limit time.Duration) time.Duration {
	t.Helper()
	ctx := context.Background()
	sec := time.Duration(0)
	for sec < limit {
		w.at(sec)
		err := n.Refresh(ctx)
		if _, nerr := n.Now(); err == nil && nerr == nil {
			return time.Duration(w.local() - int64(shiftBase))
		}
		// The start loop sleeps 5 s after a Refresh that took its time.
		sec = time.Duration(w.local()-int64(shiftBase)) + 5*time.Second
	}
	return -1
}

// First quorum with 1, 3 or 5 of 8 operators down at start: the start round
// asks all 8, so 7, 5 or 3 answer and the first round forms it. With 5 down
// for good and the other 3 down for the first 10 s, the retry goes out as
// soon as the 60 s minimum allows, on the start loop's 5 s calls.
func TestNTSShiftStartWithOperatorsDown(t *testing.T) {
	for _, down := range []int{1, 3, 5} {
		w := newFollowWorld(uint64(10 + down))
		n := newFollowNTS(w, 8, nil)
		for i := range down {
			w.down[n.Servers[i].Operator] = true
		}
		got := startQuorum(t, w, n, 3*time.Minute)
		t.Logf("%d of 8 down: first quorum %v after the start round", down, got)
		if got < 0 || got > 2*time.Second {
			t.Errorf("%d down: first quorum after %v", down, got)
		}
	}
	w := newFollowWorld(20)
	n := newFollowNTS(w, 8, nil)
	for i := range 8 {
		if i < 5 {
			w.down[n.Servers[i].Operator] = true
		} else {
			w.downUntil[n.Servers[i].Operator] = int64(shiftBase + 10*time.Second)
		}
	}
	got := startQuorum(t, w, n, 3*time.Minute)
	t.Logf("5 down, 3 down for the first 10 s: first quorum %v after the start round", got)
	// The 3 that did not answer are asked again NTSShiftStartRetry after
	// the start round, at the first call then: the calls come every 5 s
	// plus the 1 s timeouts, so by 26 s.
	if got < NTSShiftStartRetry || got > 26*time.Second {
		t.Errorf("first quorum after %v", got)
	}
	if g, op := minGapOf(w); g < NTSShiftMinGap {
		t.Fatalf("%s contacted twice %v apart", op, g)
	}
}

// NTS-KE names the NTP server "localhost": under the shift schedule the
// clock resolves it once at NTS-KE, so queries dial an address.
func TestNTSShiftResolvesNTPAddressAtKE(t *testing.T) {
	var servers []NTSServer
	for _, op := range []string{"a", "b", "c"} {
		cert, pool, err := ntstest.Certificate("nts.test", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		store := ntstest.NewStore()
		ntp, err := ntstest.StartNTP(store, opt(ntstest.NTPOptions{}))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(ntp.Close)
		ke, err := ntstest.StartKE(cert, store, ntstest.KEOptions{NTPServer: "localhost", NTPPort: ntp.Port})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(ke.Close)
		servers = append(servers, NTSServer{Host: "nts.test", Operator: op, Roots: pool, KEAddr: ke.Addr})
	}
	n := &NTS{Servers: servers, Coarse: &coarseClock{}, Shifts: true, noStartDelay: true}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := n.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	for op, p := range n.Status().Peers {
		host, _, err := net.SplitHostPort(p.NTPAddr)
		if err != nil || net.ParseIP(host) == nil {
			t.Fatalf("%s: NTP address %q, want an IP", op, p.NTPAddr)
		}
	}
	if _, err := n.Now(); err != nil {
		t.Fatal(err)
	}
	// An address that is an IP, or that does not resolve, stays as it is.
	if got := n.resolve(ctx, "127.0.0.1:123"); got != "127.0.0.1:123" {
		t.Fatal(got)
	}
	if got := n.resolve(ctx, "no-such-host.invalid:123"); !strings.HasPrefix(got, "no-such-host.invalid") {
		t.Fatal(got)
	}
}
