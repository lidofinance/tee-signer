//go:build nts

package ntscore

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// The rules that moved into the core from the Go clock of main (#193,
// #213, #217): the majority quorum, the receipt bound, the key exchange of
// a loss streak, the era pivot and its window, the two configuration
// calls, the start state, and the cancelled exchange. Through the honest
// host of client_test.go.

// dispersion is d as an NTP short: the root dispersion of an answer, which
// goes into its bound whole.
func dispersion(d time.Duration) uint32 { return uint32(int64(d) << 16 / int64(time.Second)) }

// swap sets the core's list to these servers of the world, and on success
// the world's with it. A server renamed since the last list is a new peer
// to the core, so what its key exchange named is forgotten.
func (w *hostileWorld) swap(core *Core, list ...*hostileServer) error {
	w.t.Helper()
	old := w.list
	if old == nil {
		old = w.servers
	}
	var servers []Server
	for _, s := range list {
		servers = append(servers, honestServer(s))
	}
	if err := core.SetServers(servers, w.coarseNow(), w.now); err != nil {
		return err
	}
	named, dialed := map[int]string{}, map[int]string{}
	for i, s := range list {
		j := indexOfServer(old, s)
		if j < 0 || s.renamed {
			continue
		}
		if a, ok := w.named[j]; ok {
			named[i] = a
		}
		if a, ok := w.dialed[j]; ok {
			dialed[i] = a
		}
	}
	for _, s := range list {
		s.renamed = false
	}
	w.list, w.named, w.dialed = append([]*hostileServer(nil), list...), named, dialed
	w.live, w.honest = map[int]*clientRequest{}, map[int]bool{}
	return nil
}

// rename gives s another host name: the same operator at another server.
func (s *hostileServer) rename(host string) { s.host, s.renamed = host, true }

// about says whether two waits are the same but for the microseconds the
// virtual clock moves during a poll.
func about(a, b time.Duration) bool { return a-b < time.Millisecond && b-a < time.Millisecond }

func within(tm time.Time, bound time.Duration, truth int64) bool {
	d := tm.UnixNano() - truth
	return d <= int64(bound) && -d <= int64(bound)
}

// The combine allows QuorumWrong of the fresh samples wrong, and counts
// that itself: two liars of five are outvoted, one of four as well; two
// of three that agree are no quorum, since all three must.
func TestCombineUsesQuorumWrong(t *testing.T) {
	for _, c := range []struct {
		n, liars int
		served   bool
	}{{3, 0, true}, {3, 1, false}, {4, 1, true}, {4, 2, false}, {5, 2, true}, {5, 3, false}, {6, 2, true}, {6, 3, false}, {7, 3, true}} {
		w, core := newHonestCore(t, c.n, nil)
		for i := 0; i < c.liars; i++ {
			w.servers[i].offset = int64(900*(i+1)) * int64(time.Second) * int64(1-2*(i%2))
		}
		err := w.round(core)
		st := core.Status()
		if !c.served {
			if !errors.Is(err, ErrNoAgreement) || st.HaveResult || st.LastFresh != c.n {
				t.Fatalf("%d liars of %d: %v, %+v", c.liars, c.n, err, st)
			}
			if _, _, err := core.Bounded(); !errors.Is(err, ErrNoQuorum) {
				t.Fatalf("%d liars of %d: a time: %v", c.liars, c.n, err)
			}
			continue
		}
		if err != nil || len(st.Members) != c.n || st.MaxWrong != QuorumWrong(c.n) {
			t.Fatalf("%d liars of %d: %v, members %v, %d allowed wrong", c.liars, c.n, err, st.Members, st.MaxWrong)
		}
		tm, bound, err := core.Bounded()
		if err != nil || !within(tm, bound, w.trueNow()) {
			t.Fatalf("%d liars of %d: served %v with bound %v, true %v (%v)", c.liars, c.n, tm, bound, time.Unix(0, w.trueNow()), err)
		}
	}
	// Liars that agree with each other do no better while they are within
	// what is allowed wrong.
	w, core := newHonestCore(t, 5, nil)
	w.servers[1].offset, w.servers[3].offset = int64(20*time.Second), int64(20*time.Second)
	if err := w.round(core); err != nil {
		t.Fatal(err)
	}
	if tm, bound, err := core.Bounded(); err != nil || !within(tm, bound, w.trueNow()) {
		t.Fatalf("two colluding of five: served %v with bound %v, true %v (%v)", tm, bound, time.Unix(0, w.trueNow()), err)
	}
}

// With exactly three samples none may be wrong, so the result is the
// overlap of all three and one wrong operator could have placed it
// anywhere in the honest overlap: Worst says so (twice the widest member's
// aged bound). With more, a wrong one is outvoted and Worst is the bound.
func TestWorstBoundWithThreeSamples(t *testing.T) {
	w, core := newHonestCore(t, 3, nil)
	w.rootDispersion = dispersion(20 * time.Millisecond)
	if _, err := w.poll(core, 0); err != nil {
		t.Fatal(err)
	}
	w.rootDispersion = 0
	if err := w.round(core); err != nil {
		t.Fatal(err)
	}
	st := core.Status()
	widest := st.Peers[0].Sample.Bound
	if st.MaxWrong != 0 || st.Bound > 2*time.Millisecond || st.Worst < 2*widest || st.Worst > 2*widest+time.Millisecond {
		t.Fatalf("three samples: bound %v, worst %v, the widest sample %v", st.Bound, st.Worst, widest)
	}
	w, core = newHonestCore(t, 4, nil)
	w.rootDispersion = dispersion(20 * time.Millisecond)
	if _, err := w.poll(core, 0); err != nil {
		t.Fatal(err)
	}
	w.rootDispersion = 0
	if err := w.round(core); err != nil {
		t.Fatal(err)
	}
	if st := core.Status(); st.MaxWrong != 1 || st.Worst != st.Bound {
		t.Fatalf("four samples: bound %v, worst %v, %d allowed wrong", st.Bound, st.Worst, st.MaxWrong)
	}
}

// An answer over the receipt bound is refused: the earlier sample stays,
// the cookies it brought are kept, and it ends a loss streak (the server
// does answer), without counting as an error.
func TestWideAnswerIsRefusedAndEndsALossStreak(t *testing.T) {
	w, core := newHonestCore(t, 3, nil)
	ps, err := w.poll(core, 0)
	if err != nil {
		t.Fatal(err)
	}
	first := *ps.Sample
	w.drop = 2
	for k := 0; k < 2; k++ {
		w.now += int64(honestInterval)
		if _, err := w.poll(core, 0); !errors.Is(err, ErrHostTimeout) {
			t.Fatalf("lost request %d: %v", k, err)
		}
	}
	if ps := core.Peer(0); ps.LostInRow != 2 || ps.Cookies != MaxCookies-2 {
		t.Fatalf("after two lost: %+v", ps)
	}
	w.rootDispersion = dispersion(125 * time.Millisecond)
	w.now += int64(honestInterval)
	ps, err = w.poll(core, 0)
	if !errors.Is(err, ErrSampleWide) || ClassOf(err.(*Error).Code) != ClassClient {
		t.Fatalf("a wide answer: %v", err)
	}
	if ps.Sample == nil || *ps.Sample != first {
		t.Fatalf("the earlier sample did not stay: %+v, was %+v", ps.Sample, first)
	}
	if ps.Stats.Wide != 1 || ps.Stats.LastBound < 125*time.Millisecond || ps.Stats.LastDelay <= 0 || ps.Stats.Errors != 2 || ps.Stats.Samples != 1 ||
		ps.LostInRow != 0 || ps.Cookies != MaxCookies || !errors.Is(ps.LastErr, ErrSampleWide) {
		t.Fatalf("after the wide answer: %+v", ps)
	}
	// The streak starts over: two more lost requests bring no key exchange.
	w.rootDispersion, w.drop = 0, 2
	for k := 0; k < 2; k++ {
		w.now += int64(honestInterval)
		w.poll(core, 0)
	}
	w.now += int64(honestInterval)
	if ps, err := w.poll(core, 0); err != nil || ps.Stats.KEOK != 1 || ps.Sample.T4 == first.T4 || ps.Stats.LastBound > 10*time.Millisecond {
		t.Fatalf("after the streak started over: %v, %+v", err, ps)
	}
	// A wide answer alone gives no sample to a quorum.
	w, core = newHonestCore(t, 3, nil)
	w.rootDispersion = dispersion(125 * time.Millisecond)
	if err := w.round(core); !errors.Is(err, ErrQuorumTooFew) {
		t.Fatalf("a quorum of wide answers: %v", err)
	}
}

// The receipt bound is the cap less the aging over the join age, so a
// sample taken stays under the cap for as long as it may join; for a cap
// the aging would eat it is half the cap.
func TestReceiptBoundLeavesRoomForAging(t *testing.T) {
	for _, c := range []struct {
		maxBound, cap, maxAge, joinAge time.Duration
		ok, wide                       time.Duration // root dispersions on either side of the receipt bound
	}{
		// 100 ms less 500 ppm of 40 s: 80 ms.
		{100 * time.Millisecond, 0, time.Minute, 40 * time.Second, 77 * time.Millisecond, 81 * time.Millisecond},
		// The cap apart from MaxBound: 200 ms less 20 ms.
		{100 * time.Millisecond, 200 * time.Millisecond, time.Minute, 40 * time.Second, 177 * time.Millisecond, 181 * time.Millisecond},
		// 500 ppm of 5 minutes is 150 ms, over the cap: half the cap.
		{100 * time.Millisecond, 100 * time.Millisecond, 10 * time.Minute, 5 * time.Minute, 47 * time.Millisecond, 51 * time.Millisecond},
		// No join age given: MaxAge is the join age. 100 ms less 30 ms.
		{100 * time.Millisecond, 0, time.Minute, 0, 67 * time.Millisecond, 71 * time.Millisecond},
	} {
		w, core := newHonestCore(t, 3, func(cfg *Config) {
			cfg.MaxBound, cfg.MaxSampleBound, cfg.MaxAge, cfg.JoinAge = c.maxBound, c.cap, c.maxAge, c.joinAge
		})
		w.rootDispersion = dispersion(c.ok)
		ps, err := w.poll(core, 0)
		if err != nil || ps.Sample.Bound < c.ok || ps.Sample.Bound > c.ok+2*time.Millisecond {
			t.Fatalf("%+v: a dispersion of %v: %v, %+v", c, c.ok, err, ps.Sample)
		}
		w.rootDispersion = dispersion(c.wide)
		w.now += int64(honestInterval)
		if ps, err := w.poll(core, 0); !errors.Is(err, ErrSampleWide) || ps.Stats.LastBound < c.wide {
			t.Fatalf("%+v: a dispersion of %v: %v, %+v", c, c.wide, err, ps)
		}
	}
}

// After KEAfterLost queries in a row without an answer the next poll runs
// NTS-KE first, once per streak; an answer ends the streak. A server that
// rotated its keys and drops old cookies would otherwise cost all eight.
func TestKeyExchangeAfterLostQueries(t *testing.T) {
	w, core := newHonestCore(t, 3, nil)
	if _, err := w.poll(core, 0); err != nil {
		t.Fatal(err)
	}
	lose := func(n int) PeerStatus {
		t.Helper()
		w.drop = n
		var ps PeerStatus
		for k := 0; k < n; k++ {
			w.now += int64(honestInterval)
			var err error
			if ps, err = w.poll(core, 0); !errors.Is(err, ErrHostTimeout) {
				t.Fatalf("lost request %d: %v", k, err)
			}
		}
		return ps
	}
	if ps := lose(KEAfterLost); ps.Stats.KEOK != 1 || ps.LostInRow != KEAfterLost || ps.Cookies != MaxCookies-KEAfterLost || ps.NeedKE {
		t.Fatalf("after %d lost: %+v", KEAfterLost, ps)
	}
	// The next contact runs NTS-KE first: a full jar, less the request's.
	if ps := lose(1); ps.Stats.KEOK != 2 || ps.Cookies != MaxCookies-1 || ps.LostInRow != KEAfterLost+1 {
		t.Fatalf("the poll after the streak: %+v", ps)
	}
	// Once per streak: the losses go on, no further key exchange.
	if ps := lose(3); ps.Stats.KEOK != 2 || ps.Cookies != MaxCookies-4 {
		t.Fatalf("further losses of the same streak: %+v", ps)
	}
	// An answer ends the streak; the next streak gets its key exchange.
	w.now += int64(honestInterval)
	if ps, err := w.poll(core, 0); err != nil || ps.LostInRow != 0 || ps.Stats.KEOK != 2 {
		t.Fatalf("the answer: %v, %+v", err, ps)
	}
	if ps := lose(KEAfterLost + 1); ps.Stats.KEOK != 3 {
		t.Fatalf("the next streak: %+v", ps)
	}
}

// The key exchange of a loss streak keeps the old keys and cookies until
// it succeeds: if it fails, the poll goes on with them, and the failure
// costs the peer nothing but its place in the streak.
func TestFailedLostKeyExchangeKeepsCookies(t *testing.T) {
	w, core := newHonestCore(t, 3, nil)
	if err := w.round(core); err != nil {
		t.Fatal(err)
	}
	w.drop = KEAfterLost
	for k := 0; k < KEAfterLost; k++ {
		w.now += int64(honestInterval)
		w.poll(core, 0)
	}
	// The key exchange fails; the query goes out with an old cookie and is
	// answered: the keys are still the old ones.
	w.keFail = 1
	w.now += int64(honestInterval)
	sent := len(w.sent)
	ps, err := w.poll(core, 0)
	if err != nil || ps.Sample == nil || ps.Stats.KEOK != 1 || ps.Stats.KEFail != 1 || ps.Cookies != MaxCookies || len(w.sent) != sent+1 || ps.LostInRow != 0 {
		t.Fatalf("a failed key exchange in a streak: %v, %+v", err, ps)
	}
	// A response the core refuses (garbage through the TLS session) leaves
	// the association as it was, too.
	w.drop = KEAfterLost
	for k := 0; k < KEAfterLost; k++ {
		w.now += int64(honestInterval)
		w.poll(core, 0)
	}
	w.keBad = 3
	w.now += int64(64 * time.Second)
	ps, err = w.poll(core, 0)
	if err != nil || ps.Sample == nil || ps.Stats.KEOK != 1 || ps.Stats.KEFail != 2 || ps.Cookies != MaxCookies {
		t.Fatalf("a refused key exchange in a streak: %v, %+v", err, ps)
	}
}

// The era pivot follows the time the core has served, so the client keeps
// reading the right NTP era for as long as it runs: twice 19 years on, the
// second quorum is 38 years from the floor and is taken, because the pivot
// moved with the first. A quorum over 20 years from the pivot is refused.
func TestEraPivotFollowsTheServedTime(t *testing.T) {
	const years = 8766 * time.Hour
	w, core := newHonestCore(t, 3, nil)
	if err := w.round(core); err != nil {
		t.Fatal(err)
	}
	if st := core.Status(); st.EraPivot < w.trueNow()-int64(time.Second) || st.EraPivot > w.trueNow() {
		t.Fatalf("pivot %v after the first quorum, true time %v", time.Unix(0, st.EraPivot), time.Unix(0, w.trueNow()))
	}
	for k := 1; k <= 2; k++ {
		w.now += int64(19 * years)
		if err := w.round(core); err != nil {
			t.Fatalf("%d years on: %v", 19*k, err)
		}
		tm, bound, err := core.Bounded()
		if err != nil || !within(tm, bound, w.trueNow()) || tm.Year() != 2026+19*k {
			t.Fatalf("%d years on: served %v (%v)", 19*k, tm, err)
		}
		if st := core.Status(); st.EraPivot < w.trueNow()-int64(time.Second) {
			t.Fatalf("%d years on: pivot %v", 19*k, time.Unix(0, st.EraPivot))
		}
	}
	// 21 years in one step: outside the window, whatever the coarse clock says.
	before := core.Status()
	w.now += int64(21 * years)
	err := w.round(core)
	if !errors.Is(err, ErrEraWindow) || !strings.Contains(err.Error(), "after the era pivot") {
		t.Fatalf("21 years on: %v", err)
	}
	if _, _, err := core.Bounded(); !errors.Is(err, ErrNoQuorum) {
		t.Fatalf("a time after the window refusal: %v", err)
	}
	// The pivot stays at the last time served (the combine raises it to the
	// reading taken after the last quorum formed, microseconds on).
	if st := core.Status(); st.EraPivot < before.EraPivot || st.EraPivot > before.EraPivot+int64(time.Second) || st.Violations != 0 || !errors.Is(st.LastErr, ErrEraWindow) {
		t.Fatalf("after the window refusal: %+v", st)
	}
}

// A quorum time outside the sanity window (before the floor, or over 20
// years after the pivot) is refused before the coarse and drift checks and
// does not enter the drift history: once the servers are right again the
// next quorum serves, with no drift violation in between.
func TestEraWindowRefusalsKeepTheDriftHistory(t *testing.T) {
	for _, c := range []struct {
		off  time.Duration
		text string
	}{{-60 * 24 * time.Hour, "before the floor"}, {21 * 8766 * time.Hour, "after the era pivot"}} {
		w, core := newHonestCore(t, 4, nil)
		for r := 0; r < 3; r++ {
			if err := w.round(core); err != nil {
				t.Fatal(err)
			}
			w.now += int64(honestInterval)
		}
		before := core.Status()
		// Every server lies together, and the coarse clock agrees with them:
		// the window refuses it all the same.
		for _, s := range w.servers {
			s.offset = int64(c.off)
		}
		for _, i := range core.Due(w.now) {
			w.poll(core, i)
		}
		err := core.Combine(time.Unix(0, w.trueNow()+int64(c.off)), w.now)
		if !errors.Is(err, ErrEraWindow) || !strings.Contains(err.Error(), c.text) {
			t.Fatalf("servers %v off: %v", c.off, err)
		}
		st := core.Status()
		if st.HaveResult || st.DriftDT != before.DriftDT || st.DriftDelta != before.DriftDelta || st.Violations != 0 || st.EraPivot != before.EraPivot ||
			st.HaveCoarseDiff && st.CoarseDiff != before.CoarseDiff {
			t.Fatalf("servers %v off: the refusal left %+v, was %+v", c.off, st, before)
		}
		if _, _, err := core.Bounded(); !errors.Is(err, ErrNoQuorum) {
			t.Fatalf("servers %v off: a time: %v", c.off, err)
		}
		for _, s := range w.servers {
			s.offset = 0
		}
		w.now += int64(honestInterval)
		if err := w.round(core); err != nil {
			t.Fatalf("servers right again after %v: %v", c.off, err)
		}
		if st := core.Status(); st.Violations != 0 || !st.HaveResult {
			t.Fatalf("servers right again after %v: %+v", c.off, st)
		}
	}
}

// The NTP era never comes from the coarse clock. A coarse reading 2^32 s
// off (the next era: the same octets on the wire) moves nothing: the
// answers are read in the right era, the coarse check refuses the quorum,
// and neither the pivot nor the drift history changes. On a running core
// and from the start, over NTS and over plain NTP.
func TestCoarseClockAnEraOffIsRefused(t *testing.T) {
	const era = int64(1) << 32 * int64(time.Second)
	for _, proto := range []Protocol{ProtocolNTS, ProtocolNTP} {
		if proto == ProtocolNTP && !PlainSupported() {
			continue
		}
		for _, running := range []bool{true, false} {
			for _, sign := range []int64{1, -1} {
				w, core := newHonestCore(t, 4, func(c *Config) { c.Protocol = proto })
				what := fmt.Sprintf("%v, running %v, coarse %+d eras", proto, running, sign)
				if running {
					for r := 0; r < 2; r++ {
						if err := w.round(core); err != nil {
							t.Fatal(err)
						}
						w.now += int64(honestInterval)
					}
				}
				before := core.Status()
				// The servers may say the coarse clock's era too: on the wire
				// that is the same answer.
				if sign > 0 {
					for _, s := range w.servers {
						s.offset = era
					}
				}
				w.coarse, w.coarseLocal = w.trueNow()+sign*era, w.now
				coarse := time.Unix(0, w.coarse)
				for _, i := range core.Due(w.now) {
					if _, err := core.Poll(i, coarse, w.coarseLocal); err != nil && !(sign < 0 && !running && errors.Is(err, ErrNoTrustedTime)) {
						t.Fatalf("%s: peer %d: %v", what, i, err)
					}
					if w.failed != nil {
						t.Fatalf("%s: %v", what, w.failed)
					}
				}
				err := core.Combine(coarse, w.coarseLocal)
				switch {
				case sign < 0 && !running && proto == ProtocolNTS:
					// A coarse clock in 1890 dates no certificate: no samples.
					if !errors.Is(err, ErrQuorumTooFew) {
						t.Fatalf("%s: %v", what, err)
					}
				case !errors.Is(err, ErrCoarseCheck):
					t.Fatalf("%s: %v", what, err)
				}
				if _, _, err := core.Bounded(); !errors.Is(err, ErrNoQuorum) {
					t.Fatalf("%s: a time: %v", what, err)
				}
				st := core.Status()
				if st.EraPivot != before.EraPivot || st.Violations != 0 || st.DriftDT != before.DriftDT {
					t.Fatalf("%s: pivot %v (was %v), %+v", what, time.Unix(0, st.EraPivot), time.Unix(0, before.EraPivot), st)
				}
				for i, ps := range st.Peers {
					if ps.Sample != nil && (ps.Sample.Offset-w.trueOffset > int64(time.Second) || w.trueOffset-ps.Sample.Offset > int64(time.Second)) {
						t.Fatalf("%s: peer %d read in another era: offset %d, true %d", what, i, ps.Sample.Offset, w.trueOffset)
					}
				}
				// The coarse clock right again: the same samples serve.
				if sign < 0 && !running && proto == ProtocolNTS {
					continue
				}
				if err := core.Combine(w.coarseNow(), w.now); err != nil {
					t.Fatalf("%s: the coarse clock right again: %v", what, err)
				}
				if tm, bound, err := core.Bounded(); err != nil || !within(tm, bound, w.trueNow()) {
					t.Fatalf("%s: served %v (%v), true %v", what, tm, err, time.Unix(0, w.trueNow()))
				}
			}
		}
	}
}

// SetServers on a running core: a server that is as before keeps its
// peer; a changed or new one is a new peer; a removed member leaves the
// quorum at once, and the quorum forms again without it or the core
// serves no time until one forms.
func TestSetServers(t *testing.T) {
	w, core := newHonestCore(t, 5, func(c *Config) { c.Capacity, c.StartWait = 6, 30*time.Second })
	s := w.servers
	if err := w.round(core); err != nil {
		t.Fatal(err)
	}
	if _, _, err := core.Bounded(); err != nil {
		t.Fatal(err)
	}
	before := core.Status()
	// The same servers in another order: nothing but the order changes.
	if err := w.swap(core, s[4], s[3], s[2], s[1], s[0]); err != nil {
		t.Fatal(err)
	}
	st := core.Status()
	if !st.HaveResult || st.At != before.At || st.Offset != before.Offset || len(st.Members) != 5 || st.Cold {
		t.Fatalf("after a permutation: %+v", st)
	}
	for i := range st.Peers {
		was, is := before.Peers[4-i], st.Peers[i]
		if is.Cookies != was.Cookies || is.Sample == nil || *is.Sample != *was.Sample || is.NTPAddr != was.NTPAddr || is.NextPoll != was.NextPoll || is.Stats.KEOK != 1 {
			t.Fatalf("after a permutation: peer %d %+v, was %+v", i, is, was)
		}
	}
	if got := core.Due(w.now + int64(honestInterval)); len(got) != 5 {
		t.Fatalf("due after a permutation: %v", got)
	}
	// A member removed: the quorum forms again from the four left, in the call.
	if err := w.swap(core, s[0], s[1], s[2], s[3]); err != nil {
		t.Fatal(err)
	}
	st = core.Status()
	if !st.HaveResult || st.At <= before.At || len(st.Members) != 4 || st.MaxWrong != 1 || len(st.Peers) != 4 || st.Cold || st.LastErr != nil {
		t.Fatalf("after a removal: %+v", st)
	}
	if st.Peers[0].Sample == nil || *st.Peers[0].Sample != *before.Peers[0].Sample {
		t.Fatalf("after a removal: the first server's sample: %+v", st.Peers[0])
	}
	// The same operator at another host is a new peer: no keys, no sample.
	// It was a member, so the quorum forms again from the three left.
	at := st.At
	s[0].rename("nts-a2.test")
	if err := w.swap(core, s[0], s[1], s[2], s[3]); err != nil {
		t.Fatal(err)
	}
	st = core.Status()
	if p := st.Peers[0]; p.Sample != nil || p.Cookies != 0 || p.Stats.KEOK != 0 || !p.NeedKE || p.NTPAddr != "" {
		t.Fatalf("a changed server kept state: %+v", p)
	}
	if !st.HaveResult || st.At <= at || !slices.Equal(st.Members, []int{1, 2, 3}) || st.MaxWrong != 0 {
		t.Fatalf("after a change: %+v", st)
	}
	served, _, err := core.Bounded()
	if err != nil {
		t.Fatal(err)
	}
	// Another member removed: two samples are no quorum. No time, and the
	// start state begins; the removed server's sample is gone for good.
	if err := w.swap(core, s[0], s[1], s[2]); err != nil {
		t.Fatal(err)
	}
	st = core.Status()
	if st.HaveResult || !st.Cold || !errors.Is(st.LastErr, ErrQuorumTooFew) || st.LastFresh != 2 {
		t.Fatalf("after a removal that leaves two samples: %+v", st)
	}
	if _, _, err := core.Bounded(); !errors.Is(err, ErrNoQuorum) {
		t.Fatalf("a time with two samples: %v", err)
	}
	// The removed server back in the list is a new peer: still no quorum.
	if err := w.swap(core, s[0], s[1], s[2], s[3]); err != nil {
		t.Fatal(err)
	}
	if st := core.Status(); st.HaveResult || st.Peers[3].Sample != nil || st.Peers[3].Cookies != 0 {
		t.Fatalf("a server that came back: %+v", st)
	}
	// The new peers are asked (a key exchange each), and the quorum forms.
	w.now += int64(honestInterval)
	if err := w.round(core); err != nil {
		t.Fatal(err)
	}
	st = core.Status()
	if len(st.Members) != 4 || st.Cold || st.Peers[0].Stats.KEOK != 1 || st.Peers[1].Stats.KEOK != 1 || st.Violations != 0 {
		t.Fatalf("after the new peers were asked: %+v", st)
	}
	if tm, bound, err := core.Bounded(); err != nil || tm.Before(served) || !within(tm, bound, w.trueNow()) {
		t.Fatalf("after the swaps: served %v, before them %v (%v)", tm, served, err)
	}
	// A new operator in the sixth slot, and nothing over the capacity.
	extra := &hostileServer{op: "x", c2s: w.rng.bytes(32), s2c: w.rng.bytes(32)}
	if err := w.swap(core, s[0], s[1], s[2], s[3], s[4], extra); err != nil {
		t.Fatal(err)
	}
	w.now += int64(honestInterval)
	if err := w.round(core); err != nil || len(core.Status().Members) != 6 {
		t.Fatalf("six servers: %v, %+v", err, core.Status())
	}
}

// SetServers refuses a list that would give one server two votes or does
// not fit, and a refused call changes nothing.
func TestSetServersRefusals(t *testing.T) {
	w, core := newHonestCore(t, 4, func(c *Config) { c.Capacity = 5 })
	if err := w.round(core); err != nil {
		t.Fatal(err)
	}
	good := func() []Server {
		var out []Server
		for _, s := range w.servers {
			out = append(out, honestServer(s))
		}
		return out
	}
	before := core.Status()
	for what, edit := range map[string]func(l []Server) []Server{
		"an operator named twice":    func(l []Server) []Server { l[1].Operator = l[0].Operator; return l },
		"a host named twice":         func(l []Server) []Server { l[2].Host = l[0].Host; return l },
		"an NTP address named twice": func(l []Server) []Server { l[1].NTPAddr, l[3].NTPAddr = "192.0.2.1:123", "192.0.2.1:123"; return l },
		"more servers than fit": func(l []Server) []Server {
			return append(l, Server{Operator: "x", Host: "x.test"}, Server{Operator: "y", Host: "y.test"})
		},
		"no operator label":             func(l []Server) []Server { l[0].Operator = ""; return l },
		"an operator label too long":    func(l []Server) []Server { l[0].Operator = strings.Repeat("o", MaxOperatorLen+1); return l },
		"no host":                       func(l []Server) []Server { l[3].Host = ""; return l },
		"an NTP address over the limit": func(l []Server) []Server { l[3].NTPAddr = strings.Repeat("a", MaxAddrLen+1); return l },
		"roots over the limit":          func(l []Server) []Server { l[3].Roots = make([]byte, MaxRootsLen+1); return l },
	} {
		if err := core.SetServers(edit(good()), w.coarseNow(), w.now); !errors.Is(err, ErrBadConfig) {
			t.Fatalf("%s: %v", what, err)
		}
		if diff := sameClient(before, core.Status()); diff != "" {
			t.Fatalf("%s: refused, and %s changed", what, diff)
		}
	}
	// Two servers with one NTP address unset are not twins, and the same
	// list again changes nothing.
	if err := core.SetServers(good(), w.coarseNow(), w.now); err != nil {
		t.Fatal(err)
	}
	if diff := sameClient(before, core.Status()); diff != "" {
		t.Fatalf("the same list again changed %s", diff)
	}
	// An operator named twice is refused at the start as well.
	cfg := Config{
		Servers:  []Server{{Operator: "a", Host: "a.test"}, {Operator: "b", Host: "b.test"}, {Operator: "a", Host: "c.test"}},
		Interval: time.Second, MinPoll: time.Second, MaxPoll: time.Minute, MaxBound: time.Second, MaxAge: time.Minute,
		MaxCoarseDiff: time.Second, CoarseResolution: time.Second, ExchangeTimeout: time.Second, DriftBaselinePolls: 1, FloorUnix: hostileFloor,
	}
	if _, err := New(cfg, &hostileWorld{}); !errors.Is(err, ErrBadConfig) {
		t.Fatalf("an operator named twice at the start: %v", err)
	}
	// A host named twice is taken at the start (as on main), not at a swap.
	cfg.Servers[2] = Server{Operator: "c", Host: "a.test"}
	c2, err := New(cfg, &hostileWorld{})
	if err != nil {
		t.Fatalf("a host named twice at the start: %v", err)
	}
	c2.Close()
	if err := core.SetServers(nil, time.Time{}, 0); err != nil {
		t.Fatalf("an empty list: %v", err)
	}
	if st := core.Status(); st.HaveResult || len(st.Peers) != 0 {
		t.Fatalf("an empty list: %+v", st)
	}
	core.Close()
	if err := core.SetServers(good(), w.coarseNow(), w.now); !errors.Is(err, ErrClosed) {
		t.Fatalf("SetServers after Close: %v", err)
	}
	if err := core.SetPolicy(ProtocolNTS, time.Second, time.Second, w.coarseNow(), w.now); !errors.Is(err, ErrClosed) {
		t.Fatalf("SetPolicy after Close: %v", err)
	}
}

// The configuration calls and the combine are refused while a poll is
// under way, and change nothing then.
func TestConfigurationCallsAreBusyDuringAPoll(t *testing.T) {
	w, core := newHonestCore(t, 4, nil)
	if err := w.round(core); err != nil {
		t.Fatal(err)
	}
	var errs []error
	w.onOpen = func() {
		errs = append(errs,
			core.SetServers([]Server{honestServer(w.servers[0]), honestServer(w.servers[1]), honestServer(w.servers[2])}, w.coarseNow(), w.now),
			core.SetPolicy(ProtocolNTS, 50*time.Millisecond, 50*time.Millisecond, w.coarseNow(), w.now),
			core.Combine(w.coarseNow(), w.now))
		if st := core.Status(); !st.Busy || len(st.Peers) != 0 {
			errs = append(errs, fmt.Errorf("a full status during a poll: %+v", st))
		}
	}
	w.now += int64(honestInterval)
	if _, err := w.poll(core, 0); err != nil {
		t.Fatal(err)
	}
	w.onOpen = nil
	if len(errs) != 3 || !errors.Is(errs[0], ErrBusy) || !errors.Is(errs[1], ErrBusy) || !errors.Is(errs[2], ErrBusy) {
		t.Fatalf("during a poll: %v", errs)
	}
	if st := core.Status(); len(st.Peers) != 4 || !st.HaveResult || st.Busy {
		t.Fatalf("after the poll: %+v", st)
	}
	if _, bound, err := core.Bounded(); err != nil || bound > 100*time.Millisecond {
		t.Fatalf("after the poll: %v", err)
	}
}

// The time never goes back across a swap that takes every server out: the
// highest time served stays, though every peer is new.
func TestHighestSurvivesSetServers(t *testing.T) {
	w, core := newHonestCore(t, 3, func(c *Config) { c.StartWait = time.Minute })
	if err := w.round(core); err != nil {
		t.Fatal(err)
	}
	highest, _, err := core.Bounded()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range w.servers {
		s.rename(fmt.Sprintf("other-%s.test", s.op))
		s.offset = -int64(10 * time.Second)
	}
	if err := w.swap(core, w.servers...); err != nil {
		t.Fatal(err)
	}
	if st := core.Status(); st.HaveResult || !st.Cold {
		t.Fatalf("after every server changed: %+v", st)
	}
	// The servers now agree on a time 10 s back. The drift history stayed,
	// so the first quorum is refused against it; the next agrees with it.
	if err := w.round(core); !errors.Is(err, ErrDrift) {
		t.Fatalf("the first quorum of the new servers: %v", err)
	}
	w.now += int64(honestInterval)
	if err := w.round(core); err != nil {
		t.Fatal(err)
	}
	st := core.Status()
	if raw := time.Unix(0, st.Now+st.Offset); !raw.Before(highest) {
		t.Fatalf("the new quorum reads %v, not behind %v", raw, highest)
	}
	if tm, _, err := core.Bounded(); err != nil || !tm.Equal(highest) {
		t.Fatalf("served %v, the highest before the swap was %v (%v)", tm, highest, err)
	}
}

// SetPolicy refuses what it cannot take and changes nothing then.
func TestSetPolicyRefusals(t *testing.T) {
	w, core := newHonestCore(t, 4, nil)
	if err := w.round(core); err != nil {
		t.Fatal(err)
	}
	before := core.Status()
	for _, c := range []struct {
		p                Protocol
		bound, sampleCap time.Duration
	}{
		{Protocol(2), 100 * time.Millisecond, 100 * time.Millisecond},
		{Protocol(-1), 100 * time.Millisecond, 100 * time.Millisecond},
		{ProtocolNTS, 0, 100 * time.Millisecond},
		{ProtocolNTS, -1, 100 * time.Millisecond},
		{ProtocolNTS, 100 * time.Millisecond, 99 * time.Millisecond},
		{ProtocolNTS, 100 * time.Millisecond, 0},
		{ProtocolNTS, 100 * time.Millisecond, MaxSampleBound + 1},
		{ProtocolNTP, 0, 100 * time.Millisecond},
	} {
		if err := core.SetPolicy(c.p, c.bound, c.sampleCap, w.coarseNow(), w.now); !errors.Is(err, ErrBadConfig) {
			t.Fatalf("SetPolicy(%v, %v, %v): %v", c.p, c.bound, c.sampleCap, err)
		}
		if diff := sameClient(before, core.Status()); diff != "" {
			t.Fatalf("SetPolicy(%v, %v, %v): refused, and %s changed", c.p, c.bound, c.sampleCap, diff)
		}
		if _, _, err := core.Bounded(); err != nil {
			t.Fatalf("SetPolicy(%v, %v, %v): refused, and the time is gone: %v", c.p, c.bound, c.sampleCap, err)
		}
	}
	// The same policy again, and the widest: nothing but the bounds changes.
	if err := core.SetPolicy(ProtocolNTS, 100*time.Millisecond, MaxSampleBound, w.coarseNow(), w.now); err != nil {
		t.Fatal(err)
	}
	if diff := sameClient(before, core.Status()); diff != "" {
		t.Fatalf("a wider sample bound changed %s", diff)
	}
	// The bounds of the start are checked the same way.
	for what, edit := range map[string]func(c *Config){
		"a sample bound under MaxBound": func(c *Config) { c.MaxSampleBound = c.MaxBound - 1 },
		"a sample bound over the most":  func(c *Config) { c.MaxSampleBound = MaxSampleBound + 1 },
		"an unknown protocol":           func(c *Config) { c.Protocol = 2 },
		"a negative query timeout":      func(c *Config) { c.QueryTimeout = -1 },
		"a negative start wait":         func(c *Config) { c.StartWait = -1 },
		"a capacity under the servers":  func(c *Config) { c.Capacity = 2 },
		"a capacity over the most":      func(c *Config) { c.Capacity = MaxServers + 1 },
		"an NTP address over the limit": func(c *Config) { c.Servers[0].NTPAddr = strings.Repeat("a", MaxAddrLen+1) },
	} {
		cfg := Config{
			Servers:  []Server{{Operator: "a", Host: "a.test"}, {Operator: "b", Host: "b.test"}, {Operator: "c", Host: "c.test"}},
			Interval: time.Second, MinPoll: time.Second, MaxPoll: time.Minute, MaxBound: 100 * time.Millisecond, MaxAge: time.Minute,
			MaxCoarseDiff: time.Second, CoarseResolution: time.Second, ExchangeTimeout: time.Second, DriftBaselinePolls: 1, FloorUnix: hostileFloor,
		}
		edit(&cfg)
		if _, err := New(cfg, &hostileWorld{}); !errors.Is(err, ErrBadConfig) {
			t.Fatalf("%s: %v", what, err)
		}
	}
}

// A tighter sample bound drops each sample over the new receipt bound; if
// one was a member, the quorum forms again without it, or no time is
// served. A tighter MaxBound applies to the quorum in force at once.
func TestSetPolicyBounds(t *testing.T) {
	for _, n := range []int{4, 3} {
		w, core := newHonestCore(t, n, func(c *Config) { c.StartWait = time.Minute })
		// The last server's answers are 60 ms wide: within 100 ms less the
		// aging (70 ms), over 50 ms less the aging (25 ms, half the cap).
		for i := 0; i < n; i++ {
			if i == n-1 {
				w.rootDispersion = dispersion(60 * time.Millisecond)
			}
			if _, err := w.poll(core, i); err != nil {
				t.Fatal(err)
			}
		}
		w.rootDispersion = 0
		if err := core.Combine(w.coarseNow(), w.now); err != nil || len(core.Status().Members) != n {
			t.Fatalf("%d servers: %v", n, err)
		}
		before := core.Status()
		if err := core.SetPolicy(ProtocolNTS, 50*time.Millisecond, 50*time.Millisecond, w.coarseNow(), w.now); err != nil {
			t.Fatal(err)
		}
		st := core.Status()
		if st.Peers[n-1].Sample != nil || st.Peers[0].Sample == nil || st.Peers[n-1].Cookies != MaxCookies || st.Protocol != ProtocolNTS {
			t.Fatalf("%d servers: the wide sample stayed, or more went: %+v", n, st.Peers)
		}
		if n == 4 {
			if !st.HaveResult || st.At <= before.At || !slices.Equal(st.Members, []int{0, 1, 2}) || st.Cold {
				t.Fatalf("4 servers: %+v", st)
			}
			if _, _, err := core.Bounded(); err != nil {
				t.Fatal(err)
			}
			// An answer of 60 ms is refused from here on.
			w.rootDispersion = dispersion(60 * time.Millisecond)
			w.now += int64(honestInterval)
			if _, err := w.poll(core, 3); !errors.Is(err, ErrSampleWide) {
				t.Fatalf("a 60 ms answer under the new bound: %v", err)
			}
			// MaxBound at once: the quorum in force is over 100 us.
			if err := core.SetPolicy(ProtocolNTS, 100*time.Microsecond, 50*time.Millisecond, w.coarseNow(), w.now); err != nil {
				t.Fatal(err)
			}
			if _, _, err := core.Bounded(); !errors.Is(err, ErrBoundOverLimit) {
				t.Fatalf("the time under a MaxBound of 100 us: %v", err)
			}
			if err := core.SetPolicy(ProtocolNTS, 100*time.Millisecond, 100*time.Millisecond, w.coarseNow(), w.now); err != nil {
				t.Fatal(err)
			}
			if _, _, err := core.Bounded(); err != nil {
				t.Fatalf("the time under the first bounds again: %v", err)
			}
			continue
		}
		if st.HaveResult || !st.Cold || !errors.Is(st.LastErr, ErrQuorumTooFew) {
			t.Fatalf("3 servers: %+v", st)
		}
		if _, _, err := core.Bounded(); !errors.Is(err, ErrNoQuorum) {
			t.Fatalf("3 servers: a time: %v", err)
		}
	}
}

// A new protocol starts the core over, failing closed: every association,
// sample, the quorum in force and the drift history go; the poll times
// stay; and the time never goes back.
func TestSetPolicyProtocolChange(t *testing.T) {
	if !PlainSupported() {
		t.Skip("the core was built without plain NTP")
	}
	w, core := newHonestCore(t, 4, func(c *Config) { c.StartWait = time.Minute })
	for r := 0; r < 3; r++ {
		if err := w.round(core); err != nil {
			t.Fatal(err)
		}
		w.now += int64(honestInterval)
	}
	highest, _, err := core.Bounded()
	if err != nil {
		t.Fatal(err)
	}
	before := core.Status()
	if before.Protocol != ProtocolNTS || !before.HaveDrift {
		t.Fatalf("before: %+v", before)
	}
	if err := core.SetPolicy(ProtocolNTP, 100*time.Millisecond, 100*time.Millisecond, w.coarseNow(), w.now); err != nil {
		t.Fatal(err)
	}
	w.plain = true
	st := core.Status()
	if st.Protocol != ProtocolNTP || st.HaveResult || st.HaveDrift || !st.Cold || !errors.Is(st.LastErr, ErrNoQuorum) || st.EraPivot < before.EraPivot {
		t.Fatalf("after the change: %+v", st)
	}
	for i, ps := range st.Peers {
		if ps.Sample != nil || ps.Cookies != 0 || ps.NeedKE || ps.NextPoll != before.Peers[i].NextPoll || ps.Poll != before.Peers[i].Poll {
			t.Fatalf("after the change: peer %d %+v", i, ps)
		}
	}
	if _, _, err := core.Bounded(); !errors.Is(err, ErrNoQuorum) {
		t.Fatalf("a time across the change: %v", err)
	}
	// The old samples are gone: a combine at once has nothing.
	if err := core.Combine(w.coarseNow(), w.now); !errors.Is(err, ErrQuorumTooFew) {
		t.Fatalf("a combine at once: %v", err)
	}
	// The servers 10 s back on the new protocol: the history is gone, so
	// the quorum serves; the time stays at the highest served before.
	for _, s := range w.servers {
		s.offset = -int64(10 * time.Second)
	}
	kes := w.kes
	if err := w.round(core); err != nil {
		t.Fatal(err)
	}
	st = core.Status()
	if w.kes != kes || st.Protocol != ProtocolNTP || st.Cold || st.Peers[0].NTPAddr != "nts-a.test:123" || st.Peers[0].Cookies != 0 {
		t.Fatalf("on plain NTP: %d key exchanges, %+v", w.kes-kes, st)
	}
	if tm, _, err := core.Bounded(); err != nil || !tm.Equal(highest) {
		t.Fatalf("served %v, the highest before the change was %v (%v)", tm, highest, err)
	}
	// And back: again nothing of the other protocol is left.
	if err := core.SetPolicy(ProtocolNTS, 100*time.Millisecond, 100*time.Millisecond, w.coarseNow(), w.now); err != nil {
		t.Fatal(err)
	}
	w.plain = false
	if st := core.Status(); st.HaveResult || st.Peers[0].Sample != nil || !st.Peers[0].NeedKE || st.Protocol != ProtocolNTS {
		t.Fatalf("back on NTS: %+v", st)
	}
	for _, s := range w.servers {
		s.offset = 0
	}
	w.now += int64(honestInterval)
	if err := w.round(core); err != nil {
		t.Fatal(err)
	}
	if st := core.Status(); st.Peers[0].Stats.KEOK != 2 || st.Peers[0].Cookies != MaxCookies {
		t.Fatalf("back on NTS, after a round: %+v", st.Peers[0])
	}
}

// A build without plain NTP refuses it as a protocol, at the start and on
// a running core, and says so.
func TestPlainRefusedByTheBuild(t *testing.T) {
	if PlainSupported() {
		t.Skip("the core was built with plain NTP (make -C ../c noplain and the tag ntsnoplain build the other)")
	}
	cfg := Config{
		Servers:  []Server{{Operator: "a", Host: "a.test"}, {Operator: "b", Host: "b.test"}, {Operator: "c", Host: "c.test"}},
		Interval: time.Second, MinPoll: time.Second, MaxPoll: time.Minute, MaxBound: 100 * time.Millisecond, MaxAge: time.Minute,
		MaxCoarseDiff: time.Second, CoarseResolution: time.Second, ExchangeTimeout: time.Second, DriftBaselinePolls: 1, FloorUnix: hostileFloor,
		Protocol: ProtocolNTP,
	}
	if _, err := New(cfg, &hostileWorld{}); !errors.Is(err, ErrBadConfig) {
		t.Fatalf("plain NTP at the start: %v", err)
	}
	w, core := newHonestCore(t, 3, nil)
	if err := w.round(core); err != nil {
		t.Fatal(err)
	}
	before := core.Status()
	if err := core.SetPolicy(ProtocolNTP, 100*time.Millisecond, 100*time.Millisecond, w.coarseNow(), w.now); !errors.Is(err, ErrBadConfig) {
		t.Fatalf("plain NTP on a running core: %v", err)
	}
	if diff := sameClient(before, core.Status()); diff != "" || core.Status().Protocol != ProtocolNTS {
		t.Fatalf("refused, and %s changed", diff)
	}
	if _, _, err := core.Bounded(); err != nil {
		t.Fatal(err)
	}
}

// The start state after a configuration call left no quorum: a failed key
// exchange is tried again after about an interval, without backoff, until
// StartWait is over; then the backoff applies, quorum or not. A quorum
// ends it sooner.
func TestStartStateAfterAConfigurationCall(t *testing.T) {
	const startWait = 20 * time.Second
	start := func() (*hostileWorld, *Core) {
		w, core := newHonestCore(t, 3, func(c *Config) { c.StartWait = startWait })
		if err := w.round(core); err != nil {
			t.Fatal(err)
		}
		if core.Status().Cold {
			t.Fatal("cold after the first quorum")
		}
		for _, s := range w.servers {
			s.rename(fmt.Sprintf("new-%s.test", s.op))
		}
		if err := w.swap(core, w.servers...); err != nil {
			t.Fatal(err)
		}
		if st := core.Status(); !st.Cold || st.HaveResult {
			t.Fatalf("after the swap: %+v", st)
		}
		return w, core
	}
	w, core := start()
	began := w.now
	w.keFail = 1000
	// In the start state every retry comes within 5/4 of the interval.
	for w.now-began < int64(startWait)-int64(3*honestInterval) {
		ps, err := w.poll(core, 0)
		if !errors.Is(err, ErrHost) {
			t.Fatalf("a failed key exchange in the start state: %v", err)
		}
		if wait := time.Duration(ps.NextKE - w.now); wait < honestInterval*3/4-time.Millisecond || wait > honestInterval*5/4 {
			t.Fatalf("%v into the start state: the next key exchange in %v", time.Duration(w.now-began), wait)
		}
		w.now = ps.NextKE
	}
	if !core.Summary().Cold {
		t.Fatal("not cold before the start wait is over")
	}
	// Past StartWait the failures back off, though no combine has run.
	w.now = began + int64(startWait) + int64(time.Second)
	var waits []time.Duration
	for k := 0; k < 4; k++ {
		ps, err := w.poll(core, 0)
		if !errors.Is(err, ErrHost) {
			t.Fatalf("a failed key exchange after the start state: %v", err)
		}
		waits = append(waits, time.Duration(ps.NextKE-w.now))
		w.now = ps.NextKE
	}
	if !about(waits[1], 2*waits[0]) || !about(waits[2], 4*waits[0]) || !about(waits[3], 8*waits[0]) || waits[0] < 2*honestInterval*3/4-time.Millisecond {
		t.Fatalf("after the start state the waits are %v, want them doubling", waits)
	}
	if st := core.Summary(); st.Cold {
		t.Fatalf("still cold after the start wait: %+v", st)
	}
	// A combine notes the end of the start state as well.
	if err := core.Combine(w.coarseNow(), w.now); !errors.Is(err, ErrQuorumTooFew) || core.Status().Cold {
		t.Fatalf("a combine after the start wait: %v", err)
	}

	// A quorum ends the start state at once.
	w, core = start()
	w.now += int64(honestInterval)
	if err := w.round(core); err != nil {
		t.Fatal(err)
	}
	if st := core.Status(); st.Cold || !st.HaveResult {
		t.Fatalf("after a quorum: %+v", st)
	}
	w.drop = lostToSpend
	for k := 0; k < lostToSpend; k++ {
		w.now += int64(honestInterval)
		w.poll(core, 0)
	}
	w.keFail = 2
	w.now += int64(honestInterval)
	ps, err := w.poll(core, 0)
	if !errors.Is(err, ErrHost) || !about(time.Duration(ps.NextKE-w.now), honestInterval) {
		t.Fatalf("a failed key exchange after the quorum: %v, next in %v", err, time.Duration(ps.NextKE-w.now))
	}
	w.now = ps.NextKE
	if ps, err := w.poll(core, 0); !errors.Is(err, ErrHost) || !about(time.Duration(ps.NextKE-w.now), 2*honestInterval) {
		t.Fatalf("the second failure after the quorum: %v, next in %v", err, time.Duration(ps.NextKE-w.now))
	}

	// Without a StartWait a configuration call begins no start state.
	w, core = newHonestCore(t, 3, nil)
	if err := w.round(core); err != nil {
		t.Fatal(err)
	}
	if err := w.swap(core, w.servers[0], w.servers[1]); err != nil {
		t.Fatal(err)
	}
	if st := core.Status(); st.Cold || st.HaveResult {
		t.Fatalf("no StartWait: %+v", st)
	}
}

// An exchange the host's caller cancelled is no loss: no error, no loss
// streak, no key exchange failure and no backoff; the peer stays due; a
// cookie that went out stays spent (the harness fails on one sent twice).
func TestCancelledExchangeCostsNothing(t *testing.T) {
	w, core := newHonestCore(t, 3, nil)
	// The first key exchange, cancelled: tried again at once.
	w.cancelAt = 1
	ps, err := w.poll(core, 0)
	if !errors.Is(err, ErrHostCancelled) || ClassOf(err.(*Error).Code) != ClassHost || ps.Stats.KEFail != 0 || ps.NextKE != 0 || ps.Stats.Queries != 0 ||
		!errors.Is(ps.LastErr, ErrHostCancelled) {
		t.Fatalf("a cancelled key exchange: %v, %+v", err, ps)
	}
	w.cancelAt = 0
	if ps, err := w.poll(core, 0); err != nil || ps.Stats.KEOK != 1 {
		t.Fatalf("the key exchange again at once: %v, %+v", err, ps)
	}
	// The query, cancelled at the open, the send and the receive.
	for op, spent := range map[int]int{2: 0, 3: 1, 4: 1} {
		was := core.Peer(0)
		w.cancelAt = op
		w.now += int64(honestInterval)
		ps, err := w.poll(core, 0)
		if !errors.Is(err, ErrHostCancelled) {
			t.Fatalf("cancelled at operation %d: %v", op, err)
		}
		if ps.Stats.Errors != 0 || ps.LostInRow != 0 || ps.NextPoll != was.NextPoll || ps.Cookies != was.Cookies-spent || ps.Stats.Queries != was.Stats.Queries+1 ||
			ps.Sample == nil || *ps.Sample != *was.Sample || ps.Poll != was.Poll {
			t.Fatalf("cancelled at operation %d: %+v, was %+v", op, ps, was)
		}
		if !slices.Contains(core.Due(w.now), 0) {
			t.Fatalf("cancelled at operation %d: the peer is not due", op)
		}
		w.cancelAt = 0
		if ps, err := w.poll(core, 0); err != nil || ps.Cookies != MaxCookies {
			t.Fatalf("after the cancel at operation %d: %v, %+v", op, err, ps)
		}
	}
	// The key exchange of a loss streak, cancelled, is not used up: the
	// next poll runs it.
	w.drop = KEAfterLost
	for k := 0; k < KEAfterLost; k++ {
		w.now += int64(honestInterval)
		w.poll(core, 0)
	}
	w.cancelAt = 1
	w.now += int64(honestInterval)
	ps, err = w.poll(core, 0)
	if !errors.Is(err, ErrHostCancelled) || ps.Stats.KEFail != 0 || ps.Cookies != MaxCookies-KEAfterLost || ps.LostInRow != KEAfterLost || ps.NextKE != 0 {
		t.Fatalf("the streak's key exchange, cancelled: %v, %+v", err, ps)
	}
	w.cancelAt = 0
	if ps, err := w.poll(core, 0); err != nil || ps.Stats.KEOK != 2 || ps.LostInRow != 0 {
		t.Fatalf("the streak's key exchange again: %v, %+v", err, ps)
	}
	// Another peer's first key exchange, cancelled, leaves no wait either.
	w.cancelAt = 1
	if ps, err := w.poll(core, 1); !errors.Is(err, ErrHostCancelled) || ps.NextKE != 0 {
		t.Fatalf("a cancelled key exchange of another peer: %v, %+v", err, ps)
	}
}

// The query timeout of the configuration is what the host is given for a
// query; without it, the shorter of the exchange timeout and half the
// interval.
func TestQueryTimeout(t *testing.T) {
	for _, c := range []struct{ set, want time.Duration }{{0, time.Second}, {300 * time.Millisecond, 300 * time.Millisecond}, {3 * time.Second, 3 * time.Second}} {
		w, core := newHonestCore(t, 3, func(cfg *Config) { cfg.QueryTimeout = c.set })
		if _, err := w.poll(core, 0); err != nil {
			t.Fatal(err)
		}
		if w.openTimeout != c.want {
			t.Fatalf("QueryTimeout %v: the socket was opened with %v, want %v", c.set, w.openTimeout, c.want)
		}
		// A lost answer costs that long, no more.
		w.drop = 1
		w.now += int64(honestInterval)
		at := w.now
		if _, err := w.poll(core, 0); !errors.Is(err, ErrHostTimeout) {
			t.Fatal(err)
		}
		if took := time.Duration(w.now - at); took < c.want || took > c.want+100*time.Millisecond {
			t.Fatalf("QueryTimeout %v: a lost answer took %v", c.set, took)
		}
	}
}

// Plain NTP as the core's protocol: no key exchange, the header alone to
// the server's NTP address (or its host on port 123), and the quorum, the
// bound and the checks as with NTS. The status says which protocol the
// time is from.
func TestPlainNTPClient(t *testing.T) {
	if !PlainSupported() {
		t.Skip("the core was built without plain NTP")
	}
	w, core := newHonestCore(t, 4, func(c *Config) {
		c.Protocol = ProtocolNTP
		c.Servers[1].NTPAddr = "192.0.2.7:1123"
	})
	w.servers[1].ntpAddr = "192.0.2.7:1123"
	for r := 0; r < 3; r++ {
		if err := w.round(core); err != nil {
			t.Fatal(err)
		}
		w.now += int64(honestInterval)
	}
	st := core.Status()
	if st.Protocol != ProtocolNTP || len(st.Members) != 4 || st.MaxWrong != 1 || w.kes != 0 || !st.HaveDrift {
		t.Fatalf("plain NTP: %d key exchanges, %+v", w.kes, st)
	}
	for i, ps := range st.Peers {
		want := fmt.Sprintf("nts-%s.test:123", w.servers[i].op)
		if i == 1 {
			want = "192.0.2.7:1123"
		}
		if ps.NTPAddr != want || ps.Cookies != 0 || ps.NeedKE || ps.Stats.KEOK != 0 || ps.Stats.Samples != 3 || ps.Sample.CookiesReceived != 0 || ps.Sample.CookiesHeld != 0 {
			t.Fatalf("plain NTP: peer %d %+v", i, ps)
		}
	}
	tm, bound, err := core.Bounded()
	if err != nil || !within(tm, bound, w.trueNow()) {
		t.Fatalf("plain NTP: served %v with bound %v, true %v (%v)", tm, bound, time.Unix(0, w.trueNow()), err)
	}
	// A liar is outvoted as with NTS, and a lost answer is a loss, without
	// any key exchange for a streak of them.
	w.servers[0].offset = int64(time.Hour)
	w.drop = KEAfterLost + 2
	for k := 0; k < KEAfterLost+2; k++ {
		if _, err := w.poll(core, 3); !errors.Is(err, ErrHostTimeout) {
			t.Fatalf("a lost plain answer: %v", err)
		}
		w.now += int64(honestInterval)
	}
	if ps := core.Peer(3); ps.LostInRow != KEAfterLost+2 || w.kes != 0 || ps.Stats.Errors != KEAfterLost+2 {
		t.Fatalf("plain NTP after lost answers: %+v", ps)
	}
	if err := w.round(core); err != nil {
		t.Fatal(err)
	}
	if tm, bound, err := core.Bounded(); err != nil || !within(tm, bound, w.trueNow()) {
		t.Fatalf("plain NTP with a liar: served %v, true %v (%v)", tm, time.Unix(0, w.trueNow()), err)
	}
	// The coarse check is the limit that is left: every server an hour off
	// together is refused by it.
	for _, s := range w.servers {
		s.offset = int64(time.Hour)
	}
	w.now += int64(honestInterval)
	if err := w.round(core); !errors.Is(err, ErrCoarseCheck) {
		t.Fatalf("plain NTP, every server an hour off: %v", err)
	}
	if _, _, err := core.Bounded(); !errors.Is(err, ErrNoQuorum) {
		t.Fatalf("plain NTP, a time after the coarse refusal: %v", err)
	}
}

// Under plain NTP no Kiss-o'-Death can be authenticated, and RATE, DENY
// and RSTR are obeyed as they come: RATE doubles the poll up to MaxPoll,
// DENY and RSTR stop the server for MaxPoll and drop its sample. NTSN and
// unknown codes are only counted. A kiss ends the query: the answer after
// it is not taken.
func TestPlainNTPKissCodes(t *testing.T) {
	if !PlainSupported() {
		t.Skip("the core was built without plain NTP")
	}
	plain := func(c *Config) { c.Protocol = ProtocolNTP }
	for _, code := range []string{"DENY", "RSTR"} {
		w, core := newHonestCore(t, 3, plain)
		if _, err := w.poll(core, 0); err != nil {
			t.Fatal(err)
		}
		w.kiss = code
		w.now += int64(honestInterval)
		ps, err := w.poll(core, 0)
		var e *Error
		if !errors.As(err, &e) || !errors.Is(err, ErrKiss) || e.Kiss != code || e.KissAuthentic {
			t.Fatalf("%s: %v", code, err)
		}
		if ps.Disabled != code || ps.Poll != honestMaxPoll || ps.Sample != nil || ps.Stats.Kisses[code] != 1 {
			t.Fatalf("%s: %+v", code, ps)
		}
		w.kiss = ""
		w.now += int64(honestMaxPoll - time.Second)
		if slices.Contains(core.Due(w.now), 0) {
			t.Fatalf("%s: due again before MaxPoll", code)
		}
		w.now += int64(2 * time.Second)
		if ps, err := w.poll(core, 0); err != nil || ps.Disabled != "" || ps.Sample == nil {
			t.Fatalf("%s, after MaxPoll: %+v, %v", code, ps, err)
		}
	}
	w, core := newHonestCore(t, 3, plain)
	if _, err := w.poll(core, 0); err != nil {
		t.Fatal(err)
	}
	w.kiss = "RATE"
	for _, want := range []time.Duration{4, 8, 16, 32, 64, 64} {
		w.now += int64(honestMaxPoll)
		ps, _ := w.poll(core, 0)
		if ps.Poll != want*time.Second || ps.Disabled != "" || ps.Sample == nil {
			t.Fatalf("RATE: poll %v, want %v (%+v)", ps.Poll, want*time.Second, ps)
		}
	}
	// Each good answer halves it back.
	w.kiss = ""
	w.now += int64(honestMaxPoll)
	if ps, err := w.poll(core, 0); err != nil || ps.Poll != 32*time.Second {
		t.Fatalf("after RATE, a good answer: %v, %+v", err, ps)
	}
	for code, counted := range map[string]string{"NTSN": "NTSN", "NTS\x00": "NTSN", "STEP": "OTHER"} {
		w, core := newHonestCore(t, 3, plain)
		if _, err := w.poll(core, 0); err != nil {
			t.Fatal(err)
		}
		w.kissThenAnswer = code
		w.now += int64(honestInterval)
		at := w.now
		ps, err := w.poll(core, 0)
		if !errors.Is(err, ErrKiss) || ps.Stats.Kisses[counted] != 1 || ps.Poll != honestInterval || ps.Disabled != "" || ps.Sample == nil || ps.Stats.Samples != 1 ||
			ps.LostInRow != 0 || ps.Stats.Errors != 0 {
			t.Fatalf("%q: %v, %+v", code, err, ps)
		}
		// The kiss ended the query at once: no grace, no timeout.
		if took := time.Duration(w.now - at); took > 100*time.Millisecond {
			t.Fatalf("%q: the query took %v", code, took)
		}
	}
}

// Under NTS an unauthenticated Kiss-o'-Death is only counted, whatever its
// code (the branch's rule, kept): no backoff, no stop, the keys stay.
func TestUnauthenticatedKissIsOnlyCountedUnderNTS(t *testing.T) {
	for _, code := range []string{"RATE", "DENY", "RSTR", "NTSN", "NTS\x00"} {
		w, core := newHonestCore(t, 3, nil)
		if _, err := w.poll(core, 0); err != nil {
			t.Fatal(err)
		}
		w.plainKiss = code
		w.now += int64(honestInterval)
		ps, err := w.poll(core, 0)
		var e *Error
		if !errors.As(err, &e) || !errors.Is(err, ErrKiss) || e.KissAuthentic {
			t.Fatalf("%q: %v", code, err)
		}
		counted := code
		if code == "NTS\x00" {
			counted = "NTSN"
		}
		if e.Kiss != counted || ps.Stats.Kisses[counted] != 1 || ps.Poll != honestInterval || ps.Disabled != "" || ps.Sample == nil || ps.Cookies != MaxCookies-1 ||
			ps.NeedKE || ps.Stats.KEOK != 1 {
			t.Fatalf("%q: %v, %+v", code, err, ps)
		}
		w.plainKiss = ""
		w.now += int64(honestInterval)
		if ps, err := w.poll(core, 0); err != nil || ps.Stats.KEOK != 1 || ps.Cookies != MaxCookies {
			t.Fatalf("%q, the next poll: %v, %+v", code, err, ps)
		}
	}
}

// The texts of the quorum's refusals are main's (#193), and the new codes
// have their class.
func TestPortedReasonTexts(t *testing.T) {
	if got := ErrQuorumTooFew.Error(); got != "too few servers: at least 3, and over twice the number allowed wrong" {
		t.Fatalf("too few: %q", got)
	}
	if got := ErrNoAgreement.Error(); got != "the servers disagree: too many wrong" {
		t.Fatalf("no agreement: %q", got)
	}
	if ClassOf(codeHostCancelled) != ClassHost || ClassOf(codeEraWindow) != ClassClient || ClassOf(codeSampleWide) != ClassClient {
		t.Fatal("the classes of the new codes")
	}
	if codeHostCancelled != 93 || codeEraWindow != 111 || codeSampleWide != 112 {
		t.Fatalf("the new codes: %d, %d, %d", codeHostCancelled, codeEraWindow, codeSampleWide)
	}
	if s := CodeError(codeEraWindow, 0).Error(); !strings.Contains(s, "before the floor") {
		t.Fatalf("era window, detail 0: %q", s)
	}
	if s := CodeError(codeEraWindow, 1).Error(); !strings.Contains(s, "after the era pivot") {
		t.Fatalf("era window, detail 1: %q", s)
	}
	if ProtocolNTS.String() != "nts" || ProtocolNTP.String() != "ntp" || Protocol(7).String() != "protocol(7)" {
		t.Fatal("the protocols' names")
	}
}

// The edges of the era window, to the nanosecond. The world is
// deterministic, so the quorum time of its first round is known from one
// run; the floor, which is the era pivot until a time is served, is then
// set around it. A quorum time exactly EraWindow after the pivot is
// served and one nanosecond more is refused; a quorum time at the floor is
// served and one a nanosecond before it is refused.
func TestEraWindowExactEdges(t *testing.T) {
	if EraWindow != 20*8766*time.Hour {
		t.Fatalf("the era window is %v, want 20 years of 8766 hours", EraWindow)
	}
	// The coarse reading is ten seconds ahead of the truth (within the
	// coarse check), so that it dates the certificates after a floor that
	// lies at the quorum time itself.
	first := func(floor time.Time) (Status, error) {
		w, core := newHonestCore(t, 3, func(c *Config) {
			if !floor.IsZero() {
				c.FloorUnix = floor
			}
		})
		for i := range w.servers {
			w.coarse, w.coarseLocal = w.trueNow()+int64(10*time.Second), w.now
			if _, err := core.Poll(i, time.Unix(0, w.coarse), w.coarseLocal); err != nil || w.failed != nil {
				t.Fatalf("floor %v, peer %d: %v, %v", floor, i, err, w.failed)
			}
		}
		err := core.Combine(time.Unix(0, w.coarse), w.coarseLocal)
		return core.Status(), err
	}
	st, err := first(time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	at := st.At + st.Offset // the quorum time
	for _, c := range []struct {
		name  string
		floor int64
		text  string // "" for served
	}{
		{"exactly the window after the pivot", at - int64(EraWindow), ""},
		{"1 ns over the window", at - int64(EraWindow) - 1, "after the era pivot"},
		{"1 s over the window", at - int64(EraWindow) - int64(time.Second), "after the era pivot"},
		{"at the floor", at, ""},
		{"1 ns before the floor", at + 1, "before the floor"},
	} {
		st, err := first(time.Unix(0, c.floor))
		if c.text == "" {
			if err != nil || !st.HaveResult || st.At+st.Offset != at || st.EraPivot != at {
				t.Fatalf("%s: %v; quorum time %d, want %d; pivot %d", c.name, err, st.At+st.Offset, at, st.EraPivot)
			}
			continue
		}
		if !errors.Is(err, ErrEraWindow) || !strings.Contains(err.Error(), c.text) || st.HaveResult || st.EraPivot != c.floor || st.HaveCoarseDiff {
			t.Fatalf("%s: %v, %+v", c.name, err, st)
		}
	}
}

// The edge of the receipt bound, to the nanosecond. The bound the first
// answer of the world gets is known from one run; the cap is then set so
// that the receipt bound (the cap less the aging over the join age, or
// half the cap if that is more) is that bound, or a nanosecond under it.
// At the bound the answer is taken, a nanosecond over it is refused as
// wide; and a sample taken leaves when SetPolicy moves the receipt bound a
// nanosecond under it, and stays when it does not.
func TestReceiptBoundExactEdge(t *testing.T) {
	const joinAge, longJoin = 40 * time.Second, 5 * time.Minute
	run := func(cap, join time.Duration) (*hostileWorld, *Core, PeerStatus, error) {
		w, core := newHonestCore(t, 3, func(c *Config) {
			c.MaxBound, c.MaxSampleBound, c.MaxAge, c.JoinAge = 10*time.Millisecond, cap, 10*time.Minute, join
		})
		w.rootDispersion = dispersion(77 * time.Millisecond)
		ps, err := w.poll(core, 0)
		return w, core, ps, err
	}
	_, _, ps, err := run(MaxSampleBound, joinAge)
	if err != nil {
		t.Fatal(err)
	}
	b := ps.Sample.Bound
	if b < 77*time.Millisecond || b > 80*time.Millisecond {
		t.Fatalf("the bound of the world's first answer: %v", b)
	}
	for _, c := range []struct {
		name string
		cap  time.Duration // its receipt bound is b
		join time.Duration
	}{
		// 500 ppm of 40 s is 20 ms: the cap less the aging.
		{"the cap less the aging", b + Drift(joinAge), joinAge},
		// 500 ppm of 5 minutes is 150 ms, over the cap: half the cap. An
		// odd cap halves down, so 2b - 1 gives b - 1.
		{"half the cap", 2 * b, longJoin},
	} {
		if Drift(joinAge) != 20*time.Millisecond || Drift(longJoin) != 150*time.Millisecond {
			t.Fatalf("aging: %v over %v, %v over %v", Drift(joinAge), joinAge, Drift(longJoin), longJoin)
		}
		w, core, ps, err := run(c.cap, c.join)
		if err != nil || ps.Sample == nil || ps.Sample.Bound != b || ps.Stats.Wide != 0 {
			t.Fatalf("%s: an answer at the receipt bound %v: %v, %+v", c.name, b, err, ps)
		}
		// The same cap again keeps the sample; a nanosecond less drops it.
		if err := core.SetPolicy(ProtocolNTS, 10*time.Millisecond, c.cap, w.coarseNow(), w.now); err != nil || core.Peer(0).Sample == nil {
			t.Fatalf("%s: SetPolicy with the same cap: %v, %+v", c.name, err, core.Peer(0))
		}
		if err := core.SetPolicy(ProtocolNTS, 10*time.Millisecond, c.cap-1, w.coarseNow(), w.now); err != nil || core.Peer(0).Sample != nil {
			t.Fatalf("%s: SetPolicy with the cap 1 ns less: %v, %+v", c.name, err, core.Peer(0))
		}
		_, _, ps, err = run(c.cap-1, c.join)
		if !errors.Is(err, ErrSampleWide) || ps.Sample != nil || ps.Stats.Wide != 1 || ps.Stats.LastBound != b {
			t.Fatalf("%s: an answer 1 ns over the receipt bound: %v, %+v", c.name, err, ps)
		}
	}
}

// The edges of the two ages, to the nanosecond: a sample exactly JoinAge
// old joins a quorum and one a nanosecond older does not; the quorum
// serves while its oldest sample is exactly MaxAge old and is refused a
// nanosecond later. The virtual clock moves a microsecond for each reading
// the core takes, and a combine and Bounded take one each.
func TestJoinAgeAndMaxAgeExactEdges(t *testing.T) {
	const joinAge, maxAge, read = 6 * time.Second, 10 * time.Second, time.Microsecond
	w, core := newHonestCore(t, 3, func(c *Config) { c.JoinAge, c.MaxAge = joinAge, maxAge })
	oldest := int64(0)
	for i := range w.servers {
		ps, err := w.poll(core, i)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			oldest = ps.Sample.T4
		}
	}
	// The combine reads the clock at exactly oldest + JoinAge.
	w.now = oldest + int64(joinAge) - int64(read)
	if err := core.Combine(w.coarseNow(), w.now); err != nil {
		t.Fatalf("the oldest sample exactly JoinAge old: %v", err)
	}
	if st := core.Status(); st.At != oldest+int64(joinAge) || st.LastFresh != 3 || st.Sampled != oldest || len(st.Members) != 3 {
		t.Fatalf("the oldest sample exactly JoinAge old: %+v", st)
	}
	// One nanosecond on, the oldest sample is out: two are too few.
	w.now = oldest + int64(joinAge) - int64(read) + 1
	if err := core.Combine(w.coarseNow(), w.now); !errors.Is(err, ErrQuorumTooFew) {
		t.Fatalf("the oldest sample 1 ns over JoinAge: %v", err)
	}
	if st := core.Status(); st.LastFresh != 2 || !st.HaveResult || st.At != oldest+int64(joinAge) {
		t.Fatalf("the oldest sample 1 ns over JoinAge: %+v", st)
	}
	// The quorum formed at the edge serves until its oldest sample is
	// MaxAge old, to the nanosecond.
	w.now = oldest + int64(maxAge) - int64(read)
	if _, _, err := core.Bounded(); err != nil {
		t.Fatalf("the oldest sample exactly MaxAge old: %v", err)
	}
	if w.now != oldest+int64(maxAge) {
		t.Fatalf("Bounded read the clock %d times", (w.now-oldest-int64(maxAge))/int64(read)+1)
	}
	w.now = oldest + int64(maxAge) - int64(read) + 1
	if _, _, err := core.Bounded(); !errors.Is(err, ErrSamplesTooOld) {
		t.Fatalf("the oldest sample 1 ns over MaxAge: %v", err)
	}
}
