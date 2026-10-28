//go:build nts

package clock

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/trusted-time/nts"
	"github.com/lidofinance/tee-signer/trusted-time/nts/ntstest"
)

// coarseClock plays the HTTPS-date quorum: the host clock plus Skew, or Err.
type coarseClock struct {
	Skew time.Duration
	Err  error
}

func (c *coarseClock) Now() (time.Time, error) {
	if c.Err != nil {
		return time.Time{}, c.Err
	}
	return testClock().Add(c.Skew), nil
}

type fakeServer struct {
	store *ntstest.Store
	ke    *ntstest.KEServer
	ntp   *ntstest.NTPServer
	srv   NTSServer
}

// newServers starts one loopback KE + NTP pair per operator, each with its
// own CA and the given NTP options.
func newServers(t *testing.T, opts map[string]ntstest.NTPOptions, order ...string) []*fakeServer {
	t.Helper()
	var out []*fakeServer
	for _, op := range order {
		cert, pool, err := ntstest.Certificate("nts.test", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		f := &fakeServer{store: ntstest.NewStore()}
		if f.ntp, err = ntstest.StartNTP(f.store, opt(opts[op])); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(f.ntp.Close)
		if f.ke, err = ntstest.StartKE(cert, f.store, ntstest.KEOptions{NTPServer: "127.0.0.1", NTPPort: f.ntp.Port}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(f.ke.Close)
		f.srv = NTSServer{Host: "nts.test", Operator: op, Roots: pool, KEAddr: f.ke.Addr}
		out = append(out, f)
	}
	return out
}

func newNTS(fs []*fakeServer, coarse *coarseClock) *NTS {
	n := &NTS{Coarse: coarse, Interval: 50 * time.Millisecond, minPoll: 10 * time.Millisecond}
	for _, f := range fs {
		n.Servers = append(n.Servers, f.srv)
	}
	return n
}

func refresh(t *testing.T, n *NTS) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return n.Refresh(ctx)
}

func TestNTSClockQuorum(t *testing.T) {
	fs := newServers(t, nil, "a", "b", "c")
	n := newNTS(fs, &coarseClock{})
	if _, err := n.Now(); err == nil {
		t.Fatal("time before the first quorum")
	}
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	got, bound, err := n.Bounded()
	if err != nil {
		t.Fatal(err)
	}
	if d := testClock().Sub(got); d.Abs() > bound+5*time.Millisecond {
		t.Fatalf("NTS time %v from the host clock, bound %v", d, bound)
	}
	st := n.Status()
	if len(st.Members) != 3 || bound > NTSMaxBound {
		t.Fatalf("status %+v", st)
	}
	t.Logf("bound %v, members %v", bound, st.Members)
	sum := n.NTSSummary()
	if !sum.Quorum || len(sum.Members) != 3 || sum.BoundNow < bound || sum.BoundNow > bound+time.Millisecond ||
		sum.MaxBound != NTSMaxBound || (sum.OffsetFromHost-st.OffsetFromHost).Abs() > 5*time.Millisecond {
		t.Fatalf("summary %+v, status %+v", sum, st)
	}
	if !n.Trusted() || n.Source() != "nts(a,b,c)" {
		t.Fatal(n.Source())
	}
}

func TestNTSClockOneServerWrong(t *testing.T) {
	fs := newServers(t, map[string]ntstest.NTPOptions{"liar": {Offset: 5 * time.Second}}, "a", "b", "c", "liar")
	n := newNTS(fs, &coarseClock{})
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	got, bound, err := n.Bounded()
	if err != nil {
		t.Fatal(err)
	}
	if d := testClock().Sub(got); d.Abs() > bound+5*time.Millisecond || bound > NTSMaxBound {
		t.Fatalf("one server 5 s ahead moved the time by %v (bound %v)", d, bound)
	}
}

func TestNTSClockTwoWrongGiveNoTime(t *testing.T) {
	fs := newServers(t, map[string]ntstest.NTPOptions{"b": {Offset: 5 * time.Second}, "c": {Offset: 10 * time.Second}}, "a", "b", "c")
	n := newNTS(fs, &coarseClock{})
	if err := refresh(t, n); err == nil || !strings.Contains(err.Error(), "disagree") {
		t.Fatalf("got %v", err)
	}
	if _, err := n.Now(); err == nil {
		t.Fatal("time without a quorum")
	}
}

func TestNTSClockBoundGrowsUntilNowFails(t *testing.T) {
	fs := newServers(t, nil, "a", "b", "c")
	n := newNTS(fs, &coarseClock{})
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	_, b0, err := n.Bounded()
	if err != nil {
		t.Fatal(err)
	}
	// 100 s later on the local clock: + 50 ms (500 ppm).
	var ahead int64 = int64(100 * time.Second)
	n.Local = func() int64 { return nts.Monotonic() + ahead }
	_, b1, err := n.Bounded()
	if err != nil {
		t.Fatal(err)
	}
	if grow := b1 - b0; grow < 50*time.Millisecond || grow > 51*time.Millisecond {
		t.Fatalf("bound grew by %v in 100 s", grow)
	}
	ahead = int64(200 * time.Second)
	if _, _, err := n.Bounded(); err == nil || !strings.Contains(err.Error(), "error bound") {
		t.Fatalf("200 s without a quorum: %v", err)
	}
	if n.Status().Refusals != 1 {
		t.Fatal("refusal not counted")
	}
	// HEALTH sees the bound over the limit: no quorum in force, the refusal counted.
	if sum := n.NTSSummary(); sum.Quorum || sum.Refusals != 1 || sum.BoundNow <= NTSMaxBound || sum.AgeOfQuorum < 200*time.Second {
		t.Fatalf("summary %+v", sum)
	}
}

// A coarse source really 31 s off is refused at any fraction of its second;
// one 29.9 s off passes. off is the NTS time minus the coarse source's real
// time, frac how far into its second the source was (the Date header drops
// it).
func TestNTSClockCoarseCheck(t *testing.T) {
	fs := newServers(t, nil, "a", "b", "c")
	for _, c := range []struct {
		off  time.Duration
		pass bool
	}{{31 * time.Second, false}, {-31 * time.Second, false}, {29900 * time.Millisecond, true}, {-29900 * time.Millisecond, true}} {
		for _, frac := range []time.Duration{10 * time.Millisecond, 500 * time.Millisecond, 990 * time.Millisecond} {
			n := newNTS(fs, &coarseClock{Skew: -c.off - frac})
			err := refresh(t, n)
			if c.pass != (err == nil) || (err != nil && !strings.Contains(err.Error(), "coarse clock")) {
				t.Fatalf("NTS %v from the coarse source, %v into its second: %v", c.off, frac, err)
			}
			if _, err := n.Now(); c.pass != (err == nil) {
				t.Fatalf("Now after the coarse check, off %v frac %v: %v", c.off, frac, err)
			}
		}
	}
	if !coarseRefused(31*time.Second, NTSMaxCoarseDiff, NTSCoarseResolution) || coarseRefused(30999*time.Millisecond, NTSMaxCoarseDiff, NTSCoarseResolution) ||
		!coarseRefused(-30001*time.Millisecond, NTSMaxCoarseDiff, NTSCoarseResolution) || coarseRefused(-30*time.Second, NTSMaxCoarseDiff, NTSCoarseResolution) {
		t.Fatal("limits of the coarse check")
	}
	// No coarse time at all: no NTS-KE, no time.
	gs := newServers(t, nil, "a", "b", "c")
	m := newNTS(gs, &coarseClock{Err: errors.New("no https-date")})
	if err := refresh(t, m); err == nil {
		t.Fatal("refresh without coarse time")
	}
	for _, g := range gs {
		if g.ke.Sessions.Load() != 0 {
			t.Fatal("NTS-KE ran without a coarse time")
		}
	}
}

// fixedSource is one coarse source whose reading the test sets.
type fixedSource struct{ read func() time.Time }

func (s fixedSource) Fetch(context.Context) (time.Time, error) { return s.read(), nil }
func (s fixedSource) Name() string                             { return "fixed" }

// The coarse clock (Anchored over an HTTPS-date reading
// truncated to the second) ages its reading on a local clock that runs
// 56,000 ppm slow, as Go's CLOCK_MONOTONIC did under timesyncd in WSL. 40 s
// after the reading (two missed 15 s refreshes) it is 2.24 s behind plus the
// lost fraction of a second: more than the old 2 s limit, inside the new
// one. Aged on a local clock at the real rate, as the runner now does with
// CLOCK_MONOTONIC_RAW, the difference is the fraction only.
func TestNTSClockCoarseSlewedAndTruncated(t *testing.T) {
	const age = 40 * time.Second
	for _, c := range []struct {
		name string
		rate float64 // local clock seconds per real second
		lo   time.Duration
		hi   time.Duration
	}{
		{"slewed", 1 - 56000e-6, 2240*time.Millisecond - 5*time.Millisecond, 3240*time.Millisecond + 5*time.Millisecond},
		{"raw", 1, -5 * time.Millisecond, NTSCoarseResolution + 5*time.Millisecond},
	} {
		t.Run(c.name, func(t *testing.T) {
			fs := newServers(t, nil, "a", "b", "c")
			local := time.Unix(1000, 0)
			coarse := &Anchored{Interval: 15 * time.Second, TrustedSrc: true, Local: func() time.Time { return local }}
			// The reading was taken age ago in real time; the Date header has
			// whole seconds.
			coarse.Src = fixedSource{func() time.Time { return testClock().Add(-age).Truncate(time.Second) }}
			if err := coarse.Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			local = local.Add(time.Duration(float64(age) * c.rate))
			n := &NTS{Coarse: coarse, Interval: 50 * time.Millisecond, minPoll: 10 * time.Millisecond}
			for _, f := range fs {
				n.Servers = append(n.Servers, f.srv)
			}
			err := refresh(t, n)
			diff := n.Status().CoarseDiff
			t.Logf("coarse diff %v, err %v", diff, err)
			if err != nil {
				t.Fatal(err)
			}
			if diff < c.lo || diff > c.hi {
				t.Fatalf("coarse diff %v, want %v to %v", diff, c.lo, c.hi)
			}
			if c.name == "slewed" && diff.Abs() <= 2*time.Second {
				t.Fatalf("diff %v would have passed the old |diff| <= 2 s rule", diff)
			}
		})
	}
}

func TestNTSClockKissCodes(t *testing.T) {
	fs := newServers(t, map[string]ntstest.NTPOptions{"rate": {Kiss: "RATE"}, "deny": {Kiss: "DENY"}}, "a", "b", "c", "rate", "deny")
	n := newNTS(fs, &coarseClock{})
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	st := n.Status()
	if st.Peers["rate"].Poll != 100*time.Millisecond || st.Peers["deny"].Disabled != "DENY" {
		t.Fatalf("rate poll %v, deny %q", st.Peers["rate"].Poll, st.Peers["deny"].Disabled)
	}
	// 60 ms later the others are due again, the RATE server is not (100 ms),
	// and the DENY server never again.
	time.Sleep(60 * time.Millisecond)
	rate, deny := fs[3].ntp.Requests.Load(), fs[4].ntp.Requests.Load()
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	if fs[3].ntp.Requests.Load() != rate || fs[4].ntp.Requests.Load() != deny || fs[0].ntp.Requests.Load() != 2 {
		t.Fatalf("requests: rate %d deny %d a %d", fs[3].ntp.Requests.Load(), fs[4].ntp.Requests.Load(), fs[0].ntp.Requests.Load())
	}
	// Then RATE is lifted: after a good answer the poll halves back.
	fs[3].ntp.Set(opt(ntstest.NTPOptions{}))
	time.Sleep(110 * time.Millisecond)
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	if p := n.Status().Peers["rate"].Poll; p != 50*time.Millisecond {
		t.Fatalf("poll after RATE ended: %v", p)
	}
}

func TestNTSClockNTSNRunsKeyExchangeAgain(t *testing.T) {
	fs := newServers(t, nil, "a", "b", "c")
	n := newNTS(fs, &coarseClock{})
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	fs[0].store.Forget()
	time.Sleep(60 * time.Millisecond)
	_ = refresh(t, n) // a gets NTSN, the quorum uses its earlier sample
	if k := n.Status().Peers["a"].Stats.Kisses["NTSN"]; k != 1 {
		t.Fatalf("NTSN count %d", k)
	}
	time.Sleep(60 * time.Millisecond)
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	if s := fs[0].ke.Sessions.Load(); s != 2 {
		t.Fatalf("NTS-KE sessions with a: %d, want 2", s)
	}
}

// All servers move 300 ms between two quorums 60 ms apart: as seen from
// here, the local clock ran far outside rho. That quorum is refused and Now
// fails; the next quorum, which agrees with it, is served.
func TestNTSClockRefusesWhenLocalClockBreaksRho(t *testing.T) {
	fs := newServers(t, nil, "a", "b", "c")
	n := newNTS(fs, &coarseClock{})
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		f.ntp.Set(opt(ntstest.NTPOptions{Offset: 300 * time.Millisecond}))
	}
	time.Sleep(60 * time.Millisecond)
	if err := refresh(t, n); err == nil || !strings.Contains(err.Error(), "does not keep within 500 ppm") {
		t.Fatalf("300 ms in 60 ms: %v", err)
	}
	if _, err := n.Now(); err == nil {
		t.Fatal("time served after a drift violation")
	}
	st := n.Status()
	if st.RhoViolations != 1 || st.DriftPPM < 1e6 || math.Abs(st.DriftPPM) <= nts.RhoPPM+st.DriftErrPPM {
		t.Fatalf("violations %d, drift %.0f +- %.0f ppm", st.RhoViolations, st.DriftPPM, st.DriftErrPPM)
	}
	time.Sleep(60 * time.Millisecond)
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	got, bound, err := n.Bounded()
	if err != nil {
		t.Fatal(err)
	}
	if d := testClock().Sub(got) + 300*time.Millisecond; d.Abs() > bound+5*time.Millisecond {
		t.Fatalf("after recovery %v from the servers' time", d)
	}
}

// |drift_ppm| can show up to about 1,355 with no rho violation: the reading was the quorum's jitter of a few ms over 8 s, which
// the bounds explain. Here the servers move 5 ms between two quorums 60 ms
// apart, inside bounds of 20 ms. The raw reading is about 83,000 ppm, the
// error from the bounds larger, so no violation, and the status says so:
// |drift| <= rho + err.
func TestNTSClockDriftReadingMatchesCounter(t *testing.T) {
	disp := map[string]ntstest.NTPOptions{}
	for _, op := range []string{"a", "b", "c"} {
		disp[op] = ntstest.NTPOptions{RootDisp: 20 * time.Millisecond}
	}
	fs := newServers(t, disp, "a", "b", "c")
	n := newNTS(fs, &coarseClock{})
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		f.ntp.Set(opt(ntstest.NTPOptions{RootDisp: 20 * time.Millisecond, Offset: 5 * time.Millisecond}))
	}
	time.Sleep(60 * time.Millisecond)
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	st := n.Status()
	t.Logf("drift %.0f +- %.0f ppm over %v, violations %d", st.DriftPPM, st.DriftErrPPM, st.DriftBaseline, st.RhoViolations)
	if st.DriftPPM < 50000 || st.RhoViolations != 0 || math.Abs(st.DriftPPM) > nts.RhoPPM+st.DriftErrPPM || st.DriftBaseline < 50*time.Millisecond {
		t.Fatalf("status %+v", st)
	}
}

// A steady rate far over rho that each short pair hides in its bounds: the
// servers gain 1.5 ms per 60 ms (25,000 ppm), the bounds are about 1 ms, so
// the last pair allows 2 ms. The baseline pair sees 3 ms against about 2 ms
// after two steps and refuses (later under qemu, where the loopback delay
// widens the bounds); the reading shows the failing pair.
func TestNTSClockBaselineCatchesSteadyDrift(t *testing.T) {
	o := ntstest.NTPOptions{RootDisp: time.Millisecond}
	fs := newServers(t, map[string]ntstest.NTPOptions{"a": o, "b": o, "c": o}, "a", "b", "c")
	n := newNTS(fs, &coarseClock{})
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	var err error
	step := 0
	for step = 1; step <= 10; step++ {
		for _, f := range fs {
			o.Offset = time.Duration(step) * 1500 * time.Microsecond
			f.ntp.Set(opt(o))
		}
		time.Sleep(60 * time.Millisecond)
		if err = refresh(t, n); err != nil {
			break
		}
	}
	st := n.Status()
	t.Logf("step %d: %v; drift %.0f +- %.0f ppm over %v", step, err, st.DriftPPM, st.DriftErrPPM, st.DriftBaseline)
	if err == nil || step < 2 || !strings.Contains(err.Error(), "does not keep within") {
		t.Fatalf("25,000 ppm not refused in 10 steps: %v", err)
	}
	if st.RhoViolations != 1 || math.Abs(st.DriftPPM) <= nts.RhoPPM+st.DriftErrPPM || st.DriftBaseline < 100*time.Millisecond {
		t.Fatalf("status %+v", st)
	}
}

func TestNTSClockRefusesDuplicateOperators(t *testing.T) {
	fs := newServers(t, nil, "a", "b", "b")
	n := newNTS(fs, &coarseClock{})
	if err := refresh(t, n); err == nil {
		t.Fatal("quorum of two operators")
	}
}

func TestNTSClockNeverGoesBack(t *testing.T) {
	fs := newServers(t, nil, "a", "b", "c")
	n := newNTS(fs, &coarseClock{})
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	t1, _ := n.Now()
	for _, f := range fs {
		f.ntp.Set(opt(ntstest.NTPOptions{Offset: -500 * time.Millisecond}))
	}
	// The first quorum after the jump fails the drift check, the second
	// agrees with it.
	for i := 0; i < 2; i++ {
		time.Sleep(60 * time.Millisecond)
		_ = refresh(t, n)
	}
	t2, err := n.Now()
	if err != nil {
		t.Fatal(err)
	}
	if t2.Before(t1) {
		t.Fatalf("went back from %v to %v", t1, t2)
	}
}

// The test servers' clock: it runs at the rate of nts.Monotonic
// (CLOCK_MONOTONIC_RAW), as real time does for a correct local clock. The
// host's wall clock may be slewed far from that rate (it was in WSL), which
// the drift check would rightly refuse.
var testStart, testRaw0 = time.Now(), nts.Monotonic()

func testClock() time.Time { return testStart.Add(time.Duration(nts.Monotonic() - testRaw0)) }

func opt(o ntstest.NTPOptions) ntstest.NTPOptions {
	o.Clock = testClock
	return o
}
