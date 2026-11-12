//go:build nts

package clock

import (
	"context"
	"crypto/x509"
	"errors"
	"math"
	"net"
	"strings"
	"sync/atomic"
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
	n := &NTS{Coarse: coarse, Interval: 50 * time.Millisecond, minPoll: 10 * time.Millisecond, StartDelay: -1}
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

// NTSSummary carries the per-host stats of a coarse clock that keeps them.
func TestNTSClockSummaryCoarse(t *testing.T) {
	q := &Quorum{Sources: []Source{&fakeSource{name: "x", t: time.Now()}, &fakeSource{name: "y", err: errors.New("down")}}, Min: 1}
	coarse := &Anchored{Src: q, Interval: time.Second}
	if err := coarse.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	n := &NTS{Coarse: coarse, Servers: []NTSServer{{Host: "a.test", Operator: "a"}}}
	s := n.NTSSummary().Coarse
	if len(s) != 2 || s[0].Name != "x" || s[0].Answers != 1 || s[1].Failures != 1 {
		t.Fatalf("coarse %+v", s)
	}
	if got := (&NTS{Coarse: &coarseClock{}}).NTSSummary().Coarse; got != nil {
		t.Fatalf("a coarse clock without stats: %+v", got)
	}
}

// NTSSummary lists every server, one that never answered included, without
// waiting for a Refresh.
func TestNTSClockSummaryPeers(t *testing.T) {
	fs := newServers(t, map[string]ntstest.NTPOptions{"d": {Kiss: "DENY"}}, "a", "b", "c", "d")
	n := newNTS(fs, &coarseClock{})
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	ps := n.NTSSummary().Peers
	if len(ps) != 4 {
		t.Fatalf("peers %+v", ps)
	}
	for _, p := range ps[:3] {
		if !p.Active || p.Queries != 1 || p.Answers != 1 || p.KEOK != 1 || p.LastAnswerAge < 0 || p.Off != "" || p.LastError != "" {
			t.Fatalf("answering peer %+v", p)
		}
	}
	if d := ps[3]; d.Operator != "d" || d.Answers != 0 || d.Losses != 1 || d.LastAnswerAge != -1 || d.Off != "DENY" || d.LastError == "" {
		t.Fatalf("denied peer %+v", d)
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

// The clock combines by the majority of its fresh samples: 2 wrong of 5
// still give the time of the other 3, and 2 wrong of 4 give none.
func TestNTSClockMajority(t *testing.T) {
	liars := map[string]ntstest.NTPOptions{"d": {Offset: 5 * time.Second}, "e": {Offset: -5 * time.Second}}
	fs := newServers(t, liars, "a", "b", "c", "d", "e")
	n := newNTS(fs, &coarseClock{})
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	got, bound, err := n.Bounded()
	if err != nil {
		t.Fatal(err)
	}
	if d := testClock().Sub(got); d.Abs() > bound+5*time.Millisecond || bound > NTSMaxBound {
		t.Fatalf("two of five servers 5 s off moved the time by %v (bound %v)", d, bound)
	}
	n = newNTS(fs[1:], &coarseClock{})
	if err := refresh(t, n); err == nil || !strings.Contains(err.Error(), "disagree") {
		t.Fatalf("two of four wrong: %v", err)
	}
}

func TestNTSClockBoundGrowsUntilNowFails(t *testing.T) {
	fs := newServers(t, nil, "a", "b", "c")
	n := newNTS(fs, &coarseClock{})
	// The sample age limit would refuse first.
	n.MaxAge = time.Hour
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
	if sum := n.NTSSummary(); sum.Quorum || sum.Refusals != 1 || sum.BoundNow <= NTSMaxBound || sum.AgeOfQuorum < 200*time.Second ||
		!strings.Contains(sum.Refused, "error bound") {
		t.Fatalf("summary %+v", sum)
	}
}

// Samples over MaxAge old give no time, though the bound is within
// MaxBound, and HEALTH says why. They do not form a quorum either.
func TestNTSClockOldSamplesGiveNoTime(t *testing.T) {
	fs := newServers(t, nil, "a", "b", "c")
	n := newNTS(fs, &coarseClock{})
	n.Interval, n.MaxBound = NTSInterval, time.Second
	var ahead atomic.Int64
	n.Local = func() int64 { return nts.Monotonic() + ahead.Load() }
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	if sum := n.NTSSummary(); !sum.Quorum || sum.Refused != "" || sum.MaxSampleAge != NTSMaxAge || sum.SampleAge > time.Second {
		t.Fatalf("summary %+v", sum)
	}
	n.Dial = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("blocked by the host") }
	ahead.Store(int64(NTSMaxAge - time.Second))
	if _, err := n.Now(); err != nil {
		t.Fatalf("%v before the limit: %v", NTSMaxAge-time.Second, err)
	}
	ahead.Store(int64(NTSMaxAge + time.Second))
	_, b, err := n.Bounded()
	if err == nil || !strings.Contains(err.Error(), "samples of the last quorum") || b > n.MaxBound {
		t.Fatalf("%v after the samples: bound %v, err %v", NTSMaxAge+time.Second, b, err)
	}
	if err := refresh(t, n); err == nil || !strings.Contains(err.Error(), "0 fresh samples") {
		t.Fatalf("quorum from old samples: %v", err)
	}
	sum := n.NTSSummary()
	t.Logf("HEALTH: quorum %v, sample age %v, refused: %s", sum.Quorum, sum.SampleAge, sum.Refused)
	if sum.Quorum || sum.Refusals != 1 || sum.SampleAge <= NTSMaxAge || !strings.Contains(sum.Refused, "samples of the last quorum") {
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
			n := &NTS{Coarse: coarse, Interval: 50 * time.Millisecond, minPoll: 10 * time.Millisecond, StartDelay: -1}
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
	// and the DENY server not before NTSMaxPoll.
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

// RATE backoff stops at maxPoll, as DENY/RSTR does.
func TestNTSClockRateBackoffCappedAtMaxPoll(t *testing.T) {
	fs := newServers(t, map[string]ntstest.NTPOptions{"rate": {Kiss: "RATE"}}, "a", "b", "c", "rate")
	n := newNTS(fs, &coarseClock{})
	n.maxPoll = 70 * time.Millisecond
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	if p := n.Status().Peers["rate"].Poll; p != 70*time.Millisecond {
		t.Fatalf("poll after RATE %v, want maxPoll 70ms", p)
	}
}

// A status snapshot owns its kiss counts: the next poll does not write to it.
func TestNTSClockStatusCopiesKisses(t *testing.T) {
	fs := newServers(t, map[string]ntstest.NTPOptions{"rate": {Kiss: "RATE"}}, "a", "b", "c", "rate")
	n := newNTS(fs, &coarseClock{})
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	st := n.Status()
	time.Sleep(110 * time.Millisecond)
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	if now := n.Status().Peers["rate"].Stats.Kisses["RATE"]; now != 2 {
		t.Fatalf("RATE count %d, want 2", now)
	}
	if old := st.Peers["rate"].Stats.Kisses["RATE"]; old != 1 {
		t.Fatalf("the earlier snapshot changed: RATE count %d, want 1", old)
	}
}

// A Kiss-o'-Death carries no authenticator, so anyone on the path who sees
// the request can forge one. DENY or RSTR stops a server for maxPoll only:
// a forged one must not take the operator out until the next restart.
func TestNTSClockDenyExpires(t *testing.T) {
	fs := newServers(t, map[string]ntstest.NTPOptions{"deny": {Kiss: "DENY"}}, "a", "b", "c", "deny")
	n := newNTS(fs, &coarseClock{})
	n.maxPoll = 200 * time.Millisecond
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	if d := n.Status().Peers["deny"].Disabled; d != "DENY" {
		t.Fatalf("disabled %q, want DENY", d)
	}
	fs[3].ntp.Set(opt(ntstest.NTPOptions{}))
	time.Sleep(60 * time.Millisecond)
	deny := fs[3].ntp.Requests.Load()
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	if got := fs[3].ntp.Requests.Load(); got != deny {
		t.Fatalf("the DENY server was asked again before maxPoll: %d requests, want %d", got, deny)
	}
	time.Sleep(200 * time.Millisecond)
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	p := n.Status().Peers["deny"]
	if p.Disabled != "" || fs[3].ntp.Requests.Load() == deny || p.Stats.Samples != 1 {
		t.Fatalf("after maxPoll: disabled %q, requests %d, samples %d", p.Disabled, fs[3].ntp.Requests.Load(), p.Stats.Samples)
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

// Some servers send the NAK as "NTS" and a zero octet (nts1.ntp.hr for a
// stale cookie). The clock takes it as NTSN and runs NTS-KE again.
func TestNTSClockNTSZeroNAKRunsKeyExchangeAgain(t *testing.T) {
	fs := newServers(t, map[string]ntstest.NTPOptions{"a": {Kiss: "NTS\x00"}}, "a", "b", "c", "d")
	n := newNTS(fs, &coarseClock{})
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)
	_ = refresh(t, n)
	if k := n.Status().Peers["a"].Stats.Kisses["NTSN"]; k < 1 {
		t.Fatalf("NTSN count %d, kisses %v", k, n.Status().Peers["a"].Stats.Kisses)
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
	// No server is due yet: the refused samples must not form a quorum again.
	if err := refresh(t, n); err == nil {
		t.Fatal("the refused samples formed a quorum again")
	}
	if _, err := n.Now(); err == nil {
		t.Fatal("time served from the refused samples")
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

// Without a coarse time the certificate clock gives the zero time, and
// KeyExchange refuses it before it dials: the cause shows in the error,
// and no certificate is checked at the system clock.
func TestNTSCertificateClockWithoutCoarseTime(t *testing.T) {
	n := &NTS{Coarse: &coarseClock{Err: errors.New("no coarse reading")}}
	if got := n.certTime(); !got.IsZero() {
		t.Fatalf("certificate time without a coarse reading: %v", got)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	dialed := make(chan struct{}, 1)
	go func() {
		if c, err := l.Accept(); err == nil {
			dialed <- struct{}{}
			c.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = nts.KeyExchange(ctx, nts.KEConfig{Host: "nts.test", Addr: l.Addr().String(), Roots: x509.NewCertPool(), Time: n.certTime})
	if err == nil || !strings.Contains(err.Error(), "no trusted time") {
		t.Fatalf("key exchange without a coarse time: %v", err)
	}
	select {
	case <-dialed:
		t.Fatal("key exchange dialed without a certificate time")
	case <-time.After(100 * time.Millisecond):
	}
	n.Coarse = &coarseClock{}
	if got := n.certTime(); got.Year() < 2026 {
		t.Fatalf("certificate time with a coarse reading: %v", got)
	}
}

// A server that drops queries without a kiss (it rotated its keys and
// ignores old cookies) gets NTS-KE again after ntsKEAfterLost lost queries
// in a row, not after all its cookies are spent.
func TestNTSClockKeyExchangeAfterLostQueries(t *testing.T) {
	fs := newServers(t, nil, "a", "b", "c", "d")
	n := newNTS(fs, &coarseClock{})
	n.queryTimeout = 100 * time.Millisecond
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	fs[0].ntp.Set(opt(ntstest.NTPOptions{Drop: true}))
	for range ntsKEAfterLost {
		time.Sleep(60 * time.Millisecond)
		_ = refresh(t, n)
	}
	if s := fs[0].ke.Sessions.Load(); s != 1 {
		t.Fatalf("NTS-KE sessions with a after %d lost: %d, want 1", ntsKEAfterLost, s)
	}
	// One NTS-KE per streak: 7 more lost queries (fewer than the 8 cookies
	// the second NTS-KE gave) add no more.
	for range 7 {
		time.Sleep(60 * time.Millisecond)
		_ = refresh(t, n)
	}
	if s := fs[0].ke.Sessions.Load(); s != 2 {
		t.Fatalf("NTS-KE sessions with a after %d lost: %d, want 2 (one per streak)", ntsKEAfterLost+7, s)
	}
	fs[0].ntp.Set(opt(ntstest.NTPOptions{}))
	time.Sleep(60 * time.Millisecond)
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	if s, p := fs[0].ke.Sessions.Load(), n.Status().Peers["a"]; s != 2 || p.Stats.Samples != 2 {
		t.Fatalf("after the drops: NTS-KE sessions %d, want 2; samples %d", s, p.Stats.Samples)
	}
}

// The NTS-KE after lost queries keeps the old cookies when it fails: once
// NTP answers again, the old cookies work without waiting out the backoff.
func TestNTSClockFailedLostKeyExchangeKeepsCookies(t *testing.T) {
	fs := newServers(t, nil, "a", "b", "c", "d")
	n := newNTS(fs, &coarseClock{})
	n.queryTimeout = 100 * time.Millisecond
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	fs[0].ntp.Set(opt(ntstest.NTPOptions{Drop: true}))
	fs[0].ke.Close()
	for range ntsKEAfterLost + 1 {
		time.Sleep(60 * time.Millisecond)
		_ = refresh(t, n)
	}
	if p := n.Status().Peers["a"]; p.Stats.KEFail != 1 {
		t.Fatalf("KE failures %d, want 1", p.Stats.KEFail)
	}
	fs[0].ntp.Set(opt(ntstest.NTPOptions{}))
	time.Sleep(60 * time.Millisecond)
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	if p := n.Status().Peers["a"]; p.Stats.Samples != 2 {
		t.Fatalf("samples %d after the drops, want 2 (old cookies)", p.Stats.Samples)
	}
}

// Refresh refuses a server list every quorum would refuse (more than
// nts.MaxServers, a bad or repeated operator) and an empty schedule seed,
// before it contacts anyone.
func TestNTSRefreshRefusesBadListsAndSeeds(t *testing.T) {
	many := make([]NTSServer, nts.MaxServers+1)
	for i := range many {
		many[i] = NTSServer{Host: "h.example", Operator: string(rune('a' + i))}
	}
	for name, tc := range map[string]struct {
		n    *NTS
		want string
	}{
		"17 servers":     {&NTS{Servers: many}, "at most 16"},
		"empty operator": {&NTS{Servers: []NTSServer{{Host: "a"}}}, "operator label"},
		"repeated":       {&NTS{Servers: []NTSServer{{Host: "a", Operator: "x"}, {Host: "b", Operator: "x"}}}, "named twice"},
		"empty seed":     {&NTS{Servers: many[:4], ScheduleSeed: []byte{}}, "empty schedule seed"},
		"long operator":  {&NTS{Servers: []NTSServer{{Host: "a", Operator: strings.Repeat("o", nts.MaxOperatorLen+1)}}}, "operator label"},
	} {
		tc.n.Coarse, tc.n.StartDelay = &coarseClock{}, -1
		if err := refresh(t, tc.n); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	n := &NTS{Shifts: true}
	if err := n.SetScheduleSeed(nil); err == nil {
		t.Fatal("SetScheduleSeed(nil) accepted")
	}
}

// The NTS-KE of a loss streak that the caller's deadline cuts short is not
// used up: the next contact tries it again.
func TestNTSClockLostKeyExchangeCutByDeadline(t *testing.T) {
	fs := newServers(t, nil, "a", "b", "c", "d")
	n := newNTS(fs, &coarseClock{})
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	p := n.peers[0]
	p.lostInRow = ntsKEAfterLost
	n.Dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if !n.keyExchange(ctx, p) {
		t.Fatal("the old cookies are not usable after a cut NTS-KE")
	}
	if p.lostKE || p.stats.KEFail != 0 {
		t.Fatalf("after a cut NTS-KE: lostKE %v, KE failures %d", p.lostKE, p.stats.KEFail)
	}
}

// A wide answer is authenticated, so it ends a loss streak: the next lost
// query does not run NTS-KE early.
func TestNTSWideAnswerEndsLossStreak(t *testing.T) {
	n := &NTS{MaxSampleBound: 100 * time.Millisecond}
	p := &ntsPeer{lostInRow: ntsKEAfterLost, lostKE: true, stats: NTSPeerStats{Kisses: map[string]int{}}}
	if n.record(p, nts.Sample{Bound: 200 * time.Millisecond}, nil) {
		t.Fatal("a wide answer counts as a sample")
	}
	var w *wideSampleError
	if p.lostInRow != 0 || p.lostKE || !errors.As(p.lastErr, &w) || p.stats.Wide != 1 {
		t.Fatalf("after a wide answer: lost in a row %d, lostKE %v, err %v", p.lostInRow, p.lostKE, p.lastErr)
	}
}

// A sample wider than MaxSampleBound (default MaxBound) joins no quorum:
// a host that delays the one honest answer cannot widen it past what
// signing accepts. MaxSampleBound raised to 1 s takes it again.
func TestNTSClockRefusesWideSamples(t *testing.T) {
	wide := ntstest.NTPOptions{RootDisp: 400 * time.Millisecond}
	fs := newServers(t, map[string]ntstest.NTPOptions{"a": wide}, "a", "b", "c", "d")
	n := newNTS(fs, &coarseClock{})
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	p := n.Status().Peers["a"]
	if p.Stats.Wide != 1 || p.Stats.Samples != 0 || !strings.Contains(p.LastErr, "limit") {
		t.Fatalf("a: wide %d samples %d err %v", p.Stats.Wide, p.Stats.Samples, p.LastErr)
	}
	sum := n.NTSSummary()
	if m := sum.Members; strings.Contains(","+strings.Join(m, ",")+",", ",a,") {
		t.Fatalf("quorum members %v hold the wide sample", m)
	}
	if h := sum.Peers[0]; h.Operator != "a" || h.Wide != 1 || h.Losses != 1 {
		t.Fatalf("HEALTH of a: %+v, want 1 wide loss", h)
	}
	fs2 := newServers(t, map[string]ntstest.NTPOptions{"a": wide}, "a", "b", "c", "d")
	n2 := newNTS(fs2, &coarseClock{})
	n2.MaxSampleBound = time.Second
	if err := refresh(t, n2); err != nil {
		t.Fatal(err)
	}
	if p := n2.Status().Peers["a"]; p.Stats.Wide != 0 || p.Stats.Samples != 1 {
		t.Fatalf("with a 1 s cap: wide %d samples %d", p.Stats.Wide, p.Stats.Samples)
	}
}

// A sample joins for its whole join age, and its bound, aged by rho
// (500 ppm), never passes the cap while it may join: at receipt it must be
// within the cap less the aging of the join age (38 ms at 76 s under the
// shift schedule), 62 ms at the 100 ms cap. One wider at receipt never
// joins. This keeps the error a host and wrong servers reach at twice the
// cap (rv-dko.5).
func TestNTSJoinsAgedBound(t *testing.T) {
	n := &NTS{MaxSampleBound: 100 * time.Millisecond, Shifts: true}
	maxAge := n.sampleMaxAge()
	if maxAge != int64(76*time.Second) {
		t.Fatalf("join age under the shift schedule: %v, the docs say 76 s", time.Duration(maxAge))
	}
	if d := nts.Drift(76 * time.Second); d != 38*time.Millisecond {
		t.Fatalf("aging of 76 s: %v, the docs say 38 ms", d)
	}
	rb := n.receiptBound()
	if rb != 62*time.Millisecond {
		t.Fatalf("receipt bound %v, want 62 ms", rb)
	}
	p := &ntsPeer{sample: &nts.Sample{Bound: rb, T4: 1}}
	for _, age := range []time.Duration{time.Second, 30 * time.Second, 60 * time.Second, 76 * time.Second} {
		if !n.joins(p, 1+int64(age), maxAge) {
			t.Fatalf("a sample at the receipt bound, aged %v, refused", age)
		}
		if aged := rb + nts.Drift(age); aged > n.maxSampleBound() {
			t.Fatalf("aged %v the bound is %v, over the cap", age, aged)
		}
	}
	p.sample.Bound = rb + 1
	if n.joins(p, 1, maxAge) {
		t.Fatal("a sample over the receipt bound joins")
	}
	p.sample.Bound = 50 * time.Millisecond
	if n.joins(p, 2+maxAge, maxAge) {
		t.Fatal("a sample over maxAge joins")
	}
	// record refuses the same samples, as wide.
	q := &ntsPeer{stats: NTSPeerStats{Kisses: map[string]int{}}}
	if n.record(q, nts.Sample{Bound: rb + time.Millisecond}, nil) || q.stats.Wide != 1 {
		t.Fatalf("an answer over the receipt bound: wide %d", q.stats.Wide)
	}
	if !n.record(q, nts.Sample{Bound: rb}, nil) {
		t.Fatal("an answer at the receipt bound refused")
	}
	// A cap under twice the aging (tests only; setups have at least 80 ms)
	// keeps half of it.
	small := &NTS{MaxSampleBound: 40 * time.Millisecond, Shifts: true}
	if got := small.receiptBound(); got != 20*time.Millisecond {
		t.Fatalf("receipt bound of a 40 ms cap: %v, want 20 ms", got)
	}
}

// With exactly 3 fresh samples no wrong one is outvoted, so HEALTH's worst
// bound is up to twice the widest member's bound, however narrow the
// overlap; with 4 it is the quorum's bound (rv-dko.4).
func TestNTSWorstBoundWithThreeSamples(t *testing.T) {
	wider := ntstest.NTPOptions{RootDisp: 20 * time.Millisecond}
	fs := newServers(t, map[string]ntstest.NTPOptions{"a": wider}, "a", "b", "c")
	n := newNTS(fs, &coarseClock{})
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	sum := n.NTSSummary()
	if len(sum.Members) != 3 {
		t.Fatalf("members %v, want 3", sum.Members)
	}
	widest := time.Duration(0)
	for _, p := range n.Status().Peers {
		widest = max(widest, p.Sample.Bound)
	}
	// A root dispersion of 20 ms comes back as about 19.998 ms (NTP short
	// format, 1/65536 s); the delay adds a little on top, or not.
	if widest < 19*time.Millisecond || sum.WorstBoundNow < 2*widest || sum.WorstBoundNow < sum.BoundNow {
		t.Fatalf("3 samples: worst %v, bound %v, widest member %v", sum.WorstBoundNow, sum.BoundNow, widest)
	}
	fs4 := newServers(t, map[string]ntstest.NTPOptions{"a": wider}, "a", "b", "c", "d")
	n4 := newNTS(fs4, &coarseClock{})
	if err := refresh(t, n4); err != nil {
		t.Fatal(err)
	}
	if s4 := n4.NTSSummary(); len(s4.Members) != 4 || s4.WorstBoundNow != s4.BoundNow {
		t.Fatalf("4 samples: members %v, worst %v, bound %v", s4.Members, s4.WorstBoundNow, s4.BoundNow)
	}
}
