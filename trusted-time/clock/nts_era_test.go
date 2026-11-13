//go:build nts

package clock

import (
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/trusted-time/nts"
	"github.com/lidofinance/tee-signer/trusted-time/nts/ntstest"
)

// ntpEra is one NTP era: a 32-bit seconds field wraps after it.
const ntpEra = time.Duration(1<<32) * time.Second

// testAnchor is the era anchor the tests expect: nts.FloorTime, the core's
// floor_unix_ns. NTP timestamps are read around it until a time is served,
// and no time before it is served.
var testAnchor = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

// nearTestClock fails unless got is within a second of the test clock.
func nearTestClock(t *testing.T, got time.Time) {
	t.Helper()
	if d := got.Sub(testClock()); d.Abs() > time.Second {
		t.Fatalf("time %v is %v from the test clock", got.UTC(), d)
	}
}

// eraPivotOf is the time the core reads NTP timestamps around.
func eraPivotOf(n *NTS) time.Time { return time.Unix(0, n.client.Summary().EraPivot) }

// historyHonest fails if a refused quorum left a trace in the core: a drift
// violation, or an era pivot away from the honest time (the pivot follows
// the time served, never the coarse clock, so it is the test clock's time
// or a little before it).
func historyHonest(t *testing.T, n *NTS) {
	t.Helper()
	st := n.client.Status()
	if st.Violations != 0 {
		t.Fatalf("%d drift violations: a refused quorum reached the drift check", st.Violations)
	}
	if d := testClock().Sub(time.Unix(0, st.EraPivot)); d < -time.Second || d > time.Minute {
		t.Fatalf("era pivot %v is %v before the test clock", time.Unix(0, st.EraPivot).UTC(), d)
	}
}

// rv-d3u.4: the host makes the coarse clock +2^32 s off on a running clock
// with live NTS associations. The honest answers must not map one NTP era
// ahead: the clock refuses (coarse check) instead of serving 2162, and
// serves the honest time again once the coarse clock is back.
func TestNTSClockCoarseEraShiftNotFollowed(t *testing.T) {
	fs := newServers(t, nil, "a", "b", "c")
	coarse := &coarseClock{}
	n := newNTS(fs, coarse)
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	got, err := n.Now()
	if err != nil {
		t.Fatal(err)
	}
	nearTestClock(t, got)
	coarse.Skew = ntpEra
	for i := 0; i < 3; i++ {
		time.Sleep(60 * time.Millisecond)
		_ = refresh(t, n)
		if got, err := n.Now(); err == nil {
			nearTestClock(t, got)
		}
	}
	historyHonest(t, n)
	coarse.Skew = 0
	time.Sleep(60 * time.Millisecond)
	if err := refresh(t, n); err != nil {
		t.Fatalf("honest coarse clock again: %v", err)
	}
	got, err = n.Now()
	if err != nil {
		t.Fatal(err)
	}
	nearTestClock(t, got)
}

// The same from the start, over plain NTP (no NTS-KE, whose certificate
// check at the shifted coarse time would fail first): a coarse clock 2^32 s
// ahead gives no time, not time 136 years ahead.
func TestPlainNTPClockCoarseEraShiftFromStart(t *testing.T) {
	srvs, _ := newPlainServers(t, nil, "a", "b", "c")
	n := newPlainNTS(srvs, &coarseClock{Skew: ntpEra})
	err := refresh(t, n)
	if got, nerr := n.Now(); nerr == nil {
		t.Fatalf("served %v with a coarse clock one era ahead (refresh: %v)", got.UTC(), err)
	}
	if err == nil || !strings.Contains(err.Error(), "coarse clock") {
		t.Fatalf("got %v", err)
	}
}

// shiftedPlain starts three plain NTP servers and a coarse clock that all
// agree on a time off by shift.
func shiftedPlain(t *testing.T, shift time.Duration) (*NTS, *coarseClock, []*ntstest.NTPServer) {
	t.Helper()
	o := ntstest.NTPOptions{Offset: shift}
	srvs, ntps := newPlainServers(t, map[string]ntstest.NTPOptions{"a": o, "b": o, "c": o}, "a", "b", "c")
	coarse := &coarseClock{Skew: shift}
	return newPlainNTS(srvs, coarse), coarse, ntps
}

// A quorum before the era anchor is refused, even when the coarse clock
// agrees with it.
func TestNTSClockRefusesTimeBeforeEraAnchor(t *testing.T) {
	n, _, _ := shiftedPlain(t, testAnchor.Sub(testClock())-48*time.Hour)
	err := refresh(t, n)
	if got, nerr := n.Now(); nerr == nil {
		t.Fatalf("served %v, before the era anchor (refresh: %v)", got.UTC(), err)
	}
	if err == nil || !strings.Contains(err.Error(), "before the era anchor") {
		t.Fatalf("got %v", err)
	}
	// It entered no drift history: there is no drift reading and no
	// violation, and the pivot did not move.
	if st := n.client.Status(); st.HaveDrift || st.Violations != 0 || st.HaveResult || !eraPivotOf(n).Equal(testAnchor) {
		t.Fatalf("refused quorum left a trace: drift reading %v, %d violations, pivot %v", st.HaveDrift, st.Violations, eraPivotOf(n).UTC())
	}
}

// A quorum more than 20 years after the pivot is refused, even when the
// coarse clock agrees with it.
func TestNTSClockRefusesTimeFarAfterPivot(t *testing.T) {
	n, _, _ := shiftedPlain(t, 25*365*24*time.Hour)
	err := refresh(t, n)
	if got, nerr := n.Now(); nerr == nil {
		t.Fatalf("served %v, 25 years ahead (refresh: %v)", got.UTC(), err)
	}
	if err == nil || !strings.Contains(err.Error(), "after the era pivot") {
		t.Fatalf("got %v", err)
	}
	// It entered no drift history: there is no drift reading and no
	// violation, and the pivot did not move.
	if st := n.client.Status(); st.HaveDrift || st.Violations != 0 || st.HaveResult || !eraPivotOf(n).Equal(testAnchor) {
		t.Fatalf("refused quorum left a trace: drift reading %v, %d violations, pivot %v", st.HaveDrift, st.Violations, eraPivotOf(n).UTC())
	}
}

// A quorum the sanity window refuses leaves the drift history alone: after
// it, honest answers are served at once, with no drift violation.
func TestNTSClockWindowRefusalKeepsDriftHistory(t *testing.T) {
	n, coarse, ntps := shiftedPlain(t, 0)
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	got, err := n.Now()
	if err != nil {
		t.Fatal(err)
	}
	nearTestClock(t, got)
	far := 25 * 365 * 24 * time.Hour
	setAll := func(shift time.Duration) {
		coarse.Skew = shift
		for _, s := range ntps {
			s.Set(opt(ntstest.NTPOptions{Offset: shift}))
		}
	}
	setAll(far)
	time.Sleep(60 * time.Millisecond)
	if err := refresh(t, n); err == nil {
		t.Fatal("quorum 25 years ahead accepted")
	}
	if got, err := n.Now(); err == nil {
		t.Fatalf("served %v after a refused quorum", got.UTC())
	}
	historyHonest(t, n)
	setAll(0)
	time.Sleep(60 * time.Millisecond)
	if err := refresh(t, n); err != nil {
		t.Fatalf("honest quorum after the refused one: %v", err)
	}
	got, err = n.Now()
	if err != nil {
		t.Fatal(err)
	}
	nearTestClock(t, got)
}

// The era pivot is the anchor before any time is served, then the highest
// time served, never below the anchor, and never the coarse clock's. It is
// the core's (the window's edges are checked there, ntscore's
// TestEraWindow tests); here the clock is seen to leave it alone.
func TestNTSClockEraPivot(t *testing.T) {
	if !nts.FloorTime.Equal(testAnchor) {
		t.Fatalf("era anchor %v, want %v", nts.FloorTime, testAnchor)
	}
	if !testClock().After(testAnchor) {
		t.Skipf("the test clock %v is before the era anchor", testClock().UTC())
	}
	// Plain NTP: with NTS the certificate check at the shifted coarse time
	// would fail first, and no answer would come at all.
	n, coarse, _ := shiftedPlain(t, 0)
	// A coarse clock one era off, before any time: the answers are read
	// around the anchor, the quorum is refused, the pivot is the anchor.
	coarse.Skew = ntpEra
	if err := refresh(t, n); err == nil || !strings.Contains(err.Error(), "coarse clock") {
		t.Fatalf("a coarse clock one era ahead: %v", err)
	}
	if p := eraPivotOf(n); !p.Equal(testAnchor) {
		t.Fatalf("pivot %v before any time, want the anchor", p.UTC())
	}
	coarse.Skew = 0
	time.Sleep(60 * time.Millisecond)
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	served, err := n.Now()
	if err != nil {
		t.Fatal(err)
	}
	// The pivot follows at the next combine, and never passes the time
	// served.
	time.Sleep(60 * time.Millisecond)
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	if p := eraPivotOf(n); p.Before(served) || p.After(testClock().Add(time.Second)) {
		t.Fatalf("pivot %v after serving %v", p.UTC(), served.UTC())
	}
	// The coarse clock one era ahead again: refused, and the pivot stays.
	coarse.Skew = ntpEra
	time.Sleep(60 * time.Millisecond)
	if err := refresh(t, n); err == nil {
		t.Fatal("a quorum 2^32 s from the coarse clock was served")
	}
	historyHonest(t, n)
}
