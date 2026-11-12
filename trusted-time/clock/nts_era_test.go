//go:build nts

package clock

import (
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/trusted-time/nts/ntstest"
)

// ntpEra is one NTP era: a 32-bit seconds field wraps after it.
const ntpEra = time.Duration(1<<32) * time.Second

// testAnchor is the era anchor the tests expect (eraAnchor).
var testAnchor = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// nearTestClock fails unless got is within a second of the test clock.
func nearTestClock(t *testing.T, got time.Time) {
	t.Helper()
	if d := got.Sub(testClock()); d.Abs() > time.Second {
		t.Fatalf("time %v is %v from the test clock", got.UTC(), d)
	}
}

// histOffsetNear fails unless the newest quorum in the drift history has the
// honest offset (within a second).
func histOffsetNear(t *testing.T, n *NTS) {
	t.Helper()
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.hist) == 0 {
		t.Fatal("empty drift history")
	}
	want := testClock().UnixNano() - n.local()
	if d := time.Duration(n.hist[len(n.hist)-1].offset - want); d.Abs() > time.Second {
		t.Fatalf("drift history holds a quorum %v from the honest offset", d)
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
	histOffsetNear(t, n)
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
	if len(n.hist) != 0 || n.violations != 0 {
		t.Fatalf("refused quorum entered the drift history (%d, %d violations)", len(n.hist), n.violations)
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
	if len(n.hist) != 0 || n.violations != 0 {
		t.Fatalf("refused quorum entered the drift history (%d, %d violations)", len(n.hist), n.violations)
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
	histOffsetNear(t, n)
	if n.violations != 0 {
		t.Fatalf("%d drift violations: the refused quorum reached the drift check", n.violations)
	}
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
// time served, never below the anchor, and never the coarse clock's.
func TestNTSClockEraPivot(t *testing.T) {
	if !eraAnchor.Equal(testAnchor) {
		t.Fatalf("era anchor %v, want %v", eraAnchor, testAnchor)
	}
	n := &NTS{Coarse: &coarseClock{Skew: ntpEra}}
	if p := n.eraPivot(); !p.Equal(testAnchor) {
		t.Fatalf("pivot %v before any time, want the anchor", p.UTC())
	}
	served := testClock()
	n.highest = served
	if p := n.eraPivot(); !p.Equal(served) {
		t.Fatalf("pivot %v after serving %v", p.UTC(), served.UTC())
	}
	n.highest = testAnchor.Add(-time.Hour)
	if p := n.eraPivot(); !p.Equal(testAnchor) {
		t.Fatalf("pivot %v below the anchor", p.UTC())
	}
	// Inside the window up to 20 years after the pivot, not past it.
	if why := eraRefusal(testAnchor.Add(eraWindow), testAnchor); why != "" {
		t.Fatalf("refused the window's edge: %s", why)
	}
	if eraRefusal(testAnchor.Add(eraWindow+time.Second), testAnchor) == "" || eraRefusal(testAnchor.Add(-time.Nanosecond), testAnchor) == "" {
		t.Fatal("time outside the window accepted")
	}
}
