//go:build nts

package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/trusted-time/clock"
	"github.com/lidofinance/tee-signer/trusted-time/nts"
)

// The wrapper refuses to start without the coarse check, and with a bad
// duration, before it contacts any server.
func TestNTSClockWrapperNeedsCoarseURLs(t *testing.T) {
	base := func(platform.Options) (*platform.Platform, error) { return &platform.Platform{}, nil }
	t.Setenv("RUNNER_NTS_COARSE_URLS", "https://a.example/,https://b.example/")
	if _, err := withNTSClock(base)(platform.Options{}); err == nil || !strings.Contains(err.Error(), "3 or more") {
		t.Fatalf("two coarse URLs: %v", err)
	}
	t.Setenv("RUNNER_NTS_COARSE_URLS", "https://a.example/,https://b.example/,https://c.example/")
	t.Setenv("RUNNER_NTS_WAIT", "soon")
	if _, err := withNTSClock(base)(platform.Options{}); err == nil || !strings.Contains(err.Error(), "RUNNER_NTS_WAIT") {
		t.Fatalf("bad wait: %v", err)
	}
	t.Setenv("RUNNER_NTS_WAIT", "")
	t.Setenv("RUNNER_NTS_MAX_BOUND", "-1ms")
	if _, _, err := newNTSClock(nil, nil, "", nil); err == nil || !strings.Contains(err.Error(), "RUNNER_NTS_MAX_BOUND") {
		t.Fatalf("bad max bound: %v", err)
	}
	t.Setenv("RUNNER_NTS_MAX_BOUND", "")
	n, coarse, err := newNTSClock(nil, nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if n.MaxBound != clock.NTSMaxBound || len(n.Servers) != len(nts.PublicServers) {
		t.Fatalf("max bound %v, %d servers", n.MaxBound, len(n.Servers))
	}
	// The coarse clock ages on CLOCK_MONOTONIC_RAW, as the NTS clock does.
	if coarse.Local == nil {
		t.Fatal("coarse clock on Go's monotonic clock")
	}
	before := nts.Monotonic()
	got := coarse.Local().UnixNano()
	if after := nts.Monotonic(); got < before || got > after {
		t.Fatalf("coarse local %d not between raw readings %d and %d", got, before, after)
	}
}

func TestNTSStatusLine(t *testing.T) {
	st := clock.NTSStatus{
		Members: []string{"a", "b", "c"},
		Peers: map[string]clock.NTSPeerStatus{
			"b": {Poll: 32 * time.Second, Disabled: "DENY", Stats: clock.NTSPeerStats{Kisses: map[string]int{"DENY": 1}}},
			"a": {Poll: 64 * time.Second, Sample: &nts.Sample{Delay: time.Millisecond, Bound: 2 * time.Millisecond},
				Stats: clock.NTSPeerStats{Samples: 3, Queries: 4, KEOK: 1}},
		},
	}
	got := statusLine(st)
	want := "a:3/4/ke1,poll=1m4s,delay=1ms,bound=2ms b:0/0/ke0,poll=32s,DENY=1,off=DENY"
	if got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

// Off by default; the flag or the variable turns it on.
func TestNTSSwitch(t *testing.T) {
	sys := clock.System{}
	base := func(platform.Options) (*platform.Platform, error) { return &platform.Platform{Clock: sys}, nil }
	t.Setenv("RUNNER_NTS_CLOCK", "")
	p, err := ntsSwitch(base)(platform.Options{})
	if err != nil || p.Clock != sys {
		t.Fatalf("off: %v %T", err, p.Clock)
	}
	// On, with too few coarse URLs: the error shows the NTS path ran.
	t.Setenv("RUNNER_NTS_COARSE_URLS", "")
	for _, on := range []func(){
		func() { t.Setenv("RUNNER_NTS_CLOCK", "1") },
		func() { t.Setenv("RUNNER_NTS_CLOCK", ""); *ntsClockFlag = true },
	} {
		on()
		if _, err := ntsSwitch(base)(platform.Options{}); err == nil || !strings.Contains(err.Error(), "-nts-coarse-urls") {
			t.Fatalf("on: %v", err)
		}
	}
	defer func() { *ntsClockFlag = false }()
}

// A set flag wins over its variable.
func TestNTSFlagsOverVariables(t *testing.T) {
	t.Setenv("RUNNER_NTS_COARSE_URLS", "https://a.example/,https://b.example/")
	t.Setenv("RUNNER_NTS_MAX_BOUND", "200ms")
	*ntsCoarseFlag = "https://a.example/,https://b.example/,https://c.example/"
	*ntsMaxBoundFlag = 50 * time.Millisecond
	defer func() { *ntsCoarseFlag, *ntsMaxBoundFlag = "", 0 }()
	n, _, err := newNTSClock(nil, nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if n.MaxBound != 50*time.Millisecond {
		t.Fatalf("max bound %v", n.MaxBound)
	}
	*ntsMaxBoundFlag = -time.Millisecond
	if _, _, err := newNTSClock(nil, nil, "", nil); err == nil || !strings.Contains(err.Error(), "-nts-max-bound") {
		t.Fatalf("negative flag: %v", err)
	}
	*ntsMaxBoundFlag = 0
	n, _, err = newNTSClock(nil, nil, "", nil)
	if err != nil || n.MaxBound != 200*time.Millisecond {
		t.Fatalf("variable: %v %v", n.MaxBound, err)
	}
}

// The platform's dialer reaches the NTS clock.
func TestNTSClockTakesThePlatformDialer(t *testing.T) {
	t.Setenv("RUNNER_NTS_COARSE_URLS", "https://a.example/,https://b.example/,https://c.example/")
	called := false
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		called = true
		return nil, errors.New("test dialer")
	}
	n, _, err := newNTSClock(nil, dial, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.Dial(context.Background(), "udp", "x:123"); err == nil || !called {
		t.Fatal("not the platform's dialer")
	}
}

// No quorum within -nts-wait: the start fails, so the supervisor starts
// the runner again. A runner that went on would load no share (the
// restart floor needs the clock) and never load them later.
func TestNTSClockStartFailsWithoutQuorum(t *testing.T) {
	t.Setenv("RUNNER_NTS_COARSE_URLS", "https://127.0.0.1:1/,https://127.0.0.1:2/,https://127.0.0.1:3/")
	t.Setenv("RUNNER_NTS_WAIT", "1s")
	start := time.Now()
	n, err := startNTSClock(context.Background(), &http.Client{Timeout: time.Second}, nil, "", nil, slog.New(slog.DiscardHandler))
	if err == nil || !strings.Contains(err.Error(), "no quorum") {
		t.Fatalf("started without a quorum: %v %v", n, err)
	}
	if d := time.Since(start); d > 30*time.Second {
		t.Fatalf("gave up after %v, want about the 1s wait", d)
	}
}

// The wrapper hands that error to the host before it closes the platform:
// main never sees the platform, so it cannot.
func TestNTSClockStartFailureIsReported(t *testing.T) {
	t.Setenv("RUNNER_NTS_COARSE_URLS", "https://127.0.0.1:1/,https://127.0.0.1:2/,https://127.0.0.1:3/")
	t.Setenv("RUNNER_NTS_WAIT", "1s")
	var reported string
	closed := false
	base := func(platform.Options) (*platform.Platform, error) {
		return &platform.Platform{HTTPClient: &http.Client{Timeout: time.Second},
			ReportExit: func(s string) { reported = s }, Close: func() error { closed = true; return nil }}, nil
	}
	if _, err := withNTSClock(base)(platform.Options{}); err == nil {
		t.Fatal("started without a quorum")
	}
	if !strings.Contains(reported, "no quorum") || !closed {
		t.Fatalf("reported %q, closed %v", reported, closed)
	}
}

// -nts-max-bound and RUNNER_NTS_MAX_BOUND are refused above the cap: a
// larger bound would let the clock serve a time it vouches for less.
func TestNTSMaxBoundCap(t *testing.T) {
	t.Setenv("RUNNER_NTS_COARSE_URLS", "https://a.example/,https://b.example/,https://c.example/")
	defer func() { *ntsMaxBoundFlag = 0 }()
	for _, v := range []time.Duration{100 * time.Millisecond, 250 * time.Millisecond} {
		*ntsMaxBoundFlag = v
		if n, _, err := newNTSClock(nil, nil, "", nil); err != nil || n.MaxBound != v {
			t.Fatalf("-nts-max-bound %v: %v", v, err)
		}
	}
	for _, v := range []time.Duration{251 * time.Millisecond, time.Second, time.Hour, 1000 * time.Hour} {
		*ntsMaxBoundFlag = v
		if _, _, err := newNTSClock(nil, nil, "", nil); err == nil || !strings.Contains(err.Error(), "-nts-max-bound") {
			t.Fatalf("-nts-max-bound %v: %v", v, err)
		}
	}
	*ntsMaxBoundFlag = 0
	t.Setenv("RUNNER_NTS_MAX_BOUND", "24h")
	if _, _, err := newNTSClock(nil, nil, "", nil); err == nil || !strings.Contains(err.Error(), "RUNNER_NTS_MAX_BOUND") {
		t.Fatalf("RUNNER_NTS_MAX_BOUND=24h: %v", err)
	}
}

// The runner always runs the 60 s schedule (shifts from 7 servers, all
// active below) and refuses fewer than 4 servers.
func TestNTSScheduleNeedsEnoughServers(t *testing.T) {
	seed := []byte("seed")
	// A slice, not a map: the constants may come to equal a literal.
	for _, tc := range []struct {
		n    int
		want bool
	}{{0, false}, {3, false}, {ntsMinServers, true}, {6, true}, {ntsShiftMinServers, true}, {12, true}} {
		c := &clock.NTS{Servers: make([]clock.NTSServer, tc.n)}
		err := ntsSchedule(c, seed)
		if (err == nil) != tc.want || c.Shifts != tc.want || (tc.want && string(c.ScheduleSeed) != "seed") || (!tc.want && c.ScheduleSeed != nil) {
			t.Errorf("%d servers: err %v, shifts %v, seed %q", tc.n, err, c.Shifts, c.ScheduleSeed)
		}
	}
	// An empty seed would give every signer the same order.
	c := &clock.NTS{Servers: make([]clock.NTSServer, ntsMinServers)}
	if err := ntsSchedule(c, []byte{}); err == nil || c.Shifts {
		t.Errorf("empty seed: err %v, shifts %v", err, c.Shifts)
	}
}

// -nts-terms-confirmed adds catalog entries to the default set; id@host
// picks an alt host. A bad value stops the clock from being built.
func TestNTSTermsConfirmed(t *testing.T) {
	t.Setenv("RUNNER_NTS_TERMS_CONFIRMED", "")
	def, err := publicNTSServers()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("RUNNER_NTS_TERMS_CONFIRMED", "time.nl@any.time.nl")
	got, err := publicNTSServers()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(def)+1 || len(got) < ntsShiftMinServers {
		t.Fatalf("%d servers with time.nl, %d without; shifts need %d", len(got), len(def), ntsShiftMinServers)
	}
	var found bool
	for _, s := range got {
		if s.Operator == "time.nl" && s.Host == "any.time.nl" && s.Roots != nil {
			found = true
		}
	}
	if !found {
		t.Fatalf("no time.nl on any.time.nl in %+v", got)
	}
	for _, bad := range []string{"nope", "cloudflare", "time.nl@ntppool2.time.nl", "time.nl,time.nl"} {
		t.Setenv("RUNNER_NTS_TERMS_CONFIRMED", bad)
		if _, err := publicNTSServers(); err == nil || !strings.Contains(err.Error(), "-nts-terms-confirmed") {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

// -nts-max-sample-bound defaults to -nts-max-bound, may be raised to 1 s
// (no cap), and is refused below the max bound or above 1 s.
func TestNTSMaxSampleBound(t *testing.T) {
	t.Setenv("RUNNER_NTS_COARSE_URLS", "https://a.example/,https://b.example/,https://c.example/")
	t.Setenv("RUNNER_NTS_MAX_BOUND", "")
	t.Setenv("RUNNER_NTS_MAX_SAMPLE_BOUND", "")
	defer func() { *ntsMaxBoundFlag, *ntsMaxSampleFlag = 0, 0 }()
	for _, tc := range []struct {
		bound, sample, want time.Duration
		err                 string
	}{
		{0, 0, 100 * time.Millisecond, ""},
		{250 * time.Millisecond, 0, 250 * time.Millisecond, ""},
		{0, time.Second, time.Second, ""},
		{0, 50 * time.Millisecond, 0, "-nts-max-sample-bound"},
		{0, 2 * time.Second, 0, "-nts-max-sample-bound"},
	} {
		*ntsMaxBoundFlag, *ntsMaxSampleFlag = tc.bound, tc.sample
		n, _, err := newNTSClock(nil, nil, "", nil)
		switch {
		case tc.err != "":
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%v/%v: %v, want %q", tc.bound, tc.sample, err, tc.err)
			}
		case err != nil:
			t.Errorf("%v/%v: %v", tc.bound, tc.sample, err)
		case n.MaxSampleBound != tc.want:
			t.Errorf("%v/%v: MaxSampleBound %v, want %v", tc.bound, tc.sample, n.MaxSampleBound, tc.want)
		}
	}
	*ntsMaxBoundFlag, *ntsMaxSampleFlag = 0, 0
	t.Setenv("RUNNER_NTS_MAX_SAMPLE_BOUND", "500ms")
	if n, _, err := newNTSClock(nil, nil, "", nil); err != nil || n.MaxSampleBound != 500*time.Millisecond {
		t.Fatalf("RUNNER_NTS_MAX_SAMPLE_BOUND=500ms: %v", err)
	}
}
