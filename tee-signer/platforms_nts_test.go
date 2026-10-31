//go:build nts

package main

import (
	"context"
	"errors"
	"flag"
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

// Off by default; the flag or the variable turns it on; -clock https-date
// next to it is refused before any server is asked.
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
	if flag.Lookup("clock") == nil {
		flag.String("clock", "platform", "main.go's flag, for this test")
	}
	_ = flag.Set("clock", "https-date")
	defer func() { _ = flag.Set("clock", "platform") }()
	if _, err := ntsSwitch(base)(platform.Options{}); err == nil || !strings.Contains(err.Error(), "-clock https-date") {
		t.Fatalf("with -clock https-date: %v", err)
	}
}

// A set flag wins over its variable.
func TestNTSFlagsOverVariables(t *testing.T) {
	t.Setenv("RUNNER_NTS_COARSE_URLS", "https://a.example/,https://b.example/")
	t.Setenv("RUNNER_NTS_MAX_BOUND", "1s")
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
	if err != nil || n.MaxBound != time.Second {
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
	n, err := startNTSClock(context.Background(), &http.Client{Timeout: time.Second}, nil, "", slog.New(slog.DiscardHandler))
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
