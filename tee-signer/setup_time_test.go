//go:build nts

package main

import (
	"bytes"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/trusted-time/clock"
)

// mustFlagSettings are the clock values of the flags, protocol nts.
func mustFlagSettings(t *testing.T) ntsSettings {
	t.Helper()
	s, err := ntsFlagSettings(clock.ProtocolNTS)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// timeSetup is a setup with time_policy ntp, 200 ms and 400 ms, and
// time_servers time.nl on its alt host.
func timeSetup() *setupwire.Setup {
	s := &setupwire.Setup{}
	s.Locked.TimePolicy = setupwire.TimePolicy{Protocol: setupwire.ClockNTP, MaxBoundMs: 200, MaxSampleBoundMs: 400}
	s.Open.TimeServers = []string{"time.nl@any.time.nl"}
	return s
}

// clearClockFlags unsets the four flags the setup replaces, and their
// variables.
func clearClockFlags(t *testing.T) {
	t.Helper()
	for _, v := range []string{"RUNNER_CLOCK_PROTOCOL", "RUNNER_NTS_MAX_BOUND", "RUNNER_NTS_MAX_SAMPLE_BOUND", "RUNNER_NTS_TERMS_CONFIRMED"} {
		t.Setenv(v, "")
	}
	*clockProtoFlag, *ntsMaxBoundFlag, *ntsMaxSampleFlag, *ntsConfirmFlag = "", 0, 0, ""
	t.Cleanup(func() { *clockProtoFlag, *ntsMaxBoundFlag, *ntsMaxSampleFlag, *ntsConfirmFlag = "", 0, 0, "" })
}

// A setup's time_policy and time_servers reach the NTS clock: its
// protocol, both bounds and the default set plus time_servers.
func TestNTSClockTakesTheSetup(t *testing.T) {
	clearClockFlags(t)
	t.Setenv("RUNNER_NTS_COARSE_URLS", "https://a.example/,https://b.example/,https://c.example/")
	def, err := publicNTSServers()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"nitro", "azure", "gcp", "dev"} {
		s, err := ntsSettingsFor(name, timeValues(timeSetup()), slog.New(slog.DiscardHandler))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		n, _, err := newNTSClockWith(nil, nil, "", s, nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if n.Protocol != clock.ProtocolNTP || n.MaxBound != 200*time.Millisecond || n.MaxSampleBound != 400*time.Millisecond {
			t.Fatalf("%s: protocol %s, bounds %v %v", name, n.Protocol, n.MaxBound, n.MaxSampleBound)
		}
		if len(n.Servers) != len(def)+1 || !slices.ContainsFunc(n.Servers, func(s clock.NTSServer) bool { return s.Host == "any.time.nl" }) {
			t.Fatalf("%s: servers %+v", name, n.Servers)
		}
	}
	// An entry the catalog refuses stops the clock from being built.
	bad := timeSetup()
	bad.Open.TimeServers = []string{"nosuch"}
	s, err := ntsSettingsFor("nitro", timeValues(bad), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := newNTSClockWith(nil, nil, "", s, nil); err == nil || !strings.Contains(err.Error(), "the setup's time_servers") {
		t.Fatalf("unknown entry: %v", err)
	}
}

// With a setup, a cloud platform refuses each of the four flags and their
// variables; the dev platform warns and takes the setup's values.
func TestNTSSetupRefusesClockFlags(t *testing.T) {
	for _, c := range []struct {
		name string
		set  func()
	}{
		{"-clock-protocol", func() { *clockProtoFlag = "nts" }},
		{"-nts-max-bound", func() { *ntsMaxBoundFlag = 100 * time.Millisecond }},
		{"-nts-max-sample-bound", func() { *ntsMaxSampleFlag = 100 * time.Millisecond }},
		{"-nts-terms-confirmed", func() { *ntsConfirmFlag = "fer" }},
		{"RUNNER_CLOCK_PROTOCOL", func() { t.Setenv("RUNNER_CLOCK_PROTOCOL", "ntp") }},
		{"RUNNER_NTS_MAX_BOUND", func() { t.Setenv("RUNNER_NTS_MAX_BOUND", "100ms") }},
		{"RUNNER_NTS_MAX_SAMPLE_BOUND", func() { t.Setenv("RUNNER_NTS_MAX_SAMPLE_BOUND", "100ms") }},
		{"RUNNER_NTS_TERMS_CONFIRMED", func() { t.Setenv("RUNNER_NTS_TERMS_CONFIRMED", "fer") }},
	} {
		clearClockFlags(t)
		c.set()
		for _, p := range []string{"nitro", "azure", "gcp"} {
			if _, err := ntsSettingsFor(p, timeValues(timeSetup()), nil); err == nil || !strings.Contains(err.Error(), c.name) {
				t.Errorf("%s on %s: %v", c.name, p, err)
			}
		}
		var logs bytes.Buffer
		s, err := ntsSettingsFor("dev", timeValues(timeSetup()), slog.New(slog.NewTextHandler(&logs, nil)))
		if err != nil || s.protocol != clock.ProtocolNTP || !slices.Equal(s.confirmed, timeSetup().Open.TimeServers) || !strings.Contains(logs.String(), c.name) {
			t.Errorf("%s on dev: %+v %v, log %q", c.name, s, err, logs.String())
		}
		// Without a setup the flag counts.
		if _, err := ntsSettingsFor("dev", nil, nil); err != nil {
			t.Errorf("%s without a setup: %v", c.name, err)
		}
	}
}

// The config updates' sink swaps the clock's servers and sets its policy;
// a list the catalog refuses changes nothing.
func TestNTSTimeSink(t *testing.T) {
	clearClockFlags(t)
	t.Setenv("RUNNER_NTS_COARSE_URLS", "https://a.example/,https://b.example/,https://c.example/")
	n, _, err := newNTSClock(nil, nil, "", clock.ProtocolNTS, nil)
	if err != nil {
		t.Fatal(err)
	}
	sink := timeSinkOf(n)
	if sink == nil || timeSinkOf(clock.System{}) != nil {
		t.Fatal("no sink for the NTS clock, or one for the system clock")
	}
	before := len(n.Servers)
	if err := sink.SetServers([]string{"fer"}); err != nil || len(n.Servers) != before+1 {
		t.Fatalf("swap: %v, %d servers", err, len(n.Servers))
	}
	if err := sink.SetServers([]string{"nosuch"}); err == nil || len(n.Servers) != before+1 {
		t.Fatalf("unknown entry: %v, %d servers", err, len(n.Servers))
	}
	p := setupwire.TimePolicy{Protocol: setupwire.ClockNTP, MaxBoundMs: 150, MaxSampleBoundMs: 300}
	if err := sink.SetPolicy(p); err != nil || n.NTSSummary().Protocol != clock.ProtocolNTP || n.NTSSummary().MaxBound != 150*time.Millisecond {
		t.Fatalf("policy: %v, %+v", err, n.NTSSummary())
	}
	if err := sink.SetPolicy(setupwire.TimePolicy{Protocol: setupwire.ClockNTS, MaxBoundMs: 300, MaxSampleBoundMs: 300}); err == nil {
		t.Fatal("a max bound over the image's cap was taken")
	}
}
