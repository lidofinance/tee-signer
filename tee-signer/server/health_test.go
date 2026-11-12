package server

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	"github.com/lidofinance/tee-signer/trusted-time/clock"
)

// HEALTH reports the setup state, unattested, and config_hash is its
// setup_hash. It also carries the version and the protocol level.
func TestHealthCarriesTheSetupState(t *testing.T) {
	want := backend.SetupState{SetupHash: backend.Root{0xcc}, Locked: backend.ConfigGroup{Version: 2, Hash: backend.Root{1},
		Pending: backend.PendingUpdate{Version: 3, Hash: backend.Root{2}, EffectiveAt: 1_800_000_000}}, ApproverSetHash: backend.Root{4}}
	s := shareServer(t, &shareStore{m: map[string][]byte{}}, [32]byte{}, [32]byte{})
	s.State, s.Platform.Clock = constState(want), clock.System{}
	h, err := s.health()
	if err != nil {
		t.Fatal(err)
	}
	b, err := wire.EncodeHealth(h)
	if err != nil {
		t.Fatal(err)
	}
	got, err := wire.DecodeHealth(b)
	if err != nil || got.Setup == nil || *got.Setup != want || got.ConfigHash != want.SetupHash {
		t.Fatalf("health %+v %v, want setup %+v", got, err, want)
	}
	if got.Version != Version || got.Protocol != backend.ProtocolLevel || !strings.Contains(string(b), fmt.Sprintf(`"protocol":%d`, backend.ProtocolLevel)) {
		t.Fatalf("version %q, protocol %d, want %q and %d: %s", got.Version, got.Protocol, Version, backend.ProtocolLevel, b)
	}
}

// HEALTH reports the NTS state in milliseconds, and only a clock with that
// state has it: the system clock does not satisfy clock.NTSReporter.
func TestHealthNTS(t *testing.T) {
	got := healthNTS(clock.NTSSummary{Protocol: clock.ProtocolNTS, Quorum: true, BoundNow: 12345 * time.Microsecond, MaxBound: 100 * time.Millisecond,
		OffsetFromHost: -2500 * time.Millisecond, Members: []string{"a", "b", "c"}, AgeOfQuorum: 4 * time.Second,
		SampleAge: 20 * time.Second, MaxSampleAge: time.Minute, Refusals: 3,
		DriftPPM: 2.5, DriftErrPPM: 41, DriftBaseline: 16 * time.Minute, RhoViolations: 1, CoarseDiff: 420 * time.Millisecond})
	want := &backend.ClockNTS{Protocol: "nts", Quorum: true, BoundNowMS: 12.345, MaxBoundMS: 100, OffsetFromHostMS: -2500, Members: []string{"a", "b", "c"},
		QuorumAgeMS: 4000, SampleAgeMS: 20000, MaxSampleAgeMS: 60000, Refusals: 3, DriftPPM: 2.5, DriftErrPPM: 41, DriftBaselineS: 960,
		RhoViolations: 1, CoarseDiffMS: 420}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	// One entry per server, a server that never answered included, with
	// the shift counts of its operator.
	got = healthNTS(clock.NTSSummary{FallbacksCapped: 2,
		Peers: []clock.NTSPeerHealth{
			{Operator: "a", Host: "a.test", Active: true, Queries: 10, Answers: 9, Losses: 1, KEOK: 1, LastAnswerAge: 1500 * time.Millisecond},
			{Operator: "b", Host: "b.test", Queries: 3, Losses: 3, KEFail: 2, LastAnswerAge: -1, Off: "DENY", LastError: "kiss DENY"},
		},
		Operators: map[string]clock.NTSOperatorCounts{"a": {Fallbacks: 4, Bursts: 5, Rates: 6, Handovers: 7, FailedHandovers: 8, FallbackKE: 9}},
	})
	wantOps := []backend.ClockNTSOperator{
		{Operator: "a", Host: "a.test", Active: true, Queries: 10, Answers: 9, Losses: 1, KEOK: 1, LastAnswerAgeMS: 1500,
			Fallbacks: 4, Bursts: 5, Rates: 6, Handovers: 7, FailedHandovers: 8, FallbackKE: 9},
		{Operator: "b", Host: "b.test", Queries: 3, Losses: 3, KEFail: 2, LastAnswerAgeMS: -1, Off: "DENY", LastError: "kiss DENY"},
	}
	if !reflect.DeepEqual(got.Operators, wantOps) || got.FallbacksCapped != 2 {
		t.Fatalf("operators %+v, capped %d", got.Operators, got.FallbacksCapped)
	}
	// One entry per coarse host, one that never answered included.
	got = healthNTS(clock.NTSSummary{Coarse: []clock.SourceStats{
		{Name: "https-date(https://a.test/)", Queries: 4, Answers: 3, Failures: 1, LastAnswerAge: 2 * time.Second, LastDiff: -time.Second},
		{Name: "https-date(https://b.test/)", Queries: 4, Failures: 4, LastAnswerAge: -1, LastError: "timeout"},
	}})
	wantCoarse := []backend.ClockNTSCoarse{
		{Source: "https-date(https://a.test/)", Queries: 4, Answers: 3, Failures: 1, LastAnswerAgeMS: 2000, LastDiffMS: -1000},
		{Source: "https-date(https://b.test/)", Queries: 4, Failures: 4, LastAnswerAgeMS: -1, LastError: "timeout"},
	}
	if !reflect.DeepEqual(got.Coarse, wantCoarse) {
		t.Fatalf("coarse %+v", got.Coarse)
	}
	// A plain NTP clock says so.
	if got := healthNTS(clock.NTSSummary{Protocol: clock.ProtocolNTP}); got.Protocol != "ntp" {
		t.Fatalf("protocol %q", got.Protocol)
	}
	// A refused clock says why.
	why := "samples of the last quorum 1m1s old, over 1m0s (no fresh quorum)"
	if got := healthNTS(clock.NTSSummary{Refused: why}); got.Quorum || got.Refused != why {
		t.Fatalf("refused: %+v", got)
	}
	var c any = clock.System{}
	if _, ok := c.(clock.NTSReporter); ok {
		t.Fatal("the system clock reports NTS state")
	}
}

// A failed state copy refresh makes HEALTH not ready with the reason; the
// next one that succeeds clears it.
func TestHealthStateCopyFailed(t *testing.T) {
	s := shareServer(t, &shareStore{m: map[string][]byte{}}, [32]byte{}, [32]byte{})
	s.State, s.Platform.Clock = constState(backend.SetupState{}), clock.System{}
	s.SetStateCopyFailed(errors.New("store down"))
	if h, err := s.health(); err != nil || h.Ready || !strings.Contains(h.StateCopyFailed, "store down") {
		t.Fatalf("after a failed refresh: %+v %v", h, err)
	}
	s.SetStateCopyFailed(nil)
	if h, err := s.health(); err != nil || !h.Ready || h.StateCopyFailed != "" {
		t.Fatalf("after a good refresh: %+v %v", h, err)
	}
}
