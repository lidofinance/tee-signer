package server

import (
	"reflect"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	"github.com/lidofinance/tee-signer/trusted-time/clock"
)

// HEALTH reports the setup state, unattested, and config_hash is its
// setup_hash.
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
}

// HEALTH reports the NTS state in milliseconds, and only a clock with that
// state has it: the system clock does not satisfy clock.NTSReporter.
func TestHealthNTS(t *testing.T) {
	got := healthNTS(clock.NTSSummary{Quorum: true, BoundNow: 12345 * time.Microsecond, MaxBound: 100 * time.Millisecond,
		OffsetFromHost: -2500 * time.Millisecond, Members: []string{"a", "b", "c"}, AgeOfQuorum: 4 * time.Second, Refusals: 3,
		DriftPPM: 2.5, DriftErrPPM: 41, DriftBaseline: 16 * time.Minute, RhoViolations: 1, CoarseDiff: 420 * time.Millisecond})
	want := &backend.ClockNTS{Quorum: true, BoundNowMS: 12.345, MaxBoundMS: 100, OffsetFromHostMS: -2500, Members: []string{"a", "b", "c"},
		QuorumAgeMS: 4000, Refusals: 3, DriftPPM: 2.5, DriftErrPPM: 41, DriftBaselineS: 960, RhoViolations: 1, CoarseDiffMS: 420}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	var c any = clock.System{}
	if _, ok := c.(clock.NTSReporter); ok {
		t.Fatal("the system clock reports NTS state")
	}
}
