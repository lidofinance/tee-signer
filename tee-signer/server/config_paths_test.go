package server

import (
	"bytes"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

// all3 are every approver of the setup's set.
var all3 = []by{{0, 1}, {1, 2}, {2, 3}}

// fakeTime is a clock that takes time values and records them.
type fakeTime struct {
	mu       sync.Mutex
	servers  [][]string
	policies []setupwire.TimePolicy
	refuse   error
	// onPolicy, if set, runs after a policy is taken.
	onPolicy func(setupwire.TimePolicy)
}

func (f *fakeTime) SetServers(specs []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.refuse != nil {
		return f.refuse
	}
	f.servers = append(f.servers, slices.Clone(specs))
	return nil
}

func (f *fakeTime) SetPolicy(p setupwire.TimePolicy) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.refuse != nil {
		return f.refuse
	}
	f.policies = append(f.policies, p)
	if f.onPolicy != nil {
		f.onPolicy(p)
	}
	return nil
}

func (f *fakeTime) got() ([][]string, []setupwire.TimePolicy) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.servers), slices.Clone(f.policies)
}

// newTimeEnv is newEnv on a setup with time_policy nts, 100 ms and 100 ms,
// no time_servers, and a clock that takes the time values.
func newTimeEnv(t *testing.T, lock *uint64) (*env, *fakeTime) {
	t.Helper()
	e := newEnvWith(t, lock, func(s *setupwire.Setup) {
		s.Locked.TimePolicy = setupwire.TimePolicy{Protocol: setupwire.ClockNTS, MaxBoundMs: 100, MaxSampleBoundMs: 100}
		s.Open.TimeServers = nil
	})
	ft := &fakeTime{}
	e.time = ft
	e.restart()
	return e, ft
}

func (e *env) lastPath() *backend.UpdatePath {
	e.t.Helper()
	h, err := e.srv.health()
	if err != nil {
		e.t.Fatal(err)
	}
	return h.LastUpdatePath
}

// The normal path: k signatures, and a loosening update waits the change
// delay. HEALTH names the path once the update is in force.
func TestConfigPathNormal(t *testing.T) {
	e, _ := newTimeEnv(t, u64(3600))
	t0 := e.now()
	b := e.body(locked, 1, e.groupHash(locked), t0)
	b.Locked.AllowedFeeRecipients = append(b.Locked.AllowedFeeRecipients, x)
	h := hashOf(t, b)
	// Every approver signs, but a new fee recipient has no fast path.
	if st := e.mustSend(signed(t, b, all3, nil), wireadmin.ConfigAccepted); st.Locked.Pending != pending(1, h, t0+3600) {
		t.Fatalf("a new fee recipient: %+v", st.Locked)
	}
	if p := e.lastPath(); p != nil {
		t.Fatalf("path before any update came into force: %+v", p)
	}
	e.clock.add(3600)
	if p := e.lastPath(); p == nil || *p != (backend.UpdatePath{Group: "locked", Version: 1, Path: "normal"}) {
		t.Fatalf("path %+v", p)
	}
}

// Break-glass: a new image, and time_policy from NTS to NTP with higher
// bounds, are in force at once when every approver signs, and wait on the
// normal path with k signatures. The clock gets the new time_policy.
func TestConfigPathBreakGlass(t *testing.T) {
	e, ft := newTimeEnv(t, u64(3600))
	t0 := e.now()
	img := func(v uint64) *setupwire.UpdateBody {
		b := e.body(locked, v, e.groupHash(locked), t0)
		b.Locked.AllowedImageMeasurements = append(b.Locked.AllowedImageMeasurements, setupwire.Image{Kind: setupwire.ImageGCP, Measurement: bytes.Repeat([]byte{0x77}, 32)})
		return b
	}
	b1 := img(1)
	if st := e.mustSend(signed(t, b1, first2, nil), wireadmin.ConfigAccepted); st.Locked.Pending != pending(1, hashOf(t, b1), t0+setupwire.ImagesMinTimeLock) {
		t.Fatalf("a new image with k signatures: %+v", st.Locked)
	}
	b2 := img(2)
	h2 := hashOf(t, b2)
	if st := e.mustSend(signed(t, b2, all3, nil), wireadmin.ConfigAccepted); st.Locked != (backend.ConfigGroup{Version: 2, Hash: h2}) {
		t.Fatalf("a new image with every approver: %+v", st.Locked)
	}
	if p := e.lastPath(); p == nil || *p != (backend.UpdatePath{Group: "locked", Version: 2, Path: "break-glass"}) {
		t.Fatalf("path %+v", p)
	}

	ntp := setupwire.TimePolicy{Protocol: setupwire.ClockNTP, MaxBoundMs: 200, MaxSampleBoundMs: 500}
	b3 := e.body(locked, 3, h2, e.now())
	b3.Locked.AllowedImageMeasurements = b2.Locked.AllowedImageMeasurements
	b3.Locked.TimePolicy = ntp
	h3 := hashOf(t, b3)
	if st := e.mustSend(signed(t, b3, all3, nil), wireadmin.ConfigAccepted); st.Locked != (backend.ConfigGroup{Version: 3, Hash: h3}) {
		t.Fatalf("NTS to NTP with every approver: %+v", st.Locked)
	}
	if _, pol := ft.got(); len(pol) != 1 || pol[0] != ntp {
		t.Fatalf("the clock got %+v", pol)
	}
	// Back to NTS tightens: k signatures, at once.
	b4 := e.body(locked, 4, h3, e.now())
	b4.Locked.AllowedImageMeasurements = b2.Locked.AllowedImageMeasurements
	h4 := hashOf(t, b4)
	if st := e.mustSend(signed(t, b4, first2, nil), wireadmin.ConfigAccepted); st.Locked != (backend.ConfigGroup{Version: 4, Hash: h4}) {
		t.Fatalf("NTP back to NTS: %+v", st.Locked)
	}
	if _, pol := ft.got(); len(pol) != 2 || pol[1] != e.setup.Locked.TimePolicy {
		t.Fatalf("the clock got %+v", pol)
	}
	if p := e.lastPath(); p == nil || p.Path != "normal" || p.Version != 4 {
		t.Fatalf("path %+v", p)
	}
}

// Emergency removal: every approver but the removed one signs, and the
// update is in force at once. With fewer signers it waits.
func TestConfigPathEmergencyRemoval(t *testing.T) {
	e, _ := newTimeEnv(t, u64(3600))
	t0 := e.now()
	rm := func(v uint64) *setupwire.UpdateBody {
		b := e.body(locked, v, e.groupHash(locked), t0)
		b.Locked.Approvers = approverSet(2, 1, 2)
		return b
	}
	b1 := rm(1)
	// Approvers 1 and 3 sign, not 2: the removed one is 3.
	if st := e.mustSend(signed(t, b1, []by{{0, 1}, {2, 3}}, []byte{1, 2}), wireadmin.ConfigAccepted); st.Locked.Pending != pending(1, hashOf(t, b1), t0+3600) {
		t.Fatalf("a removal without every other approver: %+v", st.Locked)
	}
	b2 := rm(2)
	h2 := hashOf(t, b2)
	st := e.mustSend(signed(t, b2, first2, []byte{1, 2}), wireadmin.ConfigAccepted)
	if st.Locked != (backend.ConfigGroup{Version: 2, Hash: h2}) || st.ApproverSetHash != b2.Locked.Approvers.Hash() {
		t.Fatalf("emergency removal: %+v", st)
	}
	if p := e.lastPath(); p == nil || *p != (backend.UpdatePath{Group: "locked", Version: 2, Path: "emergency-removal"}) {
		t.Fatalf("path %+v", p)
	}
}

// An open update with new time_servers is in force at once and the clock
// dials the new list. A list the catalog refuses is refused before it is
// stored, so no such update can come into force.
func TestConfigTimeServersUpdate(t *testing.T) {
	e, ft := newTimeEnv(t, nil)
	for _, c := range []struct{ list, detail string }{
		{"nosuch.example", "no entry"},
		{"ptb", "default set"},
		{"time.nl@ntppool2.time.nl", "Nitro port"},
	} {
		b := e.body(open, 1, e.groupHash(open), e.now())
		b.Open.TimeServers = []string{c.list}
		_, _, err := e.send(signed(t, b, first2, nil))
		wantCode(t, err, backend.StatusBadRequest, c.detail)
	}
	if st := e.log.State(); st.Open.Version != 0 || st.Open.Pending != nil {
		t.Fatalf("a refused list reached the log: %+v", st.Open)
	}
	b := e.body(open, 1, e.groupHash(open), e.now())
	b.Open.TimeServers = []string{"fer", "time.nl@any.time.nl"}
	h := hashOf(t, b)
	if st := e.mustSend(signed(t, b, first2, nil), wireadmin.ConfigAccepted); st.Open != (backend.ConfigGroup{Version: 1, Hash: h}) {
		t.Fatalf("time_servers update: %+v", st.Open)
	}
	if srv, _ := ft.got(); len(srv) != 1 || !slices.Equal(srv[0], b.Open.TimeServers) {
		t.Fatalf("the clock got %v", srv)
	}
	if !e.ready() {
		t.Fatal("not ready after the swap")
	}
	if p := e.lastPath(); p == nil || *p != (backend.UpdatePath{Group: "open", Version: 1, Path: "normal"}) {
		t.Fatalf("path %+v", p)
	}

	// A restart starts the clock on the setup's list, then switches it once
	// to the list in force.
	e.restart()
	if srv, _ := ft.got(); len(srv) != 2 || !slices.Equal(srv[1], b.Open.TimeServers) {
		t.Fatalf("after the restart the clock got %v", srv)
	}
	if err := e.upd.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if srv, _ := ft.got(); len(srv) != 2 {
		t.Fatalf("a second switch: %v", srv)
	}
}

// A clock that refuses the values in force stops signing, and the runner
// still takes the update that fixes them.
func TestConfigTimeRefusedStopsSigning(t *testing.T) {
	e, ft := newTimeEnv(t, nil)
	ft.refuse = errors.New("no such server in this build")
	b := e.body(open, 1, e.groupHash(open), e.now())
	b.Open.TimeServers = []string{"fer"}
	h := hashOf(t, b)
	e.mustSend(signed(t, b, first2, nil), wireadmin.ConfigAccepted)
	wantCode(t, e.register(e.setup.Locked.AllowedFeeRecipients[0]), backend.StatusClock, "no such server")
	if e.ready() {
		t.Fatal("ready while the clock refuses the values in force")
	}
	ft.mu.Lock()
	ft.refuse = nil
	ft.mu.Unlock()
	b2 := e.body(open, 2, h, e.now())
	e.mustSend(signed(t, b2, first2, nil), wireadmin.ConfigAccepted)
	if err := e.register(e.setup.Locked.AllowedFeeRecipients[0]); err != nil {
		t.Fatalf("after the fix: %v", err)
	}
}

// An update that comes into force while nothing switches the clock stops
// signing until the clock runs on its time values: no signature uses the
// values before it.
func TestConfigTimeSignsOnlyOnTheValuesInForce(t *testing.T) {
	e, ft := newTimeEnv(t, nil)
	fee := e.setup.Locked.AllowedFeeRecipients[0]
	b := e.body(open, 1, e.groupHash(open), e.now()+100)
	b.Open.TimeServers = []string{"fer"}
	e.mustSend(signed(t, b, first2, nil), wireadmin.ConfigAccepted)
	if err := e.register(fee); err != nil {
		t.Fatalf("before the effective time: %v", err)
	}
	e.clock.add(100)
	// In force now; the clock switches at the next Sync.
	wantCode(t, e.register(fee), backend.StatusClock, "does not run on the time values in force")
	if e.ready() {
		t.Fatal("ready before the switch")
	}
	if err := e.upd.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if srv, _ := ft.got(); len(srv) != 1 || !slices.Equal(srv[0], b.Open.TimeServers) {
		t.Fatalf("the clock got %v", srv)
	}
	if err := e.register(fee); err != nil {
		t.Fatalf("after the switch: %v", err)
	}
}

// A clock that started on newer signed values than the setup's (the start
// fallback) switches at start to the values really in force, and signs
// only once it has.
func TestConfigTimeStartsOnFallbackValues(t *testing.T) {
	e, ft := newTimeEnv(t, nil)
	ntp := setupwire.TimePolicy{Protocol: setupwire.ClockNTP, MaxBoundMs: 200, MaxSampleBoundMs: 400}
	// The log holds no update: the clock started on looser values than
	// those in force and goes back to the setup's at start.
	e.clockPolicy, e.clockServers = &ntp, []string{"fer"}
	e.restart()
	srv, pol := ft.got()
	if len(pol) != 1 || pol[0] != e.setup.Locked.TimePolicy || len(srv) != 1 || len(srv[0]) != 0 {
		t.Fatalf("the clock got servers %v, policies %+v", srv, pol)
	}
	if err := e.register(e.setup.Locked.AllowedFeeRecipients[0]); err != nil {
		t.Fatal(err)
	}

	// The loosened policy in force, by break-glass: a restart that starts
	// the clock on it needs no switch.
	b := e.body(locked, 1, e.groupHash(locked), e.now())
	b.Locked.TimePolicy = ntp
	e.mustSend(signed(t, b, all3, nil), wireadmin.ConfigAccepted)
	if _, pol := ft.got(); len(pol) != 2 || pol[1] != ntp {
		t.Fatalf("policies %+v", pol)
	}
	e.clockServers = nil
	e.restart()
	if _, pol := ft.got(); len(pol) != 2 {
		t.Fatalf("a switch with the clock on the values in force: %+v", pol)
	}
	if err := e.register(e.setup.Locked.AllowedFeeRecipients[0]); err != nil {
		t.Fatal(err)
	}
}
