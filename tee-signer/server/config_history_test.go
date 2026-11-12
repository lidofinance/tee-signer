package server

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
	"github.com/lidofinance/tee-signer/slashing-log"
)

// rv-pb4.3: with n = 3 and k = 2, two approvers remove the third at once
// (emergency removal), and are then every approver. Until one change delay
// after the removal, break-glass is no path: NTS to NTP waits the change
// delay, and a dropped revocation is refused. The record keeps the removal
// time across a restart. After the delay, break-glass is back.
func TestBreakGlassHeldAfterRemoval(t *testing.T) {
	e, _ := newTimeEnv(t, u64(3600))
	t0 := e.now()
	rm := e.body(locked, 1, e.groupHash(locked), t0)
	rm.Locked.Approvers = approverSet(2, 1, 2)
	h1 := hashOf(t, rm)
	if st := e.mustSend(signed(t, rm, first2, []byte{1, 2}), wireadmin.ConfigAccepted); st.Locked != (backend.ConfigGroup{Version: 1, Hash: h1}) {
		t.Fatalf("emergency removal: %+v", st.Locked)
	}
	if err := e.upd.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if got := e.log.State().RemovedAt; got != t0 {
		t.Fatalf("removal time in the record %d, want %d", got, t0)
	}
	ntp := setupwire.TimePolicy{Protocol: setupwire.ClockNTP, MaxBoundMs: 200, MaxSampleBoundMs: 500}
	lockedOn := func(v uint64, prev [32]byte, change func(l *setupwire.Locked)) *setupwire.UpdateBody {
		b := e.body(locked, v, prev, e.now())
		b.Locked.Approvers = rm.Locked.Approvers
		change(b.Locked)
		return b
	}
	bg := lockedOn(2, h1, func(l *setupwire.Locked) { l.TimePolicy = ntp })
	h2 := hashOf(t, bg)
	if st := e.mustSend(signed(t, bg, first2, nil), wireadmin.ConfigAccepted); st.Locked.Pending != pending(2, h2, e.now()+3600) {
		t.Fatalf("NTS to NTP by every approver right after the removal: %+v, want pending for the change delay", st.Locked)
	}
	e.restart()
	if got := e.log.State().RemovedAt; got != t0 {
		t.Fatalf("removal time after the restart %d, want %d", got, t0)
	}
	drop := openWith(e, 1, e.groupHash(open), e.now(), e.setup.Open.RevokedClientCerts[1:]...)
	if _, _, err := e.send(signed(t, drop, first2, nil)); refusedWith(err) != backend.StatusBadRequest || !strings.Contains(err.Error(), "after the approver removal") {
		t.Fatalf("a revocation drop right after the removal: %v, want refused", err)
	}

	// One change delay after the removal (the NTP update is in force too).
	e.clock.set(func(c *fakeClock) { c.t = c.t.Add(3600 * 1e9) })
	b3 := lockedOn(3, h2, func(l *setupwire.Locked) {
		l.TimePolicy = setupwire.TimePolicy{Protocol: setupwire.ClockNTP, MaxBoundMs: 250, MaxSampleBoundMs: 500}
	})
	h3 := hashOf(t, b3)
	if st := e.mustSend(signed(t, b3, first2, nil), wireadmin.ConfigAccepted); st.Locked != (backend.ConfigGroup{Version: 3, Hash: h3}) {
		t.Fatalf("a bound raised by every approver after the delay: %+v, want in force at once", st.Locked)
	}
	drop = openWith(e, 1, e.groupHash(open), e.now(), e.setup.Open.RevokedClientCerts[1:]...)
	e.mustSend(signed(t, drop, first2, nil), wireadmin.ConfigAccepted)
}

// rv-dko.2: with n = 3 and k = 2, two approvers rotate to their own two
// keys (no removal in shape: the order changes) and are every approver once
// the rotation is in force. A raised bound by break-glass is in force at
// once, but an added image waits the images wait. The record keeps the
// time the set came into force across a restart. Once the set has been in
// force for the images wait, break-glass adds the image at once.
func TestImageBreakGlassHeldAfterRotation(t *testing.T) {
	e, _ := newTimeEnv(t, u64(3600))
	images := max(3600, uint64(setupwire.ImagesMinTimeLock))
	own := approverSet(2, 2, 1)
	every := []by{{0, 2}, {1, 1}}
	rot := e.body(locked, 1, e.groupHash(locked), e.now())
	rot.Locked.Approvers = own
	h1 := hashOf(t, rot)
	rotAt := e.now() + 3600
	if st := e.mustSend(signed(t, rot, first2, []byte{2, 1}), wireadmin.ConfigAccepted); st.Locked.Pending != pending(1, h1, rotAt) {
		t.Fatalf("rotation: %+v, want pending for the change delay", st.Locked)
	}
	e.clock.add(3600)
	if err := e.upd.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if st := e.log.State(); st.ApproversAt != rotAt || st.RemovedAt != 0 {
		t.Fatalf("the record: approver set time %d, removal time %d; want %d, 0", st.ApproversAt, st.RemovedAt, rotAt)
	}
	lockedOn := func(v uint64, prev [32]byte, change func(l *setupwire.Locked)) *setupwire.UpdateBody {
		b := e.body(locked, v, prev, e.now())
		b.Locked.Approvers = own
		b.Locked.TimePolicy.MaxBoundMs, b.Locked.TimePolicy.MaxSampleBoundMs = 150, 150
		change(b.Locked)
		return b
	}
	addImage := func(l *setupwire.Locked) {
		l.AllowedImageMeasurements = append(l.AllowedImageMeasurements, setupwire.Image{Kind: setupwire.ImageGCP, Measurement: bytes.Repeat([]byte{0x78}, 32)})
	}
	bound := lockedOn(2, h1, func(*setupwire.Locked) {})
	h2 := hashOf(t, bound)
	if st := e.mustSend(signed(t, bound, every, nil), wireadmin.ConfigAccepted); st.Locked != (backend.ConfigGroup{Version: 2, Hash: h2}) {
		t.Fatalf("a bound raised by every approver right after the rotation: %+v, want in force at once", st.Locked)
	}
	img := lockedOn(3, h2, addImage)
	if st := e.mustSend(signed(t, img, every, nil), wireadmin.ConfigAccepted); st.Locked.Pending != pending(3, hashOf(t, img), e.now()+images) {
		t.Fatalf("an image added by every approver right after the rotation: %+v, want pending for the images wait", st.Locked)
	}
	e.restart()
	if got := e.log.State().ApproversAt; got != rotAt {
		t.Fatalf("approver set time after the restart %d, want %d", got, rotAt)
	}
	// A second before the set has been in force for the images wait.
	e.clock.add(images - 1)
	img = lockedOn(4, h2, addImage)
	if st := e.mustSend(signed(t, img, every, nil), wireadmin.ConfigAccepted); st.Locked.Pending != pending(4, hashOf(t, img), e.now()+images) {
		t.Fatalf("an image added a second early: %+v, want pending", st.Locked)
	}
	e.clock.add(1)
	img = lockedOn(5, h2, addImage)
	if st := e.mustSend(signed(t, img, every, nil), wireadmin.ConfigAccepted); st.Locked != (backend.ConfigGroup{Version: 5, Hash: hashOf(t, img)}) {
		t.Fatalf("an image added by every approver after the images wait: %+v, want in force at once", st.Locked)
	}
}

// rv-pb4.2: a time_policy the NTS clock cannot meet (a 1 ms bound) stops
// the NTS time. The update that undoes it is still taken, on the coarse
// clock; without a coarse reading it is refused. Signing waits for the NTS
// quorum, which forms again on the old values.
func TestConfigUpdateOnCoarseClock(t *testing.T) {
	e, ft := newTimeEnv(t, u64(3600))
	e.coarse = &coarseFake{fakeClock: e.clock}
	e.restart()
	fee := e.setup.Locked.AllowedFeeRecipients[0]
	tight := e.body(locked, 1, e.groupHash(locked), e.now())
	tight.Locked.TimePolicy.MaxBoundMs, tight.Locked.TimePolicy.MaxSampleBoundMs = 1, 80
	h1 := hashOf(t, tight)
	if st := e.mustSend(signed(t, tight, first2, nil), wireadmin.ConfigAccepted); st.Locked != (backend.ConfigGroup{Version: 1, Hash: h1}) {
		t.Fatalf("a 1 ms bound: %+v, want in force at once", st.Locked)
	}
	// No quorum under 1 ms.
	e.clock.set(func(c *fakeClock) { c.err = errClockDown })
	wantCode(t, e.register(fee), backend.StatusClock, "")
	undo := e.body(locked, 2, h1, e.now())
	h2 := hashOf(t, undo)
	raw := signed(t, undo, all3, nil)
	e.clock.set(func(*fakeClock) { e.coarse.off = true })
	_, _, err := e.send(raw)
	wantCode(t, err, backend.StatusClock, "no trusted time")
	e.clock.set(func(*fakeClock) { e.coarse.off = false })
	if st := e.mustSend(raw, wireadmin.ConfigAccepted); st.Locked != (backend.ConfigGroup{Version: 2, Hash: h2}) {
		t.Fatalf("the undo on the coarse clock: %+v, want in force at once", st.Locked)
	}
	if _, pol := ft.got(); len(pol) == 0 || pol[len(pol)-1] != e.setup.Locked.TimePolicy {
		t.Fatalf("the clock got %+v", pol)
	}
	// Signing needs the NTS clock: still refused on the coarse one.
	wantCode(t, e.register(fee), backend.StatusClock, "")
	e.clock.set(func(c *fakeClock) { c.err = nil })
	if err := e.register(fee); err != nil {
		t.Fatalf("after the NTS quorum is back: %v", err)
	}
}

// rv-pb4.5 (1): a rotation in force drops the pending open update, but not
// its revocations: they stay enforced (carried in the record), across a
// restart, until an open update comes into force. Leaving one out of that
// update needs every approver of the new set.
func TestRotationKeepsPendingRevocations(t *testing.T) {
	e := newEnv(t, u64(0))
	r := useRevoked(e)
	h := [32]byte{0x91}
	base := len(e.setup.Open.RevokedClientCerts)
	t0 := e.now()
	e.mustSend(signed(t, openWith(e, 1, e.groupHash(open), t0+1000, withBase(e, h)...), first2, nil), wireadmin.ConfigAccepted)
	rot := e.body(locked, 1, e.groupHash(locked), t0)
	rot.Locked.Approvers = approverSet(2, 1, 2, 4)
	st := e.mustSend(signed(t, rot, first2, []byte{1, 2, 4}), wireadmin.ConfigAccepted)
	if st.Locked.Version != 1 || st.Open.Pending != (backend.PendingUpdate{}) {
		t.Fatalf("rotation: %+v", st)
	}
	if r.Len() != base+1 || r.Incomplete() {
		t.Fatalf("after the rotation: %d entries (want %d), incomplete %v", r.Len(), base+1, r.Incomplete())
	}
	if err := e.upd.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if c := e.log.State().Carried; !slices.Contains(c, h) {
		t.Fatalf("carried in the record: %x", c)
	}
	e.restart()
	r = useRevoked(e)
	if r.Len() != base+1 || r.Incomplete() {
		t.Fatalf("after a restart: %d entries (want %d), incomplete %v", r.Len(), base+1, r.Incomplete())
	}
	drop := openWith(e, 2, e.groupHash(open), e.now(), withBase(e)...)
	_, _, err := e.send(signed(t, drop, first2, nil))
	if refusedWith(err) != backend.StatusBadRequest || !strings.Contains(err.Error(), "pending or carried") {
		t.Fatalf("leaving the carried revocation out with 2 of 3: %v, want refused", err)
	}
	e.mustSend(signed(t, drop, []by{{0, 1}, {1, 2}, {2, 4}}, nil), wireadmin.ConfigAccepted)
	if r.Len() != base {
		t.Fatalf("after the open update by every approver: %d entries, want %d", r.Len(), base)
	}
	if err := e.upd.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if c := e.log.State().Carried; c != nil {
		t.Fatalf("carried after an open update in force: %x", c)
	}
}

// rv-pb4.5 (2): a withheld locked body at its effective time makes the
// view miss values, and the revoked set incomplete, though the open bodies
// are readable.
func TestWithheldLockedBodyMakesRevocationsIncomplete(t *testing.T) {
	e := newEnv(t, u64(600))
	t0 := e.now()
	lk := e.body(locked, 1, e.groupHash(locked), t0)
	lk.Locked.AllowedFeeRecipients = append(lk.Locked.AllowedFeeRecipients, x)
	e.mustSend(signed(t, lk, first2, nil), wireadmin.ConfigAccepted)
	if err := e.upd.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	e.signer.Close()
	if err := os.Remove(filepath.Join(e.dir, "marks", markstore.BodyName(e.hash, locked, 1, 1))); err != nil {
		t.Fatal(err)
	}
	e.start()
	r := useRevoked(e)
	if r.Incomplete() {
		t.Fatal("incomplete before the locked update's effective time")
	}
	e.clock.add(601)
	e.upd.reconcile()
	if !r.Incomplete() {
		t.Fatal("complete while the locked body coming into force is withheld")
	}
}

// Mythos 1: the setup says NTS and an update in force says NTP. At start
// StartConfig switches the clock, which drops every sample; WaitClock
// waits until the clock answers on the new values, and fails the start
// when it does not within the wait.
func TestStartWaitsForClockOnValuesInForce(t *testing.T) {
	e, ft := newTimeEnv(t, u64(3600))
	ntp := setupwire.TimePolicy{Protocol: setupwire.ClockNTP, MaxBoundMs: 200, MaxSampleBoundMs: 500}
	b := e.body(locked, 1, e.groupHash(locked), e.now())
	b.Locked.TimePolicy = ntp
	e.mustSend(signed(t, b, all3, nil), wireadmin.ConfigAccepted)
	if err := e.upd.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name  string
		fails int
		wait  time.Duration
		ok    bool
	}{{"a quorum after three reads", 3, 5 * time.Second, true}, {"no quorum", 1 << 30, 50 * time.Millisecond, false}} {
		ft.mu.Lock()
		ft.onPolicy = func(p setupwire.TimePolicy) {
			if p.Protocol == setupwire.ClockNTP {
				e.clock.set(func(fc *fakeClock) { fc.failNext = c.fails })
			}
		}
		ft.mu.Unlock()
		// A start: the clock runs on the setup's NTS values.
		pol := e.setup.Locked.TimePolicy
		u, err := NewUpdates(UpdatesOptions{Setup: e.setup, SetupHash: e.hash, Log: e.log, Clock: e.clock, Logger: quiet, Time: ft, ClockPolicy: &pol})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := u.StartConfig(baseConfig(e.setup)); err != nil {
			t.Fatal(err)
		}
		if _, err := e.clock.Now(); err == nil {
			t.Fatalf("%s: the clock answers right after the switch", c.name)
		}
		err = u.WaitClock(ctx, c.wait, time.Millisecond)
		if (err == nil) != c.ok {
			t.Fatalf("%s: %v, want ok %v", c.name, err, c.ok)
		}
		e.clock.set(func(fc *fakeClock) { fc.failNext = 0 })
	}
}

// Mythos 7: HEALTH's last_update_path comes from the record, so it holds
// after a restart.
func TestLastUpdatePathAfterRestart(t *testing.T) {
	e, _ := newTimeEnv(t, u64(3600))
	b := e.body(locked, 1, e.groupHash(locked), e.now())
	b.Locked.AllowedImageMeasurements = append(b.Locked.AllowedImageMeasurements, setupwire.Image{Kind: setupwire.ImageGCP, Measurement: bytes.Repeat([]byte{0x78}, 32)})
	e.mustSend(signed(t, b, all3, nil), wireadmin.ConfigAccepted)
	want := backend.UpdatePath{Group: "locked", Version: 1, Path: "break-glass"}
	if p := e.lastPath(); p == nil || *p != want {
		t.Fatalf("path %+v", p)
	}
	if err := e.upd.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	e.restart()
	if p := e.lastPath(); p == nil || *p != want {
		t.Fatalf("path after a restart %+v, want %+v", p, want)
	}
}
