package server

import (
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-protocol"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

// hookClock is the test clock with a hook: fail makes the next reads fail,
// read gets a signal on each successful read.
type hookClock struct {
	*fakeClock
	mu   sync.Mutex
	fail int
	read chan struct{}
}

func (c *hookClock) Now() (time.Time, error) {
	c.mu.Lock()
	fail := c.fail > 0
	if fail {
		c.fail--
	}
	c.mu.Unlock()
	if fail {
		return time.Time{}, errClockDown
	}
	t, err := c.fakeClock.Now()
	if c.read != nil {
		select {
		case c.read <- struct{}{}:
		default:
		}
	}
	return t, err
}

var errClockDown = backend.Refused(backend.StatusClock, "test clock down")

// rotationPending is an env with a rotation of approvers 1-3 to 4-6 pending,
// in force at the returned time.
func rotationPending(t *testing.T) (*env, uint64) {
	e := newEnv(t, u64(3600))
	t0 := e.now()
	rot := e.body(locked, 1, e.groupHash(locked), t0)
	rot.Locked.Approvers = approverSet(2, 4, 5, 6)
	e.mustSend(signed(t, rot, first2, []byte{4, 5, 6}), wireadmin.ConfigAccepted)
	return e, t0 + 3600
}

// SSI-AUTH-01: a failed clock read does not hand out the approvers of a
// view the clock has left. The rotation came into force while the last
// view is older; lockedNow returns the new set with the one time it read.
func TestLockedNowAfterClockError(t *testing.T) {
	e, at := rotationPending(t)
	hc := &hookClock{fakeClock: e.clock}
	e.upd.opt.Clock = hc
	e.clock.add(at - e.now() + 1)
	hc.fail = 1
	if _, _, err := e.upd.lockedNow(); err == nil {
		t.Fatal("clock down: lockedNow gave approvers, want a refusal")
	}
	newSet := approverSet(2, 4, 5, 6)
	l, now, err := e.upd.lockedNow()
	if err != nil || now < at || l.Approvers.Hash() != newSet.Hash() {
		t.Fatalf("lockedNow: %v at %d, want the new set at or after %d", err, now, at)
	}
}

// SG-ACTIVATE-02: Accept reads the time after it holds writeMu. An old-set
// supersede waits for writeMu across the rotation's effective time; when it
// runs, the rotation is in force and the old set's signatures count no
// more.
func TestAcceptReadsTimeUnderWriteMu(t *testing.T) {
	e, at := rotationPending(t)
	hc := &hookClock{fakeClock: e.clock, read: make(chan struct{}, 1)}
	e.upd.opt.Clock = hc
	cancel := e.body(locked, 2, e.groupHash(locked), e.now())
	raw := signed(t, cancel, first2, nil)

	e.upd.writeMu.Lock()
	type result struct {
		o   uint8
		err error
	}
	done := make(chan result, 1)
	go func() {
		o, _, err := e.send(raw)
		done <- result{o, err}
	}()
	// Let the request read the clock, if it does before writeMu.
	select {
	case <-hc.read:
	case <-time.After(300 * time.Millisecond):
	}
	e.clock.add(at - e.now() + 1)
	e.upd.writeMu.Unlock()
	r := <-done
	newSet := approverSet(2, 4, 5, 6)
	if r.err == nil {
		t.Fatalf("the old set's supersede was taken after the rotation came into force (outcome %d)", r.o)
	}
	if st := e.srv.SetupState(); st.Locked.Version != 1 || st.ApproverSetHash != newSet.Hash() {
		t.Fatalf("after the supersede: %+v, want the rotation in force", st.Locked)
	}
}

// SETUP-AUTH-01: a supersede checked before a rotation's effective time
// must not undo the rotation when another request brought it into force
// before the supersede's record was written.
func TestAcceptDoesNotUndoAnActivation(t *testing.T) {
	e, at := rotationPending(t)
	cancel := e.body(locked, 2, e.groupHash(locked), e.now())
	e.log.onPut = func() {
		e.log.onPut = nil
		e.clock.add(at - e.now() + 1)
		e.srv.SetupState()
	}
	if _, _, err := e.send(signed(t, cancel, first2, nil)); err == nil {
		t.Fatal("the supersede was taken after the rotation came into force")
	}
	newSet := approverSet(2, 4, 5, 6)
	if st := e.srv.SetupState(); st.Locked.Version != 1 || st.ApproverSetHash != newSet.Hash() {
		t.Fatalf("after the supersede: %+v, want the rotation in force", st.Locked)
	}
	e.restart()
	if st := e.srv.SetupState(); st.Locked.Version != 1 || st.ApproverSetHash != newSet.Hash() {
		t.Fatalf("after a restart: %+v, want the rotation in force", st.Locked)
	}
}

// steadyClock is the test clock without its error: the runner's reads
// succeed while the core's reads (state.Hooks.Now) see fakeClock.err.
type steadyClock struct{ *fakeClock }

func (c steadyClock) Now() (time.Time, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t, nil
}

// A clock failure inside the core while the runner applies an update that
// came due refuses that sign only: the next sign with the clock back
// applies the update and signs.
func TestConfigApplyRetriesAfterCoreClockError(t *testing.T) {
	e := newEnv(t, u64(3600))
	e.upd.opt.Clock = steadyClock{e.clock}
	t0 := e.now()
	eT := (t0 + 3600 - testGenesis) / testEpoch
	b := e.body(locked, 1, e.groupHash(locked), t0)
	b.Locked.SlotTimeChanges = []setupwire.SlotTimeChange{{Epoch: eT + 4, SecondsPerSlot: 4}}
	e.mustSend(signed(t, b, first2, nil), wireadmin.ConfigAccepted)
	e.clock.add(3600)
	fee := e.setup.Locked.AllowedFeeRecipients[0]
	e.clock.set(func(c *fakeClock) { c.err = errClockDown })
	if err := e.register(fee); err == nil {
		t.Fatal("core clock down: signed")
	}
	e.clock.set(func(c *fakeClock) { c.err = nil })
	if err := e.register(fee); err != nil {
		t.Fatalf("clock back: %v", err)
	}
	want := []core.SlotTimeChange{{Epoch: eT + 4, SecondsPerSlot: 4}}
	if got := e.signer.Config().SlotTimeChanges; !slices.Equal(got, want) {
		t.Fatalf("slot times in the core: %+v", got)
	}
}

// A clock failure inside the core while Accept applies an update that came
// due leaves the core on the values before it. A new update is refused
// then, open and locked, since the core checks would run against those
// values; once a reconcile applies the update, both are accepted.
func TestConfigAcceptRefusedAfterCoreClockError(t *testing.T) {
	e := newEnv(t, u64(3600))
	e.upd.opt.Clock = steadyClock{e.clock}
	t0 := e.now()
	eT := (t0 + 3600 - testGenesis) / testEpoch
	b1 := e.body(locked, 1, e.groupHash(locked), t0)
	b1.Locked.SlotTimeChanges = []setupwire.SlotTimeChange{{Epoch: eT + 4, SecondsPerSlot: 4}}
	e.mustSend(signed(t, b1, first2, nil), wireadmin.ConfigAccepted)
	e.clock.add(3600)
	now := e.now()
	ob := e.body(open, 1, e.groupHash(open), now)
	ob.Open.ForkSchedule = append(ob.Open.ForkSchedule, setupwire.Fork{Epoch: eT + 1000, Version: v6})
	lb := e.body(locked, 2, hashOf(t, b1), now)
	lb.Locked.AllowedFeeRecipients = append(lb.Locked.AllowedFeeRecipients, x)
	lb.Locked.SlotTimeChanges = b1.Locked.SlotTimeChanges
	for _, raw := range [][]byte{signed(t, ob, first2, nil), signed(t, lb, first2, nil)} {
		e.clock.set(func(c *fakeClock) { c.failNext = 1 })
		_, _, err := e.send(raw)
		wantCode(t, err, backend.StatusClock, "send it again")
	}
	if st := e.log.State(); st.Open.Pending != nil || st.Locked.Pending == nil || st.Locked.Pending.Version != 1 {
		t.Fatalf("refused, but pending: %+v", st)
	}
	e.mustSend(signed(t, ob, first2, nil), wireadmin.ConfigAccepted)
	e.mustSend(signed(t, lb, first2, nil), wireadmin.ConfigAccepted)
	want := []core.SlotTimeChange{{Epoch: eT + 4, SecondsPerSlot: 4}}
	if got := e.signer.Config().SlotTimeChanges; !slices.Equal(got, want) {
		t.Fatalf("slot times in the core: %+v", got)
	}
}
