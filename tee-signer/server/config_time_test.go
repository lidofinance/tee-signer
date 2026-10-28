package server

import (
	"sync"
	"testing"
	"time"

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
// view is older; the read fails; LockedInForce refuses instead of
// returning the old set, and lockedNow returns the new set with the one
// time it read.
func TestLockedInForceRefusesOnClockError(t *testing.T) {
	e, at := rotationPending(t)
	hc := &hookClock{fakeClock: e.clock}
	e.upd.opt.Clock = hc
	e.clock.add(at - e.now() + 1)
	hc.fail = 1
	if l, err := e.upd.LockedInForce(); err == nil {
		t.Fatalf("clock down: LockedInForce gave approvers %x, want a refusal", l.Approvers.Hash())
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
