package server

import (
	"sync"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-protocol"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

// gateClock is the test clock whose next read, once armed, takes the time
// and then waits for open before it returns it: a request that read the
// time and then waited while the clock moved on.
type gateClock struct {
	*fakeClock
	mu      sync.Mutex
	armed   bool
	reached chan struct{}
	open    chan struct{}
}

func (c *gateClock) Now() (time.Time, error) {
	t, err := c.fakeClock.Now()
	c.mu.Lock()
	armed := c.armed
	c.armed = false
	c.mu.Unlock()
	if armed {
		close(c.reached)
		<-c.open
	}
	return t, err
}

// SG-ACTIVATE-01: a registration that read the config before an update's
// effective time, and reached the core after it, must not sign under the
// values the update replaced. The locked update drops the fee recipient
// old; the request reads the time before the effective time, the clock
// moves past it, and then the request goes on. It is refused, or signed
// under the new values, which refuse old too.
func TestSignAcrossEffectiveTimeUsesTheValuesInForce(t *testing.T) {
	e := newEnv(t, u64(3600))
	old := e.setup.Locked.AllowedFeeRecipients[0]
	b := e.body(locked, 1, e.groupHash(locked), e.now())
	b.Locked.AllowedFeeRecipients = []backend.Address{x}
	e.mustSend(signed(t, b, first2, nil), wireadmin.ConfigAccepted)
	if err := e.register(old); err != nil {
		t.Fatalf("before the effective time: %v", err)
	}
	gc := &gateClock{fakeClock: e.clock, armed: true, reached: make(chan struct{}), open: make(chan struct{})}
	e.upd.opt.Clock = gc
	done := make(chan error, 1)
	go func() { done <- e.register(old) }()
	<-gc.reached
	e.clock.add(3601)
	close(gc.open)
	if err := <-done; err == nil {
		t.Fatal("a registration to the dropped fee recipient signed after the update came into force")
	}
	if err := e.register(x); err != nil {
		t.Fatalf("the new fee recipient: %v", err)
	}
}
