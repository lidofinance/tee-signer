//go:build nts

package clock

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// A quorum that fails the coarse check stops the clock: Now refuses until a
// quorum passes, as after a drift refusal, instead of serving the earlier
// quorum until its samples age out.
func TestNTSClockCoarseRefusalStopsServing(t *testing.T) {
	fs := newServers(t, nil, "a", "b", "c")
	coarse := &coarseClock{}
	n := newNTS(fs, coarse)
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	if _, err := n.Now(); err != nil {
		t.Fatal(err)
	}
	// The coarse clock falls 40 s behind the servers: the next quorum is
	// refused.
	coarse.Skew = -40 * time.Second
	time.Sleep(60 * time.Millisecond)
	if err := refresh(t, n); err == nil || !strings.Contains(err.Error(), "coarse clock") {
		t.Fatalf("refresh with the coarse clock 40 s behind: %v", err)
	}
	if got, err := n.Now(); err == nil {
		t.Fatalf("Now after the coarse refusal served %v from the host clock, want an error", testClock().Sub(got))
	}
	if sum := n.NTSSummary(); sum.Quorum || !strings.Contains(sum.Refused, "coarse clock") {
		t.Fatalf("summary %+v", sum)
	}
	// Agreement again: the next quorum is served.
	coarse.Skew = 0
	time.Sleep(60 * time.Millisecond)
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	if _, err := n.Now(); err != nil {
		t.Fatalf("Now after the coarse clock agrees again: %v", err)
	}
}

// Until the first quorum, a failed NTS-KE is tried again after Interval,
// not after a doubling wait: a relay that comes up late must not push the
// next try past the runner's start wait. From the first quorum on the wait
// doubles up to maxPoll (the core's rule; TestKeyExchangeBackoff in
// ntscore pins the waits one by one). Here the key exchange fails through
// the dialer, the real client's path.
func TestNTSClockKeyExchangeWaitsIntervalUntilFirstQuorum(t *testing.T) {
	fs := newServers(t, nil, "a", "b", "c")
	var mu sync.Mutex
	down := map[string]bool{} // KE addresses the dialer refuses
	n := newNTS(fs, &coarseClock{})
	n.Interval, n.minPoll, n.maxPoll = 50*time.Millisecond, 10*time.Millisecond, 400*time.Millisecond
	n.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		refused := network == "tcp" && down[addr]
		mu.Unlock()
		if refused {
			return nil, errors.New("connect: connection refused")
		}
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	setDown := func(addrs ...string) {
		mu.Lock()
		clear(down)
		for _, a := range addrs {
			down[a] = true
		}
		mu.Unlock()
	}
	keFails := func(op string) int { return n.Status().Peers[op].Stats.KEFail }
	// Nobody reachable: three tries 60 ms apart are three failures each,
	// not one, two with a doubling wait (50, then 100 ms).
	setDown(fs[0].srv.KEAddr, fs[1].srv.KEAddr, fs[2].srv.KEAddr)
	for try := 1; try <= 3; try++ {
		if try > 1 {
			time.Sleep(60 * time.Millisecond)
		}
		if err := refresh(t, n); err == nil {
			t.Fatalf("try %d: a quorum without a key exchange", try)
		}
		for _, op := range []string{"a", "b", "c"} {
			if got := keFails(op); got != try {
				t.Fatalf("try %d, %s: %d key exchange failures before the first quorum, want one per try", try, op, got)
			}
		}
	}
	// The servers come up: the first quorum.
	setDown()
	time.Sleep(60 * time.Millisecond)
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	if _, err := n.Now(); err != nil {
		t.Fatal(err)
	}
	// a loses its server's keys (NTSN on every answer, never authenticated:
	// the core keeps polling with the cookies it holds and runs NTS-KE
	// when they run out) and its key exchange fails from then on: the
	// failures now come at a doubling wait, fewer than one per try.
	fs[0].store.Forget()
	setDown(fs[0].srv.KEAddr)
	before := keFails("a")
	for try := 0; try < 12 && keFails("a") == before; try++ {
		time.Sleep(60 * time.Millisecond)
		_ = refresh(t, n)
	}
	if keFails("a") == before {
		t.Fatal("no key exchange failure of a after its cookies ran out")
	}
	first := keFails("a")
	for try := 0; try < 6; try++ {
		time.Sleep(60 * time.Millisecond)
		_ = refresh(t, n)
	}
	if got := keFails("a") - first; got < 1 || got >= 6 {
		t.Fatalf("%d key exchange failures of a in six tries 60 ms apart after the first quorum: want a doubling wait (50, 100, 200 ms), not one per try", got)
	}
}
