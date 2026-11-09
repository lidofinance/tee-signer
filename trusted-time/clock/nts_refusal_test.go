//go:build nts

package clock

import (
	"crypto/x509"
	"net"
	"strings"
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

// closedAddr is a loopback address nothing listens on.
func closedAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// Until the first quorum, a failed NTS-KE is tried again after 3/4 to 5/4
// Interval, not after a doubling wait: a relay that comes up late must not
// push the next try past the runner's start wait. From the first quorum on
// the wait doubles up to maxPoll.
func TestNTSClockKeyExchangeWaitsIntervalUntilFirstQuorum(t *testing.T) {
	fs := newServers(t, nil, "a", "b", "c")
	down := closedAddr(t)
	n := &NTS{Coarse: &coarseClock{}, Interval: 50 * time.Millisecond, minPoll: 10 * time.Millisecond, maxPoll: 400 * time.Millisecond,
		StartDelay: -1}
	for _, f := range fs {
		s := f.srv
		s.KEAddr, s.Roots = down, x509.NewCertPool()
		n.Servers = append(n.Servers, s)
	}
	keWaits := func() []time.Duration {
		var out []time.Duration
		for _, p := range n.peers {
			out = append(out, p.keWait)
		}
		return out
	}
	for try := 1; try <= 3; try++ {
		if try > 1 {
			time.Sleep(70 * time.Millisecond)
		}
		if err := refresh(t, n); err == nil {
			t.Fatalf("try %d: a quorum without a key exchange", try)
		}
		for i, w := range keWaits() {
			if w < n.Interval*3/4 || w >= n.Interval*5/4 {
				t.Fatalf("try %d, peer %d: key exchange wait %v before the first quorum, want %v to %v (waits %v)",
					try, i, w, n.Interval*3/4, n.Interval*5/4, keWaits())
			}
		}
	}
	if fails := n.Status().Peers["a"].Stats.KEFail; fails != 3 {
		t.Fatalf("key exchange failures with a: %d, want 3", fails)
	}
	// The servers come up: the first quorum.
	for i, f := range fs {
		n.peers[i].srv.KEAddr, n.peers[i].srv.Roots = f.ke.Addr, f.srv.Roots
	}
	time.Sleep(70 * time.Millisecond)
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	// Then a's key exchange fails again: the wait doubles from Interval.
	n.peers[0].srv.KEAddr = down
	fs[0].store.Forget()
	time.Sleep(60 * time.Millisecond)
	_ = refresh(t, n) // NTSN: a drops its keys
	want := []time.Duration{50 * time.Millisecond, 100 * time.Millisecond, 200 * time.Millisecond}
	for i, w := range want {
		time.Sleep(w + 10*time.Millisecond)
		_ = refresh(t, n)
		if got := n.peers[0].keWait; got != w {
			t.Fatalf("failure %d after the first quorum: key exchange wait %v, want %v", i+1, got, w)
		}
	}
}
