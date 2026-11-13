//go:build nts

package clock

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// SetPolicy refuses what the clock cannot run, and changes nothing then.
func TestNTSSetPolicyRefusals(t *testing.T) {
	w := newFollowWorld(20)
	n := newFollowNTS(w, 8, []byte("policy"))
	for _, tc := range []struct {
		p        Protocol
		max, smp time.Duration
	}{
		{"sntp", 100 * time.Millisecond, 100 * time.Millisecond},
		{ProtocolNTS, 0, 100 * time.Millisecond},
		{ProtocolNTS, 100 * time.Millisecond, 50 * time.Millisecond},
		{ProtocolNTS, 100 * time.Millisecond, 2 * time.Second},
	} {
		if err := n.SetPolicy(tc.p, tc.max, tc.smp); err == nil {
			t.Errorf("%s %v %v: taken", tc.p, tc.max, tc.smp)
		}
	}
	if n.Protocol != "" || n.MaxBound != 0 || n.MaxSampleBound != 0 {
		t.Fatalf("a refused policy changed the clock: %q %v %v", n.Protocol, n.MaxBound, n.MaxSampleBound)
	}
}

// New bounds apply at once and keep the peers. A max bound under the
// quorum's bound stops the time with the next Now, and raising it serves
// the same quorum again with no Refresh. A max sample bound under the
// samples' bound drops them and the quorum they made. The minimum gap
// holds throughout.
func TestNTSSetPolicyBounds(t *testing.T) {
	w := newFollowWorld(21)
	n := newFollowNTS(w, 8, []byte("policy-bounds"))
	if blocked := runSwapWorld(w, n, 0, 10*time.Minute, nil); blocked != 0 {
		t.Fatalf("blocked %d s before the change", blocked)
	}
	before := map[string]*ntsPeer{}
	for _, p := range n.peers {
		before[p.srv.Operator] = p
	}
	// The test samples have a 15 ms bound.
	if err := n.SetPolicy(ProtocolNTS, 5*time.Millisecond, 100*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if _, err := n.Now(); err == nil || !strings.Contains(err.Error(), "error bound") {
		t.Fatalf("max bound 5 ms: %v", err)
	}
	if err := n.SetPolicy(ProtocolNTS, 100*time.Millisecond, 100*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if _, err := n.Now(); err != nil {
		t.Fatalf("max bound back to 100 ms: %v", err)
	}
	// A sample cap under 15 ms drops every sample: no time, and none from
	// the new samples either.
	if err := n.SetPolicy(ProtocolNTS, 10*time.Millisecond, 10*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if _, err := n.Now(); err == nil {
		t.Fatal("time served from samples over the new cap")
	}
	if blocked := runSwapWorld(w, n, 10*time.Minute, 12*time.Minute, nil); blocked != 120 {
		t.Fatalf("blocked %d of 120 s under a 10 ms sample cap", blocked)
	}
	if err := n.SetPolicy(ProtocolNTS, 100*time.Millisecond, 100*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	blocked := runSwapWorld(w, n, 12*time.Minute, 20*time.Minute, nil)
	if _, err := n.Now(); err != nil || blocked > 180 {
		t.Fatalf("after the cap went back: blocked %d s, now %v", blocked, err)
	}
	if g, op := gapsOf(w); g < NTSShiftMinGap {
		t.Fatalf("%s contacted twice %v apart", op, g)
	}
	for _, p := range n.peers {
		if before[p.srv.Operator] != p {
			t.Fatalf("%s got a new peer", p.srv.Operator)
		}
	}
	t.Logf("blocked %d s after the sample cap went back", blocked)
}

// A protocol change, nts to ntp and back, drops every sample and the
// quorum: no time until a Refresh forms a quorum on the new protocol, then
// time again. The peers, the schedule seed and the minimum gap stay.
func TestNTSSetPolicyProtocol(t *testing.T) {
	w := newFollowWorld(22)
	n := newFollowNTS(w, 8, []byte("policy-protocol"))
	if blocked := runSwapWorld(w, n, 0, 10*time.Minute, nil); blocked != 0 {
		t.Fatalf("blocked %d s before the change", blocked)
	}
	before := map[string]*ntsPeer{}
	for _, p := range n.peers {
		before[p.srv.Operator] = p
	}
	seed := string(n.ScheduleSeed)
	from := 10 * time.Minute
	for _, p := range []Protocol{ProtocolNTP, ProtocolNTS} {
		if err := n.SetPolicy(p, 100*time.Millisecond, 100*time.Millisecond); err != nil {
			t.Fatal(err)
		}
		if _, err := n.Now(); err == nil {
			t.Fatalf("to %s: time served before a quorum on it", p)
		}
		for i, peer := range n.peers {
			if ps := n.client.Peer(i); ps.Sample != nil || ps.Cookies != 0 {
				t.Fatalf("to %s: %s kept its sample or its cookies", p, peer.srv.Operator)
			}
		}
		if st := n.client.Status(); st.HaveDrift || st.HaveResult {
			t.Fatalf("to %s: the core kept its result or its drift history", p)
		}
		if s := n.NTSSummary(); s.Protocol != p || s.Quorum || !strings.HasPrefix(n.Source(), string(p)+"(") {
			t.Fatalf("to %s: summary %s quorum %v, source %s", p, s.Protocol, s.Quorum, n.Source())
		}
		blocked := runSwapWorld(w, n, from, from+10*time.Minute, nil)
		from += 10 * time.Minute
		// The next tick may form the quorum at once: a burst asks the
		// servers past their gap.
		if _, err := n.Now(); err != nil || blocked > 180 {
			t.Fatalf("to %s: blocked %d s, now %v", p, blocked, err)
		}
		t.Logf("to %s: blocked %d s", p, blocked)
	}
	if g, op := gapsOf(w); g < NTSShiftMinGap {
		t.Fatalf("%s contacted twice %v apart", op, g)
	}
	for _, p := range n.peers {
		if before[p.srv.Operator] != p {
			t.Fatalf("%s got a new peer", p.srv.Operator)
		}
	}
	if string(n.ScheduleSeed) != seed || len(n.NTSSummary().Actives) != ShiftActives(8) {
		t.Fatalf("seed %q, actives %v", n.ScheduleSeed, n.NTSSummary().Actives)
	}
}

// SetPolicy runs beside Refresh, Now and the status reads (go test -race).
func TestNTSSetPolicyConcurrent(t *testing.T) {
	w := newFollowWorld(23)
	n := newFollowNTS(w, 8, []byte("policy-race"))
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for _, f := range []func(){
		func() { _ = n.Refresh(ctx) },
		func() { _, _ = n.Now() },
		func() { _ = n.NTSSummary(); _ = n.Source(); _ = n.Status() },
	} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				f()
			}
		}()
	}
	for i := range 50 {
		w.at(time.Duration(i) * testTick)
		p := ProtocolNTS
		if i%2 == 1 {
			p = ProtocolNTP
		}
		if err := n.SetPolicy(p, 100*time.Millisecond, time.Duration(100+i)*time.Millisecond); err != nil {
			t.Error(err)
		}
	}
	cancel()
	wg.Wait()
}
