//go:build nts

package clock

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/trusted-time/nts"
)

// swapServers is the server list of the named operators, as newFollowNTS
// builds it.
func swapServers(ops ...string) []NTSServer {
	out := make([]NTSServer, len(ops))
	for i, op := range ops {
		out[i] = NTSServer{Host: op + ".test", Operator: op}
	}
	return out
}

func opNames(c int) []string {
	out := make([]string, c)
	for i := range out {
		out[i] = fmt.Sprintf("op%d", i)
	}
	return out
}

// runSwapWorld ticks w and n from second from to second to, calls at(sec)
// at the start of each tick before its Refresh, and returns the seconds
// Now failed.
func runSwapWorld(w *shiftWorld, n *NTS, from, to time.Duration, at func(sec time.Duration)) int {
	blocked := 0
	for sec := from; sec < to; sec += time.Second {
		if sec%testTick == 0 {
			w.at(sec)
			if at != nil {
				at(sec)
			}
			_ = n.Refresh(context.Background())
		}
		if _, err := n.Now(); err != nil && sec > 0 {
			blocked++
		}
	}
	return blocked
}

func contactsSince(w *shiftWorld, op string, from time.Duration) []int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []int64
	for _, c := range w.contacts[op] {
		if c >= int64(shiftBase+from) {
			out = append(out, c)
		}
	}
	return out
}

// A swap on a healthy clock keeps the quorum: no second without time, the
// 60 s minimum gap holds across it, kept operators keep their peer, a
// removed active gets no contact after it, and an added operator is asked
// at the next tick. 7 to 8 servers starts the handover with 5 actives, 8 to
// 7 drops to 4, 6 to 7 moves from all active to shifts.
func TestNTSSwapKeepsQuorum(t *testing.T) {
	const swapAt = 20 * time.Minute
	for _, tc := range []struct{ from, to int }{{7, 8}, {8, 7}, {6, 7}, {8, 9}} {
		for seed := uint64(1); seed <= 3; seed++ {
			name := fmt.Sprintf("%d to %d, seed %d", tc.from, tc.to, seed)
			w := newFollowWorld(seed)
			n := newFollowNTS(w, tc.from, fmt.Appendf(nil, "swap-%d", seed))
			ops := opNames(tc.from)
			var removed, added string
			next := slices.Clone(ops)
			before := map[string]*ntsPeer{}
			blocked := runSwapWorld(w, n, 0, 40*time.Minute, func(sec time.Duration) {
				if sec != swapAt {
					return
				}
				if tc.to < tc.from {
					// Remove an active of the moment: the case that costs
					// a slot.
					removed = n.NTSSummary().Actives[0]
					next = slices.DeleteFunc(next, func(op string) bool { return op == removed })
				} else {
					added = fmt.Sprintf("op%d", tc.from)
					next = append(next, added)
				}
				for _, p := range n.peers {
					before[p.srv.Operator] = p
				}
				if err := n.SetServers(swapServers(next...), 0); err != nil {
					t.Fatalf("%s: %v", name, err)
				}
			})
			if blocked != 0 {
				t.Errorf("%s: blocked %d s", name, blocked)
			}
			if g, op := gapsOf(w); g < NTSShiftMinGap {
				t.Errorf("%s: %s contacted twice %v apart", name, op, g)
			}
			s := n.NTSSummary()
			if len(s.Peers) != tc.to || len(s.Actives) != ShiftActives(tc.to) || s.ServerSwaps != 1 {
				t.Errorf("%s: %d peers, actives %v, %d swaps", name, len(s.Peers), s.Actives, s.ServerSwaps)
			}
			for _, p := range n.peers {
				if old, ok := before[p.srv.Operator]; ok && old != p {
					t.Errorf("%s: %s got a new peer", name, p.srv.Operator)
				}
			}
			if removed != "" {
				if c := contactsSince(w, removed, swapAt); len(c) != 0 {
					t.Errorf("%s: removed %s contacted %d times after the swap", name, removed, len(c))
				}
				if slices.Contains(s.Members, removed) || n.Source() != "nts("+strings.Join(next, ",")+")" {
					t.Errorf("%s: members %v, source %s", name, s.Members, n.Source())
				}
			}
			if added != "" {
				c := contactsSince(w, added, swapAt)
				if len(c) == 0 || c[0] != int64(shiftBase+swapAt) {
					t.Errorf("%s: added %s first asked at %v", name, added, c)
				}
			}
			t.Logf("%s: actives %v", name, s.Actives)
		}
	}
}

// Without a seed every operator stays active after a swap.
func TestNTSSwapNoSeed(t *testing.T) {
	w := newFollowWorld(10)
	n := newFollowNTS(w, 8, nil)
	blocked := runSwapWorld(w, n, 0, 10*time.Minute, func(sec time.Duration) {
		if sec == 5*time.Minute {
			if err := n.SetServers(swapServers(opNames(6)...), 0); err != nil {
				t.Fatal(err)
			}
		}
	})
	if g, op := gapsOf(w); g < NTSShiftMinGap {
		t.Fatalf("%s contacted twice %v apart", op, g)
	}
	if s := n.NTSSummary(); blocked != 0 || len(s.Actives) != 6 {
		t.Fatalf("blocked %d s, actives %v", blocked, s.Actives)
	}
}

// A Refresh in flight finishes on the old list: SetServers waits for it,
// and the next Refresh asks the new operator.
func TestNTSSwapWaitsForRefresh(t *testing.T) {
	w := newFollowWorld(11)
	release := make(chan struct{})
	var mu sync.Mutex
	var asked []string
	n := &NTS{Coarse: w, Local: w.local, StartDelay: -1, Servers: swapServers(opNames(4)...)}
	n.testQuery = func(ctx context.Context, op string, at int64) (nts.Sample, error) {
		mu.Lock()
		asked = append(asked, op)
		mu.Unlock()
		if op == "op0" {
			<-release
		}
		return w.query(op, at)
	}
	ctx := context.Background()
	w.at(0)
	refreshed := make(chan error, 1)
	go func() { refreshed <- n.Refresh(ctx) }()
	// Wait until the Refresh is in flight: op0 is asked and blocks.
	for {
		mu.Lock()
		in := slices.Contains(asked, "op0")
		mu.Unlock()
		if in {
			break
		}
		time.Sleep(time.Millisecond)
	}
	swapped := make(chan error, 1)
	go func() { swapped <- n.SetServers(swapServers("op0", "op1", "op2", "op4"), 0) }()
	select {
	case <-swapped:
		t.Fatal("SetServers returned while a Refresh was in flight")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-refreshed; err != nil {
		t.Fatal(err)
	}
	if err := <-swapped; err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if slices.Contains(asked, "op4") || !slices.Contains(asked, "op3") {
		t.Fatalf("the Refresh in flight asked %v", asked)
	}
	asked = nil
	mu.Unlock()
	w.at(testTick)
	_ = n.Refresh(ctx)
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(asked, []string{"op4"}) {
		t.Fatalf("the next Refresh asked %v, want op4", asked)
	}
}

// An operator removed and added back within its gap keeps its last
// contact: it is not asked again sooner than 60 s after it.
func TestNTSSwapMinGapAcrossRemoveAndAdd(t *testing.T) {
	w := newFollowWorld(4)
	n := newFollowNTS(w, 8, []byte("swap-back"))
	all := opNames(8)
	var gone string
	blocked := runSwapWorld(w, n, 0, 30*time.Minute, func(sec time.Duration) {
		switch sec {
		case 10 * time.Minute:
			gone = n.NTSSummary().Actives[0]
			if err := n.SetServers(swapServers(slices.DeleteFunc(slices.Clone(all), func(op string) bool { return op == gone })...), 7); err != nil {
				t.Fatal(err)
			}
		case 10*time.Minute + 2*testTick:
			if err := n.SetServers(swapServers(all...), 0); err != nil {
				t.Fatal(err)
			}
		}
	})
	if g, op := gapsOf(w); g < NTSShiftMinGap {
		t.Fatalf("%s contacted twice %v apart", op, g)
	}
	if blocked != 0 || n.NTSSummary().ServerSwaps != 2 {
		t.Fatalf("blocked %d s, %d swaps", blocked, n.NTSSummary().ServerSwaps)
	}
	if c := contactsSince(w, gone, 10*time.Minute); len(c) == 0 {
		t.Fatalf("%s never asked after it came back", gone)
	}
}

// A removed liar leaves the quorum at the swap, not at the next tick: the
// quorum forms again from the samples left, and the time stays served.
func TestNTSSwapRemovedLiarLeavesQuorum(t *testing.T) {
	w := newFollowWorld(5)
	n := newFollowNTS(w, 8, []byte("swap-liar"))
	if b := runSwapWorld(w, n, 0, 10*time.Minute, nil); b != 0 {
		t.Fatalf("blocked %d s before the liar", b)
	}
	// The newest active stays the longest; it lies from now on.
	acts := n.NTSSummary().Actives
	liar := acts[len(acts)-1]
	w.mu.Lock()
	w.wrong[liar] = 40 * time.Millisecond
	w.mu.Unlock()
	if b := runSwapWorld(w, n, 10*time.Minute, 12*time.Minute, nil); b != 0 {
		t.Fatalf("blocked %d s before the swap", b)
	}
	if !slices.Contains(n.NTSSummary().Members, liar) {
		t.Fatalf("liar %s not in the quorum %v", liar, n.NTSSummary().Members)
	}
	rest := slices.DeleteFunc(opNames(8), func(op string) bool { return op == liar })
	if err := n.SetServers(swapServers(rest...), 0); err != nil {
		t.Fatal(err)
	}
	s := n.NTSSummary()
	if slices.Contains(s.Members, liar) || !s.Quorum {
		t.Fatalf("after the swap: members %v, quorum %v (%s)", s.Members, s.Quorum, s.Refused)
	}
	if _, ok := n.Status().Peers[liar]; ok {
		t.Fatalf("liar %s still has a peer", liar)
	}
}

// A refused swap changes nothing: too few servers (under 4, or under the
// caller's minimum), an operator named twice, an empty operator.
func TestNTSSwapRefusal(t *testing.T) {
	w := newFollowWorld(6)
	n := newFollowNTS(w, 8, []byte("swap-refuse"))
	runSwapWorld(w, n, 0, 5*time.Minute, nil)
	peers := slices.Clone(n.peers)
	servers := slices.Clone(n.Servers)
	sum := n.NTSSummary()
	order := slices.Clone(n.shifts.order)
	dup := swapServers(opNames(7)...)
	dup = append(dup, NTSServer{Host: "other.test", Operator: "op0"})
	noOp := swapServers(opNames(7)...)
	noOp[3].Operator = ""
	for name, tc := range map[string]struct {
		servers []NTSServer
		min     int
	}{
		"3 servers":        {swapServers(opNames(3)...), 0},
		"3 servers, min 2": {swapServers(opNames(3)...), 2},
		"6 under min 7":    {swapServers(opNames(6)...), 7},
		"operator twice":   {dup, 0},
		"no operator":      {noOp, 0},
		"none":             {nil, 0},
	} {
		if err := n.SetServers(tc.servers, tc.min); err == nil {
			t.Errorf("%s: taken", name)
		} else {
			t.Logf("%s: %v", name, err)
		}
	}
	after := n.NTSSummary()
	if !slices.Equal(n.peers, peers) || !slices.EqualFunc(n.Servers, servers, func(a, b NTSServer) bool { return a == b }) ||
		!slices.Equal(n.shifts.order, order) || after.ServerSwaps != 0 || !slices.Equal(after.Actives, sum.Actives) {
		t.Fatalf("a refused swap changed the clock: swaps %d, actives %v before %v", after.ServerSwaps, after.Actives, sum.Actives)
	}
}

// A changed host is a new server: the operator gets a new peer.
func TestNTSSwapChangedHostIsNewPeer(t *testing.T) {
	w := newFollowWorld(7)
	n := newFollowNTS(w, 8, []byte("swap-host"))
	runSwapWorld(w, n, 0, 3*time.Minute, nil)
	old := n.peers[2]
	list := swapServers(opNames(8)...)
	list[2].Host = "moved.test"
	if err := n.SetServers(list, 0); err != nil {
		t.Fatal(err)
	}
	if n.peers[2] == old || n.peers[2].sample != nil || n.peers[1] == nil || n.Status().Peers["op2"].Host != "moved.test" {
		t.Fatal("op2 kept its peer after a host change")
	}
	if g, op := gapsOf(w); g < NTSShiftMinGap {
		t.Fatalf("%s contacted twice %v apart", op, g)
	}
}

// Without shifts a swap works the same way: a new operator is asked at the
// next Refresh, a removed one leaves the quorum at once.
func TestNTSSwapWithoutShifts(t *testing.T) {
	w := newFollowWorld(8)
	n := &NTS{Coarse: w, Local: w.local, StartDelay: -1, testQuery: w.queryCtx, Servers: swapServers(opNames(5)...)}
	w.wrong["op4"] = 40 * time.Millisecond
	ctx := context.Background()
	for sec := time.Duration(0); sec < 2*time.Minute; sec += testTick {
		w.at(sec)
		_ = n.Refresh(ctx)
	}
	if !slices.Contains(n.NTSSummary().Members, "op4") {
		t.Fatalf("members %v", n.NTSSummary().Members)
	}
	if err := n.SetServers(swapServers("op0", "op1", "op2", "op3", "op5"), 0); err != nil {
		t.Fatal(err)
	}
	if m := n.NTSSummary().Members; slices.Contains(m, "op4") {
		t.Fatalf("members after the swap %v", m)
	}
	w.at(2 * time.Minute)
	if err := n.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if m := n.NTSSummary().Members; !slices.Contains(m, "op5") || len(m) != 5 {
		t.Fatalf("members after the next Refresh %v", m)
	}
}

// SetServers, Refresh, Now, NTSSummary, Status and Source in parallel; run
// with -race.
func TestNTSSwapConcurrent(t *testing.T) {
	w := newFollowWorld(9)
	n := newFollowNTS(w, 8, []byte("swap-race"))
	ctx := context.Background()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer close(stop)
		for sec := time.Duration(0); sec < 3*time.Hour; sec += testTick {
			w.at(sec)
			_ = n.Refresh(ctx)
		}
	}()
	go func() {
		defer wg.Done()
		lists := [][]NTSServer{swapServers(opNames(7)...), swapServers(opNames(8)...), swapServers(opNames(9)...)}
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if err := n.SetServers(lists[i%len(lists)], 0); err != nil {
				t.Error(err)
				return
			}
			_, _ = n.Now()
			_ = n.NTSSummary()
			_ = n.Status()
			_ = n.Source()
		}
	}()
	wg.Wait()
	if g, op := gapsOf(w); g < NTSShiftMinGap {
		t.Fatalf("%s contacted twice %v apart", op, g)
	}
	t.Logf("%d swaps", n.NTSSummary().ServerSwaps)
}
