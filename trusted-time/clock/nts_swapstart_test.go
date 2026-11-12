//go:build nts

package clock

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"slices"
	"sync"
	"testing"
	"time"
)

// swapStartCounts sums the schedule's fallbacks and retries, and its burst
// contacts, over all operators.
func swapStartCounts(n *NTS) (fallbacks, bursts int64) {
	for _, c := range n.NTSSummary().Operators {
		fallbacks += c.Fallbacks + c.Retries
		bursts += c.Bursts
	}
	return fallbacks, bursts
}

// A swap that cannot form the quorum again, on a host that then drops every
// answer: the start state ends after the start wait. Until then an operator
// the swap added gets the 20 s start retries. After it no operator is asked
// twice within 60 s but for the counted retry of a lost answer, fallbacks
// and bursts stay under their caps, and Now fails the whole time. Once
// answers come back a quorum forms.
func TestNTSSwapStartStateEndsAfterStartWait(t *testing.T) {
	for _, wait := range []time.Duration{0, 40 * time.Second} {
		w := newFollowWorld(31)
		n := newFollowNTS(w, 8, []byte("swap-start-wait"))
		n.StartWait = wait
		want := cmpOr(wait, NTSStartWait)
		// The host drops every answer from 88 s before the swap, so no
		// sample is fresh enough to join a quorum when the swap comes.
		const dropAt = 3 * time.Minute
		const swapAt = dropAt + 88*time.Second
		runSwapWorld(w, n, 0, dropAt, nil)
		if !n.served.Load() || !n.shifts.warm {
			t.Fatal("setup: no quorum")
		}
		gone := n.NTSSummary().Members[0]
		for _, op := range append(opNames(8), "op8", "op9") {
			w.down[op] = true
		}
		runSwapWorld(w, n, dropAt, swapAt, nil)
		// Take out a member and two more, and add two new operators.
		next := slices.DeleteFunc(opNames(8), func(op string) bool { return op == gone })
		next = append(next[2:], "op8", "op9")
		w.at(swapAt)
		if err := n.SetServers(swapServers(next...), 0); err != nil {
			t.Fatal(err)
		}
		if n.served.Load() || n.shifts.warm {
			t.Fatal("the failed swap left the clock out of its start state")
		}
		// The start wait: still the start state, with start retries.
		end := swapAt + want
		blocked := runSwapWorld(w, n, swapAt, end, nil)
		if n.served.Load() || n.shifts.warm {
			t.Fatalf("wait %v: the start state ended before the start wait", want)
		}
		early := contactsSince(w, "op8", swapAt)
		short := 0
		for i := 1; i < len(early); i++ {
			if d := time.Duration(early[i] - early[i-1]); d < NTSShiftStartRetry {
				t.Fatalf("wait %v: op8 asked twice within %v (%v)", want, NTSShiftStartRetry, d)
			} else if d < NTSShiftMinGap {
				short++
			}
		}
		if short == 0 {
			t.Fatalf("wait %v: op8 got no start retry in the start wait: contacts %v", want, early)
		}
		// One tick past the wait the start state is over.
		from := end + testTick
		blocked += runSwapWorld(w, n, end, from, nil)
		if !n.served.Load() || !n.shifts.warm {
			t.Fatalf("wait %v: still in the start state %v after the swap: served %v, warm %v", want, from-swapAt, n.served.Load(), n.shifts.warm)
		}
		// The next hour runs on the normal schedule.
		f0, b0 := swapStartCounts(n)
		retries0 := n.NTSSummary().Operators
		to := from + time.Hour
		blocked += runSwapWorld(w, n, from, to, nil)
		f1, b1 := swapStartCounts(n)
		if f1-f0 > NTSShiftFallbackCap || b1-b0 > NTSShiftBurstCap {
			t.Fatalf("wait %v: %d fallbacks and retries, %d burst contacts in an hour, caps %d and %d", want, f1-f0, b1-b0, NTSShiftFallbackCap, NTSShiftBurstCap)
		}
		total := 0
		for _, op := range next {
			cs := contactsSince(w, op, from)
			total += len(cs)
			short := int64(0)
			for i := 1; i < len(cs); i++ {
				if time.Duration(cs[i]-cs[i-1]) < NTSShiftMinGap {
					short++
				}
			}
			// A retry comes 20 s after a lost answer and the next slot 40 s
			// after the retry: two short gaps per retry, and no others.
			retries := n.NTSSummary().Operators[op].Retries - retries0[op].Retries
			if short > 2*retries {
				t.Fatalf("wait %v: %s asked %d times within %v of its last contact after the start wait, with %d retries of a lost answer",
					want, op, short, NTSShiftMinGap, retries)
			}
		}
		// The grid asks each operator at most once per 60 s; the caps bound
		// the rest.
		if most := len(next)*60 + NTSShiftFallbackCap + NTSShiftBurstCap; total > most {
			t.Fatalf("wait %v: %d contacts in the hour after the start wait, at most %d", want, total, most)
		}
		if secs := int((to - swapAt) / time.Second); blocked != secs {
			t.Fatalf("wait %v: Now failed %d of %d s without a quorum", want, blocked, secs)
		}
		// Answers come back: a quorum forms within the grid's 60 s and a few
		// ticks.
		clear(w.down)
		runSwapWorld(w, n, to, to+90*time.Second, nil)
		if _, err := n.Now(); err != nil || !n.served.Load() || !n.shifts.warm {
			t.Fatalf("wait %v: no quorum after the answers came back: %v", want, err)
		}
		if m := n.NTSSummary().Members; len(m) < 3 || slices.Contains(m, gone) {
			t.Fatalf("wait %v: members %v", want, m)
		}
		t.Logf("wait %v: %d contacts, %d fallbacks and retries, %d burst contacts in the hour after the start wait", want, total, f1-f0, b1-b0)
	}
}

// The same without the shift schedule, with NTS-KE failing after the swap:
// in the start wait NTS-KE is tried every 12 to 20 s, after it it backs
// off up to NTSMaxPoll. Now fails until the servers are back, then a quorum
// forms.
func TestNTSSwapStartStateKeyExchangeBacksOff(t *testing.T) {
	for _, wait := range []time.Duration{0, 40 * time.Second} {
		w := newFollowWorld(32)
		want := cmpOr(wait, NTSStartWait)
		var mu sync.Mutex
		tries := map[string][]int64{}
		roots := x509.NewCertPool()
		servers := func(ops ...string) []NTSServer {
			out := swapServers(ops...)
			for i := range out {
				out[i].KEAddr, out[i].Roots = out[i].Host+":4460", roots
			}
			return out
		}
		n := &NTS{Coarse: w, Local: w.local, StartDelay: -1, StartWait: wait, testQuery: w.queryCtx, randN: seeded(7), Servers: servers(opNames(4)...),
			Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
				mu.Lock()
				defer mu.Unlock()
				tries[addr] = append(tries[addr], w.local())
				return nil, errors.New("refused")
			}}
		ctx := context.Background()
		const swapAt = time.Minute
		for sec := time.Duration(0); sec < swapAt; sec += testTick {
			w.at(sec)
			_ = n.Refresh(ctx)
		}
		if _, err := n.Now(); err != nil {
			t.Fatal(err)
		}
		// One sample is left after the swap: no quorum. From here the
		// servers are reached through NTS-KE, and the dial fails.
		w.at(swapAt)
		if err := n.SetServers(servers("op0", "op4", "op5", "op6"), 0); err != nil {
			t.Fatal(err)
		}
		if n.served.Load() {
			t.Fatal("the failed swap left the clock out of its start state")
		}
		n.testQuery = nil
		// The Refresh at the end of the wait ends the start state.
		end := swapAt + want
		to := end + time.Hour
		for sec := swapAt; sec < to; sec += testTick {
			w.at(sec)
			_ = n.Refresh(ctx)
			if _, err := n.Now(); err == nil {
				t.Fatalf("wait %v: Now served a time %v after the swap, without a quorum", want, sec-swapAt)
			}
			if got := n.served.Load(); got != (sec >= end) {
				t.Fatalf("wait %v: out of the start state %v at %v after the swap", want, got, sec-swapAt)
			}
		}
		for _, op := range []string{"op4", "op5", "op6"} {
			var in, after []int64
			for _, at := range tries[op+".test:4460"] {
				if time.Duration(at) < shiftBase+end {
					in = append(in, at)
				} else {
					after = append(after, at)
				}
			}
			// 12 to 20 s apart on a 4 s tick: at least one try per 24 s.
			if len(in) < int(want/(24*time.Second)) {
				t.Fatalf("wait %v: %s got %d NTS-KE tries in the start wait", want, op, len(in))
			}
			// Doubling from 16 s to 1024 s: 8 tries or so in an hour, against
			// 180 or more without backoff.
			if len(after) > 12 {
				t.Fatalf("wait %v: %s got %d NTS-KE tries in the hour after the start wait, want a backoff", want, op, len(after))
			}
			t.Logf("wait %v: %s got %d NTS-KE tries in the start wait, %d in the hour after", want, op, len(in), len(after))
		}
		n.testQuery = w.queryCtx
		w.at(to)
		if err := n.Refresh(ctx); err != nil {
			t.Fatalf("wait %v: no quorum once the servers are back: %v", want, err)
		}
		if _, err := n.Now(); err != nil {
			t.Fatal(err)
		}
	}
}

// A swap that forms the quorum again does not start the start state, and
// nothing changes when a start wait has passed.
func TestNTSSwapThatKeepsQuorumHasNoStartState(t *testing.T) {
	w := newFollowWorld(33)
	n := newFollowNTS(w, 8, []byte("swap-no-start"))
	const swapAt = 3 * time.Minute
	runSwapWorld(w, n, 0, swapAt, nil)
	gone := n.NTSSummary().Members[0]
	w.at(swapAt)
	if err := n.SetServers(swapServers(slices.DeleteFunc(opNames(8), func(op string) bool { return op == gone })...), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := n.Now(); err != nil || !n.served.Load() || !n.shifts.warm || n.coldUntil != 0 {
		t.Fatalf("after the swap: Now err %v, served %v, warm %v, start state until %d", err, n.served.Load(), n.shifts.warm, n.coldUntil)
	}
	if blocked := runSwapWorld(w, n, swapAt, swapAt+2*NTSStartWait, nil); blocked != 0 || n.coldUntil != 0 {
		t.Fatalf("Now failed %d s after a swap that kept the quorum", blocked)
	}
	if min, op := minGapOf(w); min < NTSShiftMinGap {
		t.Fatalf("%s asked twice within %v", op, min)
	}
}

// A start state that a quorum ends leaves no deadline behind, and a second
// failed swap gets a start wait of its own.
func TestNTSSwapStartStateEndsAtQuorum(t *testing.T) {
	w := newFollowWorld(34)
	n := newFollowNTS(w, 8, []byte("swap-start-quorum"))
	c := &coarseSwitch{w: w}
	n.Coarse = c
	at := 3 * time.Minute
	runSwapWorld(w, n, 0, at, nil)
	for range 2 {
		ops := n.Source()
		gone := n.NTSSummary().Members[0]
		var next []string
		for _, s := range n.Servers {
			if s.Operator != gone {
				next = append(next, s.Operator)
			}
		}
		c.fail.Store(true)
		w.at(at)
		if err := n.SetServers(swapServers(next...), 0); err != nil {
			t.Fatal(err)
		}
		c.fail.Store(false)
		if until := time.Duration(n.coldUntil) - shiftBase; until != at+NTSStartWait || n.served.Load() {
			t.Fatalf("%s without %s: start state until %v, want %v; served %v", ops, gone, until, at+NTSStartWait, n.served.Load())
		}
		runSwapWorld(w, n, at, at+2*time.Minute, nil)
		at += 2 * time.Minute
		if _, err := n.Now(); err != nil || n.coldUntil != 0 || !n.shifts.warm {
			t.Fatalf("after the quorum: Now err %v, start state until %d, warm %v", err, n.coldUntil, n.shifts.warm)
		}
	}
}

// A protocol change puts the clock in the same start state, with the same
// limit.
func TestNTSPolicyStartStateEndsAfterStartWait(t *testing.T) {
	w := newFollowWorld(35)
	n := newFollowNTS(w, 8, []byte("policy-start-wait"))
	const at = 3 * time.Minute
	runSwapWorld(w, n, 0, at, nil)
	w.at(at)
	if err := n.SetPolicy(ProtocolNTP, 100*time.Millisecond, 100*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	for _, op := range opNames(8) {
		w.down[op] = true
	}
	runSwapWorld(w, n, at, at+NTSStartWait, nil)
	if n.served.Load() || n.shifts.warm {
		t.Fatal("the start state ended before the start wait")
	}
	runSwapWorld(w, n, at+NTSStartWait, at+NTSStartWait+testTick, nil)
	if _, err := n.Now(); err == nil || !n.served.Load() || !n.shifts.warm {
		t.Fatalf("after the start wait: Now err %v, served %v, warm %v", err, n.served.Load(), n.shifts.warm)
	}
}
