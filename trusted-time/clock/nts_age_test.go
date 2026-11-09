//go:build nts

package clock

import (
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/trusted-time/nts"
)

// simNTS is an NTS clock on a fake local clock, with servers whose samples
// the test sets. The samples agree on one offset.
type simNTS struct {
	n      *NTS
	local  int64
	offset int64
}

func newSimNTS(ops ...string) *simNTS {
	s := &simNTS{local: int64(time.Hour)}
	s.offset = time.Now().UnixNano() - s.local
	s.n = &NTS{Coarse: &coarseClock{}, Local: func() int64 { return s.local }}
	for _, op := range ops {
		s.n.Servers = append(s.n.Servers, NTSServer{Host: op + ".test", Operator: op})
	}
	s.n.init()
	return s
}

// answer gives peer i a sample taken at local time t4.
func (s *simNTS) answer(i int, t4 int64) {
	s.n.peers[i].sample = &nts.Sample{Offset: s.offset, Bound: 5 * time.Millisecond, T4: t4}
}

// combine forms a quorum at the current local time, as at the end of a
// Refresh that read the coarse clock at start.
func (s *simNTS) combine(start int64) error {
	return s.n.combine(time.Unix(0, start+s.offset), start)
}

// A sample joins a quorum only if it stays under MaxAge until the next
// quorum can replace it: a tick of Run plus the longest Refresh.
func TestNTSClockJoinAgeBoundary(t *testing.T) {
	if got, want := (&NTS{}).joinAge(), 46*time.Second; got != want {
		t.Fatalf("join age %v, want %v (60 s - 4 s tick - 2 x 5 s exchange)", got, want)
	}
	for _, c := range []struct {
		age  time.Duration
		join bool
	}{{46 * time.Second, true}, {46*time.Second + 1, false}} {
		s := newSimNTS("a", "b", "c", "old")
		for i := range 3 {
			s.answer(i, s.local)
		}
		s.answer(3, s.local-int64(c.age))
		if err := s.combine(s.local); err != nil {
			t.Fatal(err)
		}
		members := s.n.Status().Members
		if slices.Contains(members, "old") != c.join {
			t.Fatalf("sample %v old: members %v, want it in: %v", c.age, members, c.join)
		}
		if !c.join {
			continue
		}
		// The quorum serves until the next one can come: a tick and a
		// Refresh of one NTS-KE and one query.
		s.local += int64(NTSInterval/4 + 2*ntsExchangeTimeout)
		if _, err := s.n.Now(); err != nil {
			t.Fatalf("at the latest next quorum: %v", err)
		}
		s.local++
		if _, err := s.n.Now(); err == nil {
			t.Fatal("served past MaxAge")
		}
	}
}

// A MaxAge no longer than a tick and the longest Refresh would let no
// sample join: Refresh refuses it before it contacts any server.
func TestNTSClockRefusesMaxAgeTooShort(t *testing.T) {
	fs := newServers(t, nil, "a", "b", "c")
	n := newNTS(fs, &coarseClock{})
	n.Interval, n.MaxAge = NTSInterval, 14*time.Second
	if err := refresh(t, n); err == nil || !strings.Contains(err.Error(), "MaxAge 14s is too short") ||
		!strings.Contains(err.Error(), "over 14s") {
		t.Fatalf("MaxAge 14 s: %v", err)
	}
	for _, f := range fs {
		if f.ke.Sessions.Load() != 0 {
			t.Fatal("contacted a server with a MaxAge it cannot serve")
		}
	}
	if _, err := n.Now(); err == nil || !strings.Contains(err.Error(), "too short") {
		t.Fatalf("Now: %v", err)
	}
	// 1 ns over the minimum is accepted.
	n.MaxAge = 14*time.Second + 1
	if err := refresh(t, n); err != nil && strings.Contains(err.Error(), "too short") {
		t.Fatalf("MaxAge just over the minimum: %v", err)
	}
}

// One operator loses half its answers, the others answer every time. The
// test runs Run's schedule on a fake clock for a day: a tick every Interval/4
// (a tick that comes during a Refresh starts the next one when it ends),
// each server asked when due, an answer after a round trip of 10 to 200 ms,
// a lost one after the query timeout. Now must not fail once the first
// quorum is in force.
func TestNTSClockLossyServerKeepsNowServing(t *testing.T) {
	s := newSimNTS("a", "b", "c", "lossy")
	n := s.n
	rng := rand.New(rand.NewPCG(1, 2))
	tick := int64(n.interval() / 4)
	base := s.local
	nextTickAfter := func(x int64) int64 { return base + ((x-base)/tick+1)*tick }
	served := false
	var fails, quorums, withLossy int
	// advance moves the fake clock to `to` in 100 ms steps and calls Now at each.
	advance := func(to int64) {
		for s.local < to {
			s.local = min(s.local+int64(100*time.Millisecond), to)
			if _, err := n.Now(); served && err != nil {
				if fails == 0 {
					t.Logf("first failure at %v: %v", time.Duration(s.local-base), err)
				}
				fails++
			}
		}
	}
	start := s.local
	for end := s.local + int64(24*time.Hour); start < end; {
		// The polls of this Refresh run in parallel; it ends with the slowest.
		type answer struct {
			i    int
			at   int64
			lost bool
		}
		var answers []answer
		refreshEnd := start
		for i, p := range n.peers {
			if start < p.nextPoll {
				continue
			}
			a := answer{i: i, at: start + int64(10*time.Millisecond) + rng.Int64N(int64(190*time.Millisecond))}
			if p.srv.Operator == "lossy" && rng.IntN(2) == 0 {
				a.at, a.lost = start+int64(ntsExchangeTimeout), true
			}
			answers = append(answers, a)
			refreshEnd = max(refreshEnd, a.at)
		}
		advance(refreshEnd)
		for _, a := range answers {
			if !a.lost {
				s.answer(a.i, a.at)
			}
			n.peers[a.i].nextPoll = a.at + int64(n.peers[a.i].poll)
		}
		if err := s.combine(start); err == nil {
			served = true
			quorums++
			if slices.Contains(n.result.members, "lossy") {
				withLossy++
			}
		}
		next := nextTickAfter(start)
		if next <= refreshEnd {
			next = refreshEnd
		}
		advance(next)
		start = next
	}
	t.Logf("%d quorums, %d with the lossy server; Now failed %d times", quorums, withLossy, fails)
	if fails > 0 {
		t.Fatalf("Now failed %d times with one server losing half its answers", fails)
	}
	if withLossy == 0 || withLossy == quorums {
		t.Fatalf("the lossy server was in %d of %d quorums: the test does not reach the age limit", withLossy, quorums)
	}
}
