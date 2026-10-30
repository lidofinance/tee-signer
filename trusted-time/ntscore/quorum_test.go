//go:build nts

package ntscore

import (
	"math"
	"sort"
	"strings"
	"testing"
	"time"
)

// The tests of the Rust core's quorum.rs, before the port. iv is one server's
// interval in milliseconds, measured at T4 = 0.

const qms = int64(time.Millisecond)

func iv(op string, offsetMS, boundMS int64) Interval {
	return Interval{Operator: op, Offset: offsetMS * qms, Bound: time.Duration(boundMS * qms)}
}

func quorumRefused(t *testing.T, in []Interval, now int64, want string) {
	t.Helper()
	q, err := Quorum(in, now)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("Quorum(%d intervals, now %d) = %+v, %v; want a quorum error with %q", len(in), now, q, err, want)
	}
}

func TestQuorumThreeThatAgree(t *testing.T) {
	// [90, 110], [95, 125], [100, 104]: two or more cover [95, 110].
	q, err := Quorum([]Interval{iv("a", 100, 10), iv("b", 110, 15), iv("c", 102, 2)}, 0)
	if err != nil || q.Lo != 95*qms || q.Hi != 110*qms || q.Offset != 102_500_000 || q.Bound != 7_500_000 {
		t.Fatalf("%+v %v", q, err)
	}
}

func TestQuorumOneLiarCannotMoveTheResultOutsideTheHonestIntervals(t *testing.T) {
	for _, liar := range []int64{-1_000_000, -50, 0, 99, 101, 150, 1_000_000} {
		q, err := Quorum([]Interval{iv("a", 100, 5), iv("b", 101, 5), iv("liar", liar, 1)}, 0)
		if err != nil {
			t.Fatalf("liar %d: %v", liar, err)
		}
		// The real offset is in both honest intervals: [96, 105].
		for _, real := range []int64{96 * qms, 100 * qms, 105 * qms} {
			if d := q.Offset - real; d > int64(q.Bound) || -d > int64(q.Bound) {
				t.Fatalf("liar %d real %d: %+v", liar, real, q)
			}
		}
	}
}

func TestQuorumTwoLiarsThatAgreeWithNobodyGiveNoAnswer(t *testing.T) {
	quorumRefused(t, []Interval{iv("a", 0, 1), iv("b", 100, 1), iv("c", 200, 1)}, 0, "disagree")
}

func TestQuorumFourServers(t *testing.T) {
	// [95, 105], [98, 102], [99, 101], [500, 502]: three cover [99, 101].
	// The simpler rule (the (F+1)-th smallest lower end, the (F+1)-th
	// largest upper end) would give [98, 105].
	q, err := Quorum([]Interval{iv("a", 100, 5), iv("b", 100, 2), iv("c", 100, 1), iv("d", 501, 1)}, 0)
	if err != nil || q.Lo != 99*qms || q.Hi != 101*qms {
		t.Fatalf("%+v %v", q, err)
	}
}

func TestQuorumTouchingIntervalsOverlap(t *testing.T) {
	// [0, 2], [2, 4], [10, 12]: the point 2 is in two.
	q, err := Quorum([]Interval{iv("a", 1, 1), iv("b", 3, 1), iv("c", 11, 1)}, 0)
	if err != nil || q.Lo != 2*qms || q.Hi != 2*qms || q.Bound != 0 {
		t.Fatalf("%+v %v", q, err)
	}
}

// Against the definition, on random intervals: Lo and Hi are covered by
// n - F intervals, nothing outside [Lo, Hi] is, and [Lo, Hi] lies inside
// the simpler rule's interval ((F+1)-th smallest lower end, (F+1)-th
// largest upper end).
func TestQuorumRandomIntervalsMatchTheDefinition(t *testing.T) {
	names := []string{"a", "b", "c", "d", "e", "f", "g"}
	x := uint64(0x2545_f491_4f6c_dd1d)
	next := func(m uint64) int64 {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		return int64(x % m)
	}
	agreed, refused := 0, 0
	for i := 0; i < 20_000; i++ {
		n := 3 + int(next(5))
		v := make([]Interval, n)
		for j := range v {
			v[j] = iv(names[j], next(200), next(40))
		}
		need := n - F
		cover := func(p int64) int {
			c := 0
			for _, s := range v {
				if s.Offset-int64(s.Bound) <= p && p <= s.Offset+int64(s.Bound) {
					c++
				}
			}
			return c
		}
		var points, covered, lows, highs []int64
		for _, s := range v {
			points = append(points, s.Offset-int64(s.Bound), s.Offset+int64(s.Bound))
			lows = append(lows, s.Offset-int64(s.Bound))
			highs = append(highs, s.Offset+int64(s.Bound))
		}
		sort.Slice(points, func(a, b int) bool { return points[a] < points[b] })
		for _, p := range points {
			if cover(p) >= need {
				covered = append(covered, p)
			}
		}
		q, err := Quorum(v, 0)
		if err != nil {
			refused++
			if !strings.Contains(err.Error(), "disagree") || len(covered) != 0 {
				t.Fatalf("round %d: %v with %d covered points", i, err, len(covered))
			}
			continue
		}
		agreed++
		if len(covered) == 0 || covered[0] != q.Lo || covered[len(covered)-1] != q.Hi {
			t.Fatalf("round %d: %+v, covered %v", i, q, covered)
		}
		sort.Slice(lows, func(a, b int) bool { return lows[a] < lows[b] })
		sort.Slice(highs, func(a, b int) bool { return highs[a] > highs[b] })
		if lows[F] > q.Lo || q.Hi > highs[F] {
			t.Fatalf("round %d: %+v outside the simpler rule's [%d, %d]", i, q, lows[F], highs[F])
		}
		if q.Offset-int64(q.Bound) > q.Lo || q.Hi > q.Offset+int64(q.Bound) {
			t.Fatalf("round %d: Offset +- Bound does not cover [Lo, Hi]: %+v", i, q)
		}
	}
	if agreed <= 1000 || refused <= 1000 {
		t.Fatalf("%d agreed, %d refused", agreed, refused)
	}
}

func TestQuorumBoundsAgeByRho(t *testing.T) {
	// 10 s old: each bound grows by 500 ppm of 10 s = 5 ms.
	s := []Interval{iv("a", 100, 1), iv("b", 100, 1), iv("c", 100, 1)}
	q, err := Quorum(s, 10_000*qms)
	if err != nil || q.Bound != 6*time.Millisecond {
		t.Fatalf("%+v %v", q, err)
	}
	quorumRefused(t, s, -1, "after the quorum time")
}

func TestQuorumRefusals(t *testing.T) {
	quorumRefused(t, []Interval{iv("a", 0, 1), iv("b", 0, 1)}, 0, "fewer than 3 servers")
	quorumRefused(t, []Interval{iv("a", 0, 1), iv("b", 0, 1), iv("a", 0, 1)}, 0, "two servers of one operator")
	quorumRefused(t, []Interval{iv("a", 0, 1), iv("b", 0, 1), iv("", 0, 1)}, 0, "operator label empty or over 32 octets")
	long := "123456789012345678901234567890123"
	if len(long) != MaxOperatorLen+1 {
		t.Fatal(len(long))
	}
	quorumRefused(t, []Interval{iv("a", 0, 1), iv("b", 0, 1), iv(long, 0, 1)}, 0, "operator label empty or over 32 octets")
	quorumRefused(t, []Interval{iv("a", 0, 1), iv("b", 0, 1), iv("c", 0, -1)}, 0, "negative error bound")
	var many []Interval
	for _, n := range strings.Split("a b c d e f g h i j k l m n o p q", " ") {
		many = append(many, iv(n, 0, 1))
	}
	if len(many) != MaxServers+1 {
		t.Fatal(len(many))
	}
	quorumRefused(t, many, 0, "more than 16 servers")
	if _, err := Quorum(many[:MaxServers], 0); err != nil {
		t.Fatalf("%d servers: %v", MaxServers, err)
	}
}

func TestQuorumExtremeValuesDoNotPanic(t *testing.T) {
	x := func(op string, o int64, b time.Duration, t4 int64) Interval {
		return Interval{Operator: op, Offset: o, Bound: b, T4: t4}
	}
	for _, o := range []int64{math.MinInt64, 0, math.MaxInt64} {
		for _, b := range []time.Duration{0, math.MaxInt64} {
			for _, tn := range [][2]int64{{math.MinInt64, math.MaxInt64}, {0, 0}, {math.MaxInt64, math.MaxInt64}} {
				_, _ = Quorum([]Interval{x("a", o, b, tn[0]), x("b", o, b, tn[0]), x("c", o, b, tn[0])}, tn[1])
			}
		}
	}
}

// FuzzQuorum is the one-liar property on three servers: two honest
// intervals hold the real offset at their T4, and so at now once their
// bounds have aged by rho; the third says anything, anywhere in time. The
// quorum must answer, [Lo, Hi] must hold the real offset, Offset +- Bound
// must cover it, and [Lo, Hi] must stay inside the union of the two honest
// intervals: the liar cannot move the answer outside them. Every input
// stays under 2^61, so no refusal for an int64 overflow is possible.
//
//	go test -tags nts -run - -fuzz=FuzzQuorum ./nts
func FuzzQuorum(f *testing.F) {
	f.Add(int64(100*qms), int64(5*qms), int64(0), int64(5*qms), int64(qms), int64(-50*qms), int64(qms), uint32(0), uint32(0), uint32(0), uint8(2))
	f.Add(int64(0), int64(0), int64(0), int64(0), int64(0), int64(1)<<60, int64(1)<<60, uint32(10_000), uint32(0), uint32(math.MaxUint32), uint8(0))
	f.Add(int64(-1)<<60, int64(7), int64(-7), int64(1)<<59, int64(1)<<58, int64(-1)<<60, int64(0), uint32(math.MaxUint32), uint32(math.MaxUint32), uint32(0), uint8(1))
	f.Fuzz(func(t *testing.T, real, ba, ea, bb, eb, liar, bl int64, ageA, ageB, ageL uint32, pos uint8) {
		const lim = int64(1) << 61
		clamp := func(v int64) int64 { return v % lim } // keeps the sign: (-lim, lim)
		abs := func(v int64) int64 {
			if v < 0 {
				return -v
			}
			return v
		}
		within := func(e, b int64) int64 { // [-b, b]
			if b == 0 {
				return 0
			}
			return e % (b + 1)
		}
		real = clamp(real)
		ba, bb, bl = abs(clamp(ba)), abs(clamp(bb)), abs(clamp(bl))
		ea, eb = within(ea, ba), within(eb, bb)
		const now = int64(1) << 40
		honest := func(op string, e, b int64, age uint32) Interval {
			return Interval{Operator: op, Offset: real + e, Bound: time.Duration(b), T4: now - int64(age)}
		}
		a, b := honest("a", ea, ba, ageA), honest("b", eb, bb, ageB)
		l := Interval{Operator: "liar", Offset: clamp(liar), Bound: time.Duration(bl), T4: now - int64(ageL)}
		var in []Interval
		switch pos % 3 {
		case 0:
			in = []Interval{l, a, b}
		case 1:
			in = []Interval{a, l, b}
		default:
			in = []Interval{a, b, l}
		}
		q, err := Quorum(in, now)
		if err != nil {
			t.Fatalf("refused: %v", err)
		}
		if q.Lo > real || real > q.Hi {
			t.Fatalf("real %d outside [%d, %d]: %+v", real, q.Lo, q.Hi, q)
		}
		if d := q.Offset - real; d > int64(q.Bound) || -d > int64(q.Bound) {
			t.Fatalf("real %d outside Offset +- Bound: %+v", real, q)
		}
		aged := func(s Interval) (lo, hi int64) {
			b := int64(s.Bound) + int64(Drift(time.Duration(now-s.T4)))
			return s.Offset - b, s.Offset + b
		}
		loA, hiA := aged(a)
		loB, hiB := aged(b)
		if q.Lo < min(loA, loB) || q.Hi > max(hiA, hiB) {
			t.Fatalf("[%d, %d] outside the honest intervals [%d, %d] and [%d, %d]", q.Lo, q.Hi, loA, hiA, loB, hiB)
		}
	})
}
