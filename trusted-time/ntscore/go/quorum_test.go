//go:build nts

package ntscore

import (
	"errors"
	"math"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/devkit/fuzzcheck"
)

// The tests of the Rust core's quorum.rs, before the port. iv is one server's
// interval in milliseconds, measured at T4 = 0.

const qms = int64(time.Millisecond)

// F is the number of wrong servers the tests ported with F = 1 allow: the
// quorum takes it as an argument now (the client's is QuorumWrong).
const F = 1

func iv(op string, offsetMS, boundMS int64) Interval {
	return Interval{Operator: op, Offset: offsetMS * qms, Bound: time.Duration(boundMS * qms)}
}

func quorumRefused(t *testing.T, in []Interval, now int64, want string) {
	t.Helper()
	q, err := Quorum(in, now, 1)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("Quorum(%d intervals, now %d) = %+v, %v; want a quorum error with %q", len(in), now, q, err, want)
	}
}

func TestQuorumThreeThatAgree(t *testing.T) {
	// [90, 110], [95, 125], [100, 104]: two or more cover [95, 110].
	q, err := Quorum([]Interval{iv("a", 100, 10), iv("b", 110, 15), iv("c", 102, 2)}, 0, 1)
	if err != nil || q.Lo != 95*qms || q.Hi != 110*qms || q.Offset != 102_500_000 || q.Bound != 7_500_000 {
		t.Fatalf("%+v %v", q, err)
	}
}

func TestQuorumOneLiarCannotMoveTheResultOutsideTheHonestIntervals(t *testing.T) {
	for _, liar := range []int64{-1_000_000, -50, 0, 99, 101, 150, 1_000_000} {
		q, err := Quorum([]Interval{iv("a", 100, 5), iv("b", 101, 5), iv("liar", liar, 1)}, 0, 1)
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
	q, err := Quorum([]Interval{iv("a", 100, 5), iv("b", 100, 2), iv("c", 100, 1), iv("d", 501, 1)}, 0, 1)
	if err != nil || q.Lo != 99*qms || q.Hi != 101*qms {
		t.Fatalf("%+v %v", q, err)
	}
}

func TestQuorumTouchingIntervalsOverlap(t *testing.T) {
	// [0, 2], [2, 4], [10, 12]: the point 2 is in two.
	q, err := Quorum([]Interval{iv("a", 1, 1), iv("b", 3, 1), iv("c", 11, 1)}, 0, 1)
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
		q, err := Quorum(v, 0, 1)
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
	q, err := Quorum(s, 10_000*qms, 1)
	if err != nil || q.Bound != 6*time.Millisecond {
		t.Fatalf("%+v %v", q, err)
	}
	quorumRefused(t, s, -1, "after the quorum time")
}

func TestQuorumRefusals(t *testing.T) {
	quorumRefused(t, []Interval{iv("a", 0, 1), iv("b", 0, 1)}, 0, "too few servers: at least 3")
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
	if _, err := Quorum(many[:MaxServers], 0, 1); err != nil {
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
				_, _ = Quorum([]Interval{x("a", o, b, tn[0]), x("b", o, b, tn[0]), x("c", o, b, tn[0])}, tn[1], 1)
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
	f.Add(int64(100*qms), int64(5*qms), int64(0), int64(5*qms), int64(qms), int64(-50*qms), int64(qms), uint32(0), uint32(0), uint32(0), uint8(2), uint8(1))
	f.Add(int64(0), int64(0), int64(0), int64(0), int64(0), int64(1)<<60, int64(1)<<60, uint32(10_000), uint32(0), uint32(math.MaxUint32), uint8(0), uint8(1))
	f.Add(int64(-1)<<60, int64(7), int64(-7), int64(1)<<59, int64(1)<<58, int64(-1)<<60, int64(0), uint32(math.MaxUint32), uint32(math.MaxUint32), uint32(0), uint8(1), uint8(1))
	f.Fuzz(func(t *testing.T, real, ba, ea, bb, eb, liar, bl int64, ageA, ageB, ageL uint32, pos uint8, mw uint8) {
		fuzzcheck.Watch(t)
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
		// maxWrong is fuzzed too: over the majority rule of three (1) it is
		// refused as too few; with 0 all three must agree, which the liar
		// may prevent, and what is agreed lies inside the honest intervals.
		switch maxWrong := int(mw % 4); {
		case maxWrong > MajorityWrong(len(in)):
			if _, err := Quorum(in, now, maxWrong); err == nil || !strings.Contains(err.Error(), "too few servers") {
				t.Fatalf("max wrong %d of 3: %v", maxWrong, err)
			}
			return
		case maxWrong == 0:
			q, err := Quorum(in, now, 0)
			if err != nil {
				if !strings.Contains(err.Error(), "disagree") {
					t.Fatalf("all three must agree: %v", err)
				}
				return
			}
			aged := func(s Interval) (lo, hi int64) {
				b := int64(s.Bound) + int64(Drift(time.Duration(now-s.T4)))
				return s.Offset - b, s.Offset + b
			}
			for _, s := range in {
				if lo, hi := aged(s); q.Lo < lo || q.Hi > hi {
					t.Fatalf("[%d, %d] outside the interval [%d, %d] of %s with none allowed wrong", q.Lo, q.Hi, lo, hi, s.Operator)
				}
			}
			return
		}
		q, err := Quorum(in, now, 1)
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

// ---- The majority rule (the Rust core's quorum.rs tests of #193) ----

var quorumNames = []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p"}

func TestMajorityCounts(t *testing.T) {
	for n, f := range map[int]int{3: 1, 4: 1, 5: 2, 6: 2, 7: 3, 8: 3, 12: 5, 0: 0, 1: 0, -1: 0} {
		if got := MajorityWrong(n); got != f {
			t.Fatalf("MajorityWrong(%d) = %d, want %d", n, got, f)
		}
	}
	// The client's rule: a majority, and at least 3 agree.
	for n, f := range map[int]int{-1: 0, 0: 0, 2: 0, 3: 0, 4: 1, 5: 2, 6: 2, 7: 3, 8: 3, 12: 5, 16: 7} {
		if got := QuorumWrong(n); got != f {
			t.Fatalf("QuorumWrong(%d) = %d, want %d", n, got, f)
		}
		if n >= 3 && (QuorumWrong(n) > MajorityWrong(n) || n-QuorumWrong(n) < 3) {
			t.Fatalf("QuorumWrong(%d) = %d: over the majority rule or fewer than 3 agree", n, QuorumWrong(n))
		}
	}
}

func TestQuorumRefusesUnsoundMaxWrong(t *testing.T) {
	var v []Interval
	for _, n := range quorumNames[:5] {
		v = append(v, iv(n, 0, 1))
	}
	tooFew := func(what string, in []Interval, maxWrong int) {
		t.Helper()
		if _, err := Quorum(in, 0, maxWrong); !errors.Is(err, ErrQuorumTooFew) {
			t.Fatalf("%s: %v", what, err)
		}
	}
	tooFew("2 wrong of 3", v[:3], 2)
	tooFew("2 wrong of 4", v[:4], 2)
	if _, err := Quorum(v, 0, 2); err != nil {
		t.Fatalf("2 wrong of 5: %v", err)
	}
	tooFew("3 wrong of 5", v, 3)
	tooFew("the largest max wrong", v, math.MaxInt)
	tooFew("a negative max wrong", v, -1)
	// max wrong 0: all must agree, still at least 3.
	if _, err := Quorum(v[:3], 0, 0); err != nil {
		t.Fatalf("0 wrong of 3: %v", err)
	}
	tooFew("0 wrong of 2", v[:2], 0)
	// More than the most servers comes first, whatever max wrong is.
	var many []Interval
	for i := 0; i <= MaxServers; i++ {
		many = append(many, iv(string(rune('A'+i)), 0, 1))
	}
	if _, err := Quorum(many, 0, 100); !errors.Is(err, ErrQuorumTooMany) {
		t.Fatalf("17 servers: %v", err)
	}
}

// honestPlus is n honest servers around 100 ms (each holds 100), plus
// wrong ones (offset and bound in ms).
func honestPlus(nHonest int, wrong ...[2]int64) []Interval {
	var v []Interval
	for i := 0; i < nHonest; i++ {
		v = append(v, iv(quorumNames[i], 100+int64(i%3)-1, 4))
	}
	for k, w := range wrong {
		v = append(v, iv(quorumNames[nHonest+k], w[0], w[1]))
	}
	return v
}

func holdsTruth(q QuorumResult) bool {
	d := q.Offset - 100*qms
	return d <= int64(q.Bound) && -d <= int64(q.Bound)
}

// Two wrong servers, far apart from each other and from the truth: the
// majority rule answers from n = 5 on, F = 1 never does.
func TestMajorityTwoWrong(t *testing.T) {
	for n := 3; n <= 12; n++ {
		v := honestPlus(n-2, [2]int64{-900, 1}, [2]int64{900, 1})
		q, err := Quorum(v, 0, MajorityWrong(n))
		if n >= 5 {
			if err != nil || !holdsTruth(q) {
				t.Fatalf("n %d: %+v, %v", n, q, err)
			}
		} else if !errors.Is(err, ErrNoAgreement) {
			t.Fatalf("n %d: %v", n, err)
		}
		if _, err := Quorum(v, 0, F); !errors.Is(err, ErrNoAgreement) {
			t.Fatalf("F = 1, n %d: %v", n, err)
		}
		// The client's rule answers from 5 on as well, and holds the truth.
		if q, err := Quorum(v, 0, QuorumWrong(n)); n >= 5 && (err != nil || !holdsTruth(q)) {
			t.Fatalf("the client's rule, n %d: %+v, %v", n, q, err)
		}
	}
}

// Two wrong servers that agree with each other (colluding): they cannot
// move the result while they are a minority.
func TestMajorityTwoColluders(t *testing.T) {
	for n := 5; n <= 12; n++ {
		for _, at := range []int64{-1000, 90, 107, 112, 1000} {
			v := honestPlus(n-2, [2]int64{at, 1}, [2]int64{at, 1})
			for _, f := range []int{MajorityWrong(n), QuorumWrong(n)} {
				q, err := Quorum(v, 0, f)
				if err != nil || !holdsTruth(q) {
					t.Fatalf("n %d at %d, %d wrong allowed: %+v, %v", n, at, f, q, err)
				}
			}
		}
	}
}

// A server smearing a leap second (moving 0 to 1000 ms) plus one more
// wrong server: with the majority rule the answer holds the truth at
// every point of the smear, from n = 5 on.
func TestMajoritySmearPlusOneWrong(t *testing.T) {
	for n := 5; n <= 12; n++ {
		for smear := int64(0); smear <= 1000; smear += 25 {
			v := honestPlus(n-2, [2]int64{100 + smear, 2}, [2]int64{-500, 1})
			q, err := Quorum(v, 0, MajorityWrong(n))
			if err != nil || !holdsTruth(q) {
				t.Fatalf("n %d smear %d: %+v, %v", n, smear, q, err)
			}
		}
	}
}

// Against the definition, on random intervals, with the majority rule and
// the client's rule and n from 3 to 12: Lo and Hi are covered by n - f
// intervals, nothing outside [Lo, Hi] is, [Lo, Hi] lies within the
// (f+1)-th lowest lower end and the (f+1)-th highest upper end, and the
// bound holds it.
func TestRandomIntervalsMajorityMatchTheDefinition(t *testing.T) {
	x := uint64(0x9e37_79b9_7f4a_7c15)
	next := func(m uint64) int64 {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		return int64(x % m)
	}
	for _, rule := range []func(int) int{MajorityWrong, QuorumWrong} {
		agreed, refused := 0, 0
		for i := 0; i < 20_000; i++ {
			n := 3 + int(next(10))
			f := rule(n)
			var v []Interval
			for k := 0; k < n; k++ {
				v = append(v, iv(quorumNames[k], next(200), next(60)))
			}
			cover := func(p int64) int {
				c := 0
				for _, s := range v {
					if s.Offset-int64(s.Bound) <= p && p <= s.Offset+int64(s.Bound) {
						c++
					}
				}
				return c
			}
			var lows, highs, covered []int64
			for _, s := range v {
				lows, highs = append(lows, s.Offset-int64(s.Bound)), append(highs, s.Offset+int64(s.Bound))
			}
			points := append(append([]int64(nil), lows...), highs...)
			sort.Slice(points, func(a, b int) bool { return points[a] < points[b] })
			for _, p := range points {
				if cover(p) >= n-f {
					covered = append(covered, p)
				}
			}
			q, err := Quorum(v, 0, f)
			if err != nil {
				refused++
				if !errors.Is(err, ErrNoAgreement) || len(covered) != 0 {
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
			if lows[f] > q.Lo || q.Hi > highs[f] {
				t.Fatalf("round %d: %+v outside [%d, %d]", i, q, lows[f], highs[f])
			}
			if q.Offset-int64(q.Bound) > q.Lo || q.Hi > q.Offset+int64(q.Bound) {
				t.Fatalf("round %d: the bound of %+v does not hold [Lo, Hi]", i, q)
			}
		}
		if agreed <= 1000 || refused <= 1000 {
			t.Fatalf("%d agreed, %d refused", agreed, refused)
		}
	}
}
