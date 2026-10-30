//go:build nts

package nts

import (
	"fmt"
	"math/big"
	"time"
)

// The time from several servers that one of them may get wrong.
//
// Each measurement gives an interval [offset - bound, offset + bound] that
// holds the real offset if the server is honest. With at most F servers
// wrong, at least n - F intervals hold the real offset, so the real offset
// is a point that at least n - F intervals cover. Quorum returns [lo, hi],
// the smallest and the largest such point, or no answer if there is none
// (more than F servers are wrong). The result is the midpoint, with half
// the width as its bound. This is the intersection algorithm of RFC 5905
// section 11.2.1 (Marzullo) with a fixed F and without the clustering that
// follows it.

const (
	// F is how many servers may be wrong at once.
	F = 1
	// MinServers is the smallest quorum: 2F + 1, so that F wrong servers
	// cannot outvote the honest ones.
	MinServers = 2*F + 1
	// MaxServers bounds a quorum.
	MaxServers = 16
	// MaxOperatorLen bounds an operator label.
	MaxOperatorLen = 32
)

// Interval is one server's measurement for the quorum.
type Interval struct {
	Operator string
	Offset   int64
	Bound    time.Duration
	T4       int64
}

// QuorumResult is the combined offset at the quorum's `now`.
type QuorumResult struct {
	Offset int64
	Bound  time.Duration
	Lo, Hi int64
}

type quorumEnd struct {
	x     *big.Int
	start bool
}

// Quorum combines MinServers to MaxServers intervals from distinct
// operators, F of which may be wrong, at the Monotonic time now. Each bound
// first grows by RhoPPM of its age at now.
func Quorum(in []Interval, now int64) (QuorumResult, error) {
	fail := func(format string, args ...any) (QuorumResult, error) {
		return QuorumResult{}, &Error{Code: CodeQuorum, Err: fmt.Errorf(format, args...)}
	}
	if len(in) < MinServers {
		return fail("fewer than %d servers", MinServers)
	}
	if len(in) > MaxServers {
		return fail("more than %d servers", MaxServers)
	}
	ends := make([]quorumEnd, 0, 2*len(in))
	for i, s := range in {
		if len(s.Operator) == 0 || len(s.Operator) > MaxOperatorLen {
			return fail("operator label empty or over %d octets", MaxOperatorLen)
		}
		for _, o := range in[:i] {
			if o.Operator == s.Operator {
				return fail("two servers of one operator")
			}
		}
		if s.Bound < 0 {
			return fail("negative error bound")
		}
		if s.T4 > now {
			return fail("measurement after the quorum time")
		}
		age := new(big.Int).Sub(big.NewInt(now), big.NewInt(s.T4))
		if !age.IsInt64() {
			return fail("offset out of range")
		}
		bound := new(big.Int).Add(big.NewInt(int64(s.Bound)), big.NewInt(int64(Drift(time.Duration(age.Int64())))))
		off := big.NewInt(s.Offset)
		ends = append(ends,
			quorumEnd{x: new(big.Int).Sub(off, bound), start: true},
			quorumEnd{x: new(big.Int).Add(off, bound), start: false})
	}
	// Sort by position; at equal positions a start comes before an end, so
	// touching intervals overlap (closed intervals).
	sortEnds(ends)
	need := len(in) - F
	var lo, hi *big.Int
	count := 0
	for _, e := range ends {
		if e.start {
			count++
			if count >= need && lo == nil {
				lo = e.x
			}
		} else {
			if count >= need {
				hi = e.x
			}
			if count > 0 {
				count--
			}
		}
	}
	if lo == nil || hi == nil {
		return fail("the servers disagree: more than %d wrong", F)
	}
	// mid = floor((lo + hi) / 2), half = ceil((hi - lo) / 2).
	sum := new(big.Int).Add(lo, hi)
	mid := new(big.Int).Div(sum, big.NewInt(2)) // Div is Euclidean: floor for a positive divisor
	width := new(big.Int).Sub(hi, lo)
	half := new(big.Int).Div(new(big.Int).Add(width, big.NewInt(1)), big.NewInt(2))
	for _, v := range []*big.Int{mid, half, lo, hi} {
		if !v.IsInt64() {
			return fail("offset out of range")
		}
	}
	return QuorumResult{Offset: mid.Int64(), Bound: time.Duration(half.Int64()), Lo: lo.Int64(), Hi: hi.Int64()}, nil
}

// sortEnds is an insertion sort: at most 32 ends.
func sortEnds(ends []quorumEnd) {
	less := func(a, b quorumEnd) bool {
		if c := a.x.Cmp(b.x); c != 0 {
			return c < 0
		}
		return a.start && !b.start
	}
	for i := 1; i < len(ends); i++ {
		for j := i; j > 0 && less(ends[j], ends[j-1]); j-- {
			ends[j], ends[j-1] = ends[j-1], ends[j]
		}
	}
}
