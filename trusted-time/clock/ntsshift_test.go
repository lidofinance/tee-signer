package clock

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"
	"time"
)

const testTick = 4 * time.Second

// next plans the next tick, 4 s after the last (the start at local 0).
func (s *ntsShifts) next() []ntsAsk {
	if !s.started {
		return s.plan(0)
	}
	return s.plan(int64(s.q+1) * s.tickNs)
}

// contact is one contact the schedule made: the tick it counts at and why.
type contact struct {
	at   int
	role ntsRole
	rate bool // the answer was RATE
}

// driveShifts runs the schedule alone for ticks ticks. answer says whether a
// contact is answered; a lost answer of an active gets a fallback one tick
// later, and fewer than 3 answers in the last gap ticks a burst.
func driveShifts(s *ntsShifts, ticks int, answer func(op, q int) bool) map[int][]contact {
	return driveShiftsRate(s, ticks, func(op, q int) (bool, bool) { return answer(op, q), false }, nil)
}

// driveShiftsRate is driveShifts where answer can also say RATE, and
// before (if set) runs before each tick.
func driveShiftsRate(s *ntsShifts, ticks int, answer func(op, q int) (ok, rate bool), before func()) map[int][]contact {
	got := map[int][]contact{}
	lastOK := make([]int, len(s.last))
	for i := range lastOK {
		lastOK[i] = never
	}
	do := func(a ntsAsk, at int) bool {
		ok, rate := answer(a.op, at)
		got[a.op] = append(got[a.op], contact{at, a.role, rate})
		s.result(a, ok, rate)
		if ok {
			lastOK[a.op] = at
		}
		return ok
	}
	for range ticks {
		if before != nil {
			before()
		}
		for _, a := range s.next() {
			if !do(a, s.q) && a.role == roleActive {
				if op, found := s.fallback(1); found {
					do(ntsAsk{op, roleFallback}, s.q+1)
				}
			}
		}
		fresh := 0
		for _, at := range lastOK {
			if at != never && s.q-at < s.gap+(s.gap*2)/5 {
				fresh++
			}
		}
		if fresh < NTSShiftBurstBelow {
			for _, a := range s.burst(1) {
				do(a, s.q+1)
			}
		}
	}
	return got
}

func checkGaps(t *testing.T, s *ntsShifts, got map[int][]contact) {
	t.Helper()
	for op, cs := range got {
		for i := 1; i < len(cs); i++ {
			if d := cs[i].at - cs[i-1].at; d < s.gap {
				t.Fatalf("operator %d contacted at ticks %d and %d (%d ticks, minimum %d)", op, cs[i-1].at, cs[i].at, d, s.gap)
			}
		}
	}
}

func TestShiftsStartAsksEveryOperatorThenTheGrid(t *testing.T) {
	s := newNTSShifts(9, []byte("seed"), testTick)
	if s.gap != 15 || s.shiftLen != 225 || s.actives != 5 {
		t.Fatalf("gap %d shift %d actives %d", s.gap, s.shiftLen, s.actives)
	}
	first := s.next()
	if len(first) != 9 {
		t.Fatalf("start asked %d of 9", len(first))
	}
	for _, a := range first {
		if a.role != roleStart {
			t.Fatalf("start role %v", a.role)
		}
	}
	// No one again before 60 s; then each active once, on its own slot,
	// 3 ticks apart (60 s / 5 actives = 12 s).
	var at []int
	for range 30 {
		for _, a := range s.next() {
			if a.role != roleActive || !slices.Contains(s.slots, a.op) {
				t.Fatalf("tick %d: %+v", s.q, a)
			}
			at = append(at, s.q)
		}
	}
	if len(at) != 5 || at[0] < 15 || at[4] > 29 {
		t.Fatalf("active ticks after start: %v", at)
	}
	for i := 1; i < 5; i++ {
		if at[i]-at[i-1] != 3 {
			t.Fatalf("slots not 3 ticks apart: %v", at)
		}
	}
}

// The trap of review 3: with a healthy link, an active is asked exactly
// every 15 ticks (60 s), never 16 or 30.
func TestShiftsGridDoesNotSlip(t *testing.T) {
	s := newNTSShifts(8, []byte("grid"), testTick)
	got := driveShifts(s, 3*225, func(int, int) bool { return true })
	checkGaps(t, s, got)
	// Back to back active contacts are 15 ticks apart, except after an
	// incoming's first contact (asked at once, off its slot), where the
	// next one waits for the slot: 16 to 29 ticks, once per handover.
	offGrid := 0
	for op, cs := range got {
		for i := 1; i < len(cs); i++ {
			if cs[i].role != roleActive || cs[i-1].role != roleActive {
				continue
			}
			switch d := cs[i].at - cs[i-1].at; {
			case d == 15:
			case d < 30:
				offGrid++
			default:
				// A gap means the operator left and came back later.
				if d < 225 {
					t.Fatalf("operator %d: active contacts %d ticks apart at tick %d", op, d, cs[i].at)
				}
			}
		}
	}
	if offGrid > 3 {
		t.Fatalf("%d off-grid active gaps in 3 shifts", offGrid)
	}
	total := 0
	for _, cs := range got {
		total += len(cs)
	}
	// 5 actives at 60 per hour for 45 minutes, plus the start (8) and up
	// to one off-grid contact per incoming.
	hours := float64(3*225) * testTick.Hours()
	if perHour := float64(total-8) / hours; perHour < 295 || perHour > 310 {
		t.Fatalf("%.1f contacts per hour, want about 300", perHour)
	}
}

func TestShiftsHandoverOneAtATime(t *testing.T) {
	s := newNTSShifts(8, []byte("handover"), testTick)
	s.next()
	prev := slices.Clone(s.slots)
	changes := 0
	for range 4 * 225 {
		s.next()
		if slices.Equal(prev, s.slots) {
			continue
		}
		var out, in []int
		for k := range prev {
			if prev[k] != s.slots[k] {
				out, in = append(out, prev[k]), append(in, s.slots[k])
			}
		}
		if len(out) != 1 {
			t.Fatalf("tick %d: %d slots changed at once", s.q, len(out))
		}
		if want := s.order[(s.shift-1)%8]; out[0] != want {
			t.Fatalf("tick %d: %d left, the order says %d", s.q, out[0], want)
		}
		if want := s.order[(s.shift-1+5)%8]; in[0] != want {
			t.Fatalf("tick %d: %d came in, the order says %d", s.q, in[0], want)
		}
		if (s.q+s.shift0)%225 != 0 {
			t.Fatalf("handover at tick %d, off the shift grid (shift0 %d)", s.q, s.shift0)
		}
		changes++
		prev = slices.Clone(s.slots)
	}
	if changes != 4 {
		t.Fatalf("%d handovers in 4 shifts", changes)
	}
}

// An incoming that does not answer stays active for its whole shift (it is
// not replaced) and counts as a failed handover; fallbacks cover its slot.
func TestShiftsFailedIncomingIsNotReplaced(t *testing.T) {
	s := newNTSShifts(8, []byte("failed"), testTick)
	firstIn := s.order[5]
	start := 225 - s.shift0 // tick of the first handover
	got := driveShifts(s, start+225-1, func(op, _ int) bool { return op != firstIn })
	checkGaps(t, s, got)
	c := s.counts[firstIn]
	if c.Handovers != 1 || c.FailedHandovers != 1 {
		t.Fatalf("counts of the failed incoming: %+v", c)
	}
	if !slices.Contains(s.slots, firstIn) {
		t.Fatalf("failed incoming %d replaced: slots %v", firstIn, s.slots)
	}
	// Every scheduled contact of it after the handover (one per 60 s) is
	// followed by a fallback to a non-active operator.
	var asks, fbs int
	for _, x := range got[firstIn] {
		if x.at >= start && x.role == roleActive {
			asks++
		}
	}
	for op, cs := range got {
		for _, x := range cs {
			if x.role == roleFallback {
				fbs++
				if x.at < start {
					t.Fatalf("fallback to %d before the handover", op)
				}
			}
		}
	}
	if asks < 14 || fbs != asks {
		t.Fatalf("%d scheduled asks of the failed incoming, %d fallbacks", asks, fbs)
	}
}

func TestShiftsFallbackPicksNonActiveNotAskedInGap(t *testing.T) {
	s := newNTSShifts(8, []byte("fallback"), testTick)
	s.next()
	for range 20 {
		s.next()
	}
	seen := map[int]bool{}
	for range 3 {
		op, ok := s.fallback(1)
		if !ok {
			t.Fatal("no fallback with 3 standbys idle")
		}
		if slices.Contains(s.slots, op) || seen[op] {
			t.Fatalf("fallback %d: active or asked again", op)
		}
		seen[op] = true
	}
	if _, ok := s.fallback(1); ok {
		t.Fatal("a fourth fallback within 60 s")
	}
}

func TestShiftsBurstAsksOnlyThoseOutOfGap(t *testing.T) {
	s := newNTSShifts(8, []byte("burst"), testTick)
	s.next()
	if b := s.burst(1); len(b) != 0 {
		t.Fatalf("burst right after the start: %v", b)
	}
	for range 15 {
		s.next()
	}
	b := s.burst(1)
	// At tick 15 at most one active has been asked again (its slot).
	if len(b) < 7 {
		t.Fatalf("burst at tick 15 asked %d", len(b))
	}
	if again := s.burst(1); len(again) != 0 {
		t.Fatalf("second burst in the same tick: %v", again)
	}
}

// Property: over random runs (loss rates, dead operators, catalog sizes),
// no operator is contacted twice within 15 ticks, counting a fallback or
// burst contact at the tick after the one it was sent in.
func TestShiftsMinGapProperty(t *testing.T) {
	for run := range 200 {
		r := rand.New(rand.NewPCG(uint64(run), 7))
		c := 3 + r.IntN(10)
		s := newNTSShifts(c, fmt.Appendf(nil, "p%d", run), testTick)
		loss := r.Float64()
		dead := r.IntN(c)
		got := driveShifts(s, 2*225+r.IntN(225), func(op, _ int) bool { return op >= dead && r.Float64() >= loss })
		checkGaps(t, s, got)
	}
}

// The same with no seed at start and a seed set at a random tick, and
// RATE answers: never two contacts within 15 ticks, and after a RATE never
// within twice the gap the operator had.
func TestShiftsMinGapPropertySeedLaterAndRate(t *testing.T) {
	for run := range 200 {
		r := rand.New(rand.NewPCG(uint64(run), 9))
		c := 3 + r.IntN(10)
		s := newNTSShifts(c, nil, testTick)
		loss, rateP := r.Float64()/2, r.Float64()/5
		seedAt, ticks := r.IntN(300), 2*225+r.IntN(225)
		got := driveShiftsRate(s, ticks, func(op, _ int) (bool, bool) {
			if r.Float64() < rateP {
				return false, true
			}
			return r.Float64() >= loss, false
		}, func() {
			if s.started && s.q == seedAt {
				s.reseed(fmt.Appendf(nil, "k%d", run))
			}
		})
		checkGaps(t, s, got)
		for op, cs := range got {
			gap := s.gap
			for i := 1; i < len(cs); i++ {
				if cs[i-1].rate {
					gap = min(2*gap, s.maxGap)
					if d := cs[i].at - cs[i-1].at; d < gap {
						t.Fatalf("run %d: operator %d asked %d ticks after a RATE, its gap is %d", run, op, d, gap)
					}
				} else {
					gap = s.gap // an answer or a loss: not tracked further
				}
			}
		}
		if !s.seeded || len(s.slots) != ShiftActives(c) {
			t.Fatalf("run %d: seeded %v slots %v", run, s.seeded, s.slots)
		}
	}
}

// Without a seed every operator is active; the start loop's calls every
// 5 s move time on by whole ticks, so the first slot after the start comes
// 60 s after it, not 15 calls later.
func TestShiftsNoSeedAndTicksFollowTime(t *testing.T) {
	s := newNTSShifts(8, nil, testTick)
	if len(s.slots) != 8 || s.seeded {
		t.Fatalf("slots %v seeded %v", s.slots, s.seeded)
	}
	s.plan(0)
	var first int64 = -1
	for now := int64(5 * time.Second); first < 0 && now < int64(2*time.Minute); now += int64(5 * time.Second) {
		if len(s.plan(now)) > 0 {
			first = now
		}
	}
	if first < int64(NTSShiftMinGap) || first > int64(NTSShiftMinGap+5*time.Second) {
		t.Fatalf("first slot after the start at %v", time.Duration(first))
	}
}

// At most NTSShiftFallbackCap fallbacks per hour; the window slides.
func TestShiftsFallbackCap(t *testing.T) {
	s := newNTSShifts(8, []byte("cap"), testTick)
	s.started = true
	got := 0
	for q := 0; q < s.hour; q++ {
		s.q = q
		for {
			if _, ok := s.fallback(1); !ok {
				break
			}
			got++
		}
	}
	if got != NTSShiftFallbackCap || s.capped == 0 {
		t.Fatalf("%d fallbacks in an hour, %d capped", got, s.capped)
	}
	s.q = 3 * s.hour
	if _, ok := s.fallback(1); !ok {
		t.Fatal("no fallback an hour after the cap")
	}
	if _, _, capped := s.snapshot(make([]string, 8)); capped != s.capped {
		t.Fatalf("snapshot capped %d", capped)
	}
}
