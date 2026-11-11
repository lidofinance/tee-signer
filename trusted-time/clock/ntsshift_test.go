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
		return s.plan(0, nil)
	}
	return s.plan(int64(s.q+1)*s.tickNs, nil)
}

// contact is one contact the schedule made: the tick it counts at and why.
type contact struct {
	at   int
	role ntsRole
	rate bool // the answer was RATE
	// early: made before the first quorum to an operator with no answer
	// yet, so it may follow a lost contact after NTSShiftStartRetry.
	early bool
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
	do := func(a ntsAsk, at int) (bool, bool) {
		ok, rate := answer(a.op, at)
		early := !s.warm && s.counts[a.op].Answers == 0
		got[a.op] = append(got[a.op], contact{at, a.role, rate, early})
		s.result(a, ok, rate, false, true)
		if ok {
			lastOK[a.op] = at
		}
		return ok, rate
	}
	all := make([]bool, len(s.last))
	for i := range all {
		all[i] = true
	}
	for range ticks {
		if before != nil {
			before()
		}
		for _, a := range s.next() {
			if ok, rate := do(a, s.q); !ok && a.role == roleActive {
				if op, found := s.fallback(a.op, 1, !rate, all); found {
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
			for _, a := range s.burst(1, all) {
				do(a, s.q+1)
			}
		}
		if fresh >= 3 {
			s.quorum()
		}
	}
	return got
}

// checkGaps: contacts with one operator a gap apart. An early contact may
// follow the one before after s.retry ticks. So may the one retry of a
// lost answer, and the contact after it is still a gap after the lost one.
func checkGaps(t *testing.T, s *ntsShifts, got map[int][]contact) {
	t.Helper()
	for op, cs := range got {
		prev := 0 // the last contact that was not a retry
		for i := 1; i < len(cs); i++ {
			min, from := s.gap, prev
			switch {
			case cs[i].role == roleRetry:
				if i != prev+1 {
					t.Fatalf("operator %d: a second retry at tick %d", op, cs[i].at)
				}
				min, from = s.retry, i-1
			case cs[i].early:
				min, from = s.retry, i-1
			}
			if d := cs[i].at - cs[from].at; d < min {
				t.Fatalf("operator %d contacted at ticks %d and %d (%d ticks, minimum %d)", op, cs[from].at, cs[i].at, d, min)
			}
			if cs[i].role != roleRetry || cs[i].rate {
				prev = i
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
		op, ok := s.fallback(0, 1, false, allOps(s))
		if !ok {
			t.Fatal("no fallback with 3 standbys idle")
		}
		if slices.Contains(s.slots, op) || seen[op] {
			t.Fatalf("fallback %d: active or asked again", op)
		}
		seen[op] = true
	}
	if _, ok := s.fallback(0, 1, false, allOps(s)); ok {
		t.Fatal("a fourth fallback within 60 s")
	}
}

func TestShiftsBurstAsksOnlyThoseOutOfGap(t *testing.T) {
	s := newNTSShifts(8, []byte("burst"), testTick)
	s.next()
	if b := s.burst(1, allOps(s)); len(b) != 0 {
		t.Fatalf("burst right after the start: %v", b)
	}
	for range 15 {
		s.next()
	}
	b := s.burst(1, allOps(s))
	// At tick 15 at most one active has been asked again (its slot).
	if len(b) < 7 {
		t.Fatalf("burst at tick 15 asked %d", len(b))
	}
	if again := s.burst(1, allOps(s)); len(again) != 0 {
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
	s.plan(0, nil)
	var first int64 = -1
	for now := int64(5 * time.Second); first < 0 && now < int64(2*time.Minute); now += int64(5 * time.Second) {
		if len(s.plan(now, nil)) > 0 {
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
			if _, ok := s.fallback(0, 1, false, allOps(s)); !ok {
				break
			}
			got++
		}
	}
	if got != NTSShiftFallbackCap || s.capped == 0 {
		t.Fatalf("%d fallbacks in an hour, %d capped", got, s.capped)
	}
	s.q = 3 * s.hour
	if _, ok := s.fallback(0, 1, false, allOps(s)); !ok {
		t.Fatal("no fallback an hour after the cap")
	}
	if _, _, capped := s.snapshot(make([]string, 8)); capped != s.capped {
		t.Fatalf("snapshot capped %d", capped)
	}
}

// Before the first quorum an operator that got the start round and did not
// answer may be asked again after NTSShiftStartRetry (5 ticks); one that
// answered or sent RATE waits the full gap. After a quorum every gap is the
// full one again.
func TestShiftsStartRetry(t *testing.T) {
	s := newNTSShifts(4, []byte("seed"), testTick)
	for _, a := range s.next() {
		s.result(a, a.op == 0, a.op == 1, false, true)
	}
	for range s.retry - 1 {
		s.next()
	}
	if b := s.burst(1, allOps(s)); len(b) != 0 {
		t.Fatalf("burst before the retry gap: %v", b)
	}
	s.next()
	var got []int
	for _, a := range s.burst(1, allOps(s)) {
		got = append(got, a.op)
		s.result(a, false, false, false, true)
	}
	slices.Sort(got)
	if !slices.Equal(got, []int{2, 3}) {
		t.Fatalf("retried %v, want the two that did not answer", got)
	}
	if s.minGap(0) != NTSShiftMinGap || s.minGap(1) != NTSShiftMinGap || s.minGap(2) != NTSShiftStartRetry {
		t.Fatalf("min gaps %v %v %v", s.minGap(0), s.minGap(1), s.minGap(2))
	}
	s.quorum()
	for range s.retry + 1 {
		s.next()
	}
	if b := s.burst(1, allOps(s)); len(b) != 0 {
		t.Fatalf("burst after the quorum within the full gap: %v", b)
	}
	if s.minGap(2) != NTSShiftMinGap {
		t.Fatalf("after the quorum: %v", s.minGap(2))
	}
}

// allOps says every operator can be asked.
func allOps(s *ntsShifts) []bool {
	out := make([]bool, len(s.last))
	for i := range out {
		out[i] = true
	}
	return out
}

// A wide answer (the server answered, too wide to use) gets no start
// retry: the operator waits its full gap, as one that answered.
func TestShiftsWideAnswerNoStartRetry(t *testing.T) {
	s := newNTSShifts(4, []byte("seed"), testTick)
	for _, a := range s.next() {
		s.result(a, false, false, a.op == 0, true)
	}
	if s.minGap(0) != NTSShiftMinGap || s.minGap(1) != NTSShiftStartRetry {
		t.Fatalf("min gaps: wide %v, lost %v", s.minGap(0), s.minGap(1))
	}
}

// After the first quorum, a lost answer with no operator free for a
// fallback (all 4 active) gets one retry of the same operator
// NTSShiftStartRetry later; its next slot stays a full gap after the lost
// contact. No retry before the first quorum, or after a RATE or a wide
// answer (retry false).
func TestShiftsRetryOfALostAnswer(t *testing.T) {
	s := newNTSShifts(4, []byte("seed"), testTick)
	for _, a := range s.next() {
		s.result(a, true, false, false, true)
	}
	s.quorum()
	var lost ntsAsk
	for lost.role != roleActive {
		for _, a := range s.next() {
			if a.role == roleActive && lost.role != roleActive {
				lost = a
			}
		}
	}
	lostAt := s.q
	s.result(lost, false, false, false, true)
	if _, ok := s.fallback(lost.op, 1, true, allOps(s)); ok {
		t.Fatal("a fallback with every operator active")
	}
	var retryAt int
	for range s.gap {
		for _, a := range s.next() {
			if a.op != lost.op {
				continue
			}
			switch a.role {
			case roleRetry:
				// refreshShifts asks no fallback or retry for a lost retry.
				retryAt = s.q
				s.result(a, false, false, false, true)
			case roleActive:
				if retryAt == 0 || s.q-lostAt < s.gap {
					t.Fatalf("slot at tick %d: lost at %d, retry at %d", s.q, lostAt, retryAt)
				}
			}
		}
	}
	if retryAt-lostAt != s.retry || s.counts[lost.op].Retries != 1 {
		t.Fatalf("retry at tick %d after the loss at %d, %d retries", retryAt, lostAt, s.counts[lost.op].Retries)
	}
	// retry false (a RATE or a wide answer): none.
	before := s.counts[lost.op].Retries
	s.fallback(lost.op, 1, false, allOps(s))
	for range s.retry + 1 {
		for _, a := range s.next() {
			if a.role == roleRetry {
				t.Fatalf("a retry of %d with retry false", a.op)
			}
		}
	}
	if s.counts[lost.op].Retries != before {
		t.Fatal("retries counted with retry false")
	}
	// Before the first quorum the start retries cover it.
	c := newNTSShifts(4, []byte("seed"), testTick)
	c.next()
	c.fallback(0, 1, true, allOps(c))
	if c.retryAt[0] != never {
		t.Fatal("a loss retry before the first quorum")
	}
}

// Calls faster than a tick (a Run ticker that fired during the start delay)
// keep the schedule at most one tick ahead of local time.
func TestShiftsTicksDoNotRunAhead(t *testing.T) {
	s := newNTSShifts(8, nil, testTick)
	s.plan(0, nil)
	for i := range 20 {
		s.plan(int64(i)*int64(100*time.Millisecond), nil)
	}
	if s.q > 1 {
		t.Fatalf("tick %d after 2 s of calls", s.q)
	}
	s.plan(int64(60*time.Second), nil)
	if s.q != 15 {
		t.Fatalf("tick %d at 60 s", s.q)
	}
}

// Fallbacks and bursts skip operators that cannot be asked now (stopped by
// DENY or RSTR, or in an NTS-KE backoff), and the burst stops while the
// fallback cap is full.
func TestShiftsFallbackAndBurstSkipUnaskable(t *testing.T) {
	s := newNTSShifts(8, []byte("fallback"), testTick)
	for range 21 {
		s.next()
	}
	can := allOps(s)
	for op := range can {
		can[op] = slices.Contains(s.slots, op)
	}
	if _, ok := s.fallback(s.slots[0], 1, false, can); ok {
		t.Fatal("a fallback to an operator that cannot be asked")
	}
	for _, a := range s.burst(1, can) {
		if !can[a.op] {
			t.Fatalf("burst asks %d", a.op)
		}
	}
	s.burstAt = make([]int, NTSShiftBurstCap)
	for i := range s.burstAt {
		s.burstAt[i] = s.q
	}
	if b := s.burst(1, allOps(s)); len(b) != 0 {
		t.Fatalf("burst with the cap full: %v", b)
	}
}

// warmLost runs 4 operators (all active) to a lost answer of an active
// after the first quorum and returns it and its tick.
func warmLost(t *testing.T) (*ntsShifts, ntsAsk, int) {
	t.Helper()
	s := newNTSShifts(4, []byte("seed"), testTick)
	for _, a := range s.next() {
		s.result(a, true, false, false, true)
	}
	s.quorum()
	for {
		for _, a := range s.next() {
			if a.role == roleActive {
				s.result(a, false, false, false, true)
				return s, a, s.q
			}
		}
	}
}

// The retry of a lost answer is booked only for an operator that can be
// asked and has the base gap (no RATE backoff); one that cannot be asked
// when it is due, or is late by more than a tick, is dropped with no
// query, no count and no cap.
func TestShiftsRetryBookedAndDropped(t *testing.T) {
	s, lost, _ := warmLost(t)
	can := allOps(s)
	can[lost.op] = false
	s.fallback(lost.op, 1, true, can)
	if s.retryAt[lost.op] != never {
		t.Fatal("a retry booked for an operator that cannot be asked")
	}
	s.gaps[lost.op] = 2 * s.gap
	s.fallback(lost.op, 1, true, allOps(s))
	if s.retryAt[lost.op] != never {
		t.Fatal("a retry booked in a RATE backoff")
	}
	s.gaps[lost.op] = s.gap
	s.fallback(lost.op, 1, true, allOps(s))
	at := s.retryAt[lost.op]
	if at == never {
		t.Fatal("no retry booked")
	}
	for s.q < at-1 {
		s.next()
	}
	can = allOps(s)
	can[lost.op] = false
	caps := len(s.fallbackAt)
	for _, a := range s.plan(int64(s.q+1)*s.tickNs, can) {
		if a.role == roleRetry {
			t.Fatal("a retry to an operator that cannot be asked")
		}
	}
	if s.retryAt[lost.op] != never || len(s.fallbackAt) != caps || s.counts[lost.op].Retries != 0 {
		t.Fatalf("dropped retry: at %d, cap %d to %d, retries %d", s.retryAt[lost.op], caps, len(s.fallbackAt), s.counts[lost.op].Retries)
	}
	// Late by more than a tick: dropped.
	s2, lost2, _ := warmLost(t)
	s2.fallback(lost2.op, 1, true, allOps(s2))
	at2 := s2.retryAt[lost2.op]
	for s2.q < at2-1 {
		s2.next()
	}
	for _, a := range s2.plan(int64(at2+2)*s2.tickNs, nil) {
		if a.role == roleRetry {
			t.Fatalf("a retry 2 ticks late at tick %d", s2.q)
		}
	}
}

// A swap carries a pending retry of a lost answer with its operator: one
// that stays keeps it under its new index and asks it once, a new one has
// none, and one that leaves takes its retry with it.
func TestShiftsSwapCarriesRetry(t *testing.T) {
	retries := func(s *ntsShifts) map[int]int {
		got := map[int]int{}
		for range s.retry + 2 {
			for _, a := range s.next() {
				if a.role == roleRetry {
					got[a.op]++
				}
			}
		}
		return got
	}

	// Two new operators, at index 0 and 5: the 4 old ones move up by one.
	s, lost, _ := warmLost(t)
	s.fallback(lost.op, 1, true, allOps(s))
	at := s.retryAt[lost.op]
	if at == never {
		t.Fatal("no retry booked")
	}
	s.swap([]int{-1, 0, 1, 2, 3, -1}, make([]*ntsShiftState, 6))
	moved := lost.op + 1
	if len(s.retryAt) != 6 || s.retryAt[moved] != at || s.retryAt[0] != never || s.retryAt[5] != never {
		t.Fatalf("after the swap: retryAt %v, want %d at %d", s.retryAt, at, moved)
	}
	if got := retries(s); len(got) != 1 || got[moved] != 1 {
		t.Fatalf("retries after the swap: %v, want one of %d", got, moved)
	}

	// The operator with the retry leaves: no retry goes out.
	s2, lost2, _ := warmLost(t)
	s2.fallback(lost2.op, 1, true, allOps(s2))
	if s2.retryAt[lost2.op] == never {
		t.Fatal("no retry booked")
	}
	var keep []int
	for op := range s2.last {
		if op != lost2.op {
			keep = append(keep, op)
		}
	}
	s2.swap(keep, make([]*ntsShiftState, len(keep)))
	for op, r := range s2.retryAt {
		if r != never {
			t.Fatalf("after the swap: a retry of %d at %d", op, r)
		}
	}
	if got := retries(s2); len(got) != 0 {
		t.Fatalf("retries after the operator left: %v", got)
	}
}

// Each burst contact counts toward NTSShiftBurstCap, and a burst stops when
// it is reached. A full fallback cap does not stop it.
func TestShiftsBurstCountsTowardItsCap(t *testing.T) {
	s := newNTSShifts(8, []byte("burst"), testTick)
	for range 16 {
		s.next()
	}
	s.burstAt = make([]int, NTSShiftBurstCap-2)
	for i := range s.burstAt {
		s.burstAt[i] = s.q
	}
	s.fallbackAt = make([]int, NTSShiftFallbackCap)
	for i := range s.fallbackAt {
		s.fallbackAt[i] = s.q
	}
	if b := s.burst(1, allOps(s)); len(b) != 2 || len(s.burstAt) != NTSShiftBurstCap {
		t.Fatalf("burst with room for 2: %d asked, %d counted", len(b), len(s.burstAt))
	}
	s.q += s.hour
	if b := s.burst(1, allOps(s)); len(b) == 0 {
		t.Fatal("no burst an hour later")
	}
}
