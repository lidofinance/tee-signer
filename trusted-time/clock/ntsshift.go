package clock

import (
	crand "crypto/rand"
	"crypto/sha256"
	"math/rand/v2"
	"slices"
	"sync"
	"time"
)

// Operator shifts (#185). The NTS clock runs this schedule when NTS.Shifts
// or NTS.ScheduleSeed is set; trusted-time/docs/nts.md has the design.
//
//   - Time is in ticks of Interval / 4 (4 s) since the start round: at
//     least one tick per Refresh, more when calls are further apart (the
//     runner's start loop). The 60 s grid sits on the tick grid and never
//     slips to the next slot.
//   - Start: the first tick asks every operator once.
//   - Without a seed, every operator is active (asked once per 60 s on
//     its slot). With a seed (SetScheduleSeed, or NTS.ScheduleSeed),
//     ShiftActives(n) of the n operators are active, in a per-signer order,
//     with the grid phase from the seed; the switch takes effect at the
//     next slot.
//   - Every NTSShiftLength the window of actives moves one place along the
//     order: the first active leaves on time, the next operator in the
//     order takes its slot. An incoming that does not answer stays (it is
//     not replaced) and counts as a failed handover.
//   - A lost answer of an active is followed at once by one query to a
//     random non-active operator not asked within its minimum gap, up to
//     NTSShiftFallbackCap per hour. If no such operator can be asked (a
//     set under NTSShiftMinServers has none), the same operator is asked
//     once more NTSShiftStartRetry after the lost contact, after the first
//     quorum only, within the same cap. Its next slot stays where it was.
//     A wide answer (over MaxSampleBound), a RATE, an operator in a RATE
//     backoff and a contact that sent nothing get no such retry.
//   - With fewer than NTSShiftBurstBelow fresh samples after the tick's
//     queries, every operator past its minimum gap is asked, up to
//     NTSShiftBurstCap burst contacts per hour.
//   - Each operator's minimum gap is NTSShiftMinGap; a Kiss-o'-Death RATE
//     doubles it (up to 1024 s), each answer halves it back.
//   - Two contacts with one operator start at least its gap apart (see
//     mark, and NTS.waitGap for the gap in local time). Until the first
//     quorum, an operator that missed its last contact and sent no RATE
//     has a gap of NTSShiftStartRetry. After it, the retry of a lost answer
//     above is the one exception: at most one per lost contact, within the
//     120 per hour cap, so an operator whose answers are lost gets at most
//     two requests per 60 s. A contact
//     that runs NTS-KE first sends its NTP query up to a few seconds after
//     its start.
const (
	// NTSShiftActives is the most operators active at once.
	NTSShiftActives = 5
	// NTSShiftSpares is how many operators ShiftActives keeps out of the
	// active set, for fallbacks and bursts.
	NTSShiftSpares = 3
	// NTSShiftMinServers is the fewest operators the schedule hands over
	// on: 4 actives and the spares. Fewer are all active (ShiftActives). With 4 actives the quorum is
	// 3 of 4. The newcomer of a handover is asked at once, off its slot,
	// and its next slot can come up to 29 ticks later; that first sample
	// ages out before it, leaving exactly 3 fresh for up to about 40 s.
	NTSShiftMinServers = 4 + NTSShiftSpares
	NTSShiftMinGap     = 60 * time.Second
	// NTSShiftStartRetry is the gap before the first quorum of a run for an
	// operator that has not answered yet (and sent no RATE). The start
	// round asks every operator; without this a failed start round (a
	// relay that comes up late) would be retried only after 60 s, once in
	// the runner's start wait. After the first quorum it is the wait of
	// the one retry of a lost answer that found no fallback.
	NTSShiftStartRetry   = 20 * time.Second
	NTSShiftLength       = 15 * time.Minute
	NTSShiftMaxAge       = 90 * time.Second
	NTSShiftQueryTimeout = time.Second
	NTSShiftStartDelay   = 10 * time.Second
	// NTSShiftBurstBelow: fewer fresh samples than this start a burst. At
	// 3 fresh all 3 must agree (nts.QuorumWrong), so one wrong operator
	// would stop the quorum in the gap after a handover; the burst fills it.
	// A set under NTSShiftMinServers has every operator on the grid, so a
	// burst finds no one past the gap; there the retry of a lost answer
	// (NTSShiftStartRetry) fills the gap.
	NTSShiftBurstBelow = 4
	// NTSShiftFallbackCap caps the fallbacks and retries of lost answers
	// per hour. A host that drops answers of actives can force them; past
	// the cap a lost answer waits for the operator's next slot. In a
	// simulation, 30 % loss everywhere needed about 65 per hour.
	NTSShiftFallbackCap = 120
	// NTSShiftBurstCap caps the burst contacts per hour, on their own: a
	// shared cap let bursts use up the fallbacks two down actives of 7
	// operators need (5.7 % blocked in the simulation, against none).
	NTSShiftBurstCap = 120
	// ntsShiftMaxGap caps the gap a RATE raises an operator to (NTSMaxPoll).
	ntsShiftMaxGap = 1024 * time.Second
)

type ntsRole uint8

const (
	roleStart ntsRole = iota
	roleActive
	roleFallback
	roleBurst
	// roleRetry asks an active again NTSShiftStartRetry after its lost
	// answer, when no fallback could be asked.
	roleRetry
)

type ntsAsk struct {
	op   int
	role ntsRole
}

// never is the last tick of an operator not yet asked.
const never = -1 << 40

type ntsShifts struct {
	mu         sync.Mutex
	tickNs     int64
	actives    int // active slots
	gap        int // base ticks between two contacts with one operator
	retry      int // ticks of NTSShiftStartRetry
	maxGap     int // the most a RATE raises an operator's gap to
	shiftLen   int // ticks per shift
	hour       int // ticks per hour, the window of NTSShiftFallbackCap
	order      []int
	phase      int // tick of slot 0 on the grid, 0 to gap-1
	shift0     int // ticks added before dividing into shifts
	startDelay time.Duration
	rnd        *rand.Rand
	seed       []byte // of the order; swap draws the order again from it
	seeded     bool

	started  bool
	warm     bool  // a quorum formed in this run
	t0       int64 // local ns of the start round
	q        int   // the current tick
	shift    int   // shifts done
	slots    []int
	last     []int  // tick of the last contact
	gaps     []int  // minimum gap per operator, in ticks
	incoming []bool // came in at a handover, no answer since
	missed   []bool // asked and got no answer (start retries)
	retryAt  []int  // tick of the retry of a lost answer, never for none
	counts   []NTSOperatorCounts
	// fallbackAt holds the ticks of the fallbacks of the last hour; capped
	// counts the fallbacks the cap refused.
	fallbackAt []int
	capped     int64
	// burstAt holds the ticks of the burst contacts of the last hour.
	burstAt []int
}

// newNTSShifts: n operators, a tick of tick. seed nil: a random seed for
// the phase and the start delay, and every operator active until
// reseed. The seed should be fixed per signer, the same after a restart,
// and unknown to the host (the runner derives it from the released key),
// so the order cannot be computed ahead from public data. It does not keep
// the order from a host that watches: one cycle of NTS-KE and NTP traffic
// shows it, and every start begins at the same window, so a host that
// restarts the signer can keep the first window active. That gives it no
// more than dropping answers already does.
func newNTSShifts(n int, seed []byte, tick time.Duration) *ntsShifts {
	ceilTicks := func(d time.Duration) int { return int((d + tick - 1) / tick) }
	s := &ntsShifts{
		tickNs:   int64(tick),
		gap:      ceilTicks(NTSShiftMinGap),
		retry:    ceilTicks(NTSShiftStartRetry),
		maxGap:   ceilTicks(ntsShiftMaxGap),
		shiftLen: ceilTicks(NTSShiftLength),
		hour:     ceilTicks(time.Hour),
		last:     make([]int, n),
		gaps:     make([]int, n),
		incoming: make([]bool, n),
		missed:   make([]bool, n),
		retryAt:  make([]int, n),
		counts:   make([]NTSOperatorCounts, n),
	}
	for i := range s.last {
		s.last[i], s.gaps[i], s.retryAt[i] = never, s.gap, never
	}
	if seed == nil {
		seed = make([]byte, 32)
		_, _ = crand.Read(seed)
		s.setOrder(seed, n)
	} else {
		s.setOrder(seed, n)
		s.seeded = true
		s.actives = ShiftActives(n)
		s.setSlots()
	}
	s.startDelay = time.Duration(s.rnd.Int64N(int64(NTSShiftStartDelay) + 1))
	return s
}

// ShiftActives is how many of n operators are active under a seeded
// schedule: NTSShiftActives, but never fewer than NTSShiftSpares left over
// (4 of 7, 5 of 8 or more). Below NTSShiftMinServers every operator is
// active, each once per NTSShiftMinGap, and nothing hands over: a small set
// (a region with few close operators) keeps all its servers in the quorum
// and asks each no more often than a shift does.
func ShiftActives(n int) int {
	if n < NTSShiftMinServers {
		return n
	}
	return min(NTSShiftActives, n-NTSShiftSpares)
}

// setOrder draws the order, the grid phase and the shift phase from seed,
// with every operator active.
func (s *ntsShifts) setOrder(seed []byte, n int) {
	s.seed = seed
	s.rnd = rand.New(rand.NewChaCha8(sha256.Sum256(seed)))
	s.order = s.rnd.Perm(n)
	s.phase = s.rnd.IntN(s.gap)
	s.shift0 = s.rnd.IntN(s.shiftLen)
	s.actives = n
	s.setSlots()
}

// setSlots puts the window of the current shift in the slots.
func (s *ntsShifts) setSlots() {
	c := len(s.order)
	s.shift = (s.q + s.shift0) / s.shiftLen
	s.slots = make([]int, s.actives)
	for k := range s.slots {
		s.slots[k] = s.order[(s.shift+k)%c]
	}
}

// reseed switches to shifts with the order and phase from seed. Contacts
// made so far keep their gaps, so the first slot of the new grid that is
// at least a gap after an operator's last contact is its next one.
func (s *ntsShifts) reseed(seed []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setOrder(seed, len(s.last))
	s.actives = ShiftActives(len(s.last))
	s.setSlots()
	clear(s.incoming)
	s.seeded = true
}

// ntsShiftState is what a swap carries of one operator's schedule when its
// peer goes: the last contact and gap in ticks, and its RATE answers (a
// RATE before the first quorum rules out the start retry).
type ntsShiftState struct {
	last, gap int
	rates     int64
}

// state returns operator op's schedule state, for a swap that removes it.
func (s *ntsShifts) state(op int) ntsShiftState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return ntsShiftState{s.last[op], s.gaps[op], s.counts[op].Rates}
}

// cold puts the schedule back in its start state (no quorum yet in this
// run): an operator that missed its last contact may be asked again after
// NTSShiftStartRetry until the next quorum.
func (s *ntsShifts) cold() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.warm = false
}

// swap moves the schedule to a new operator set: keep[i] is the old index
// of new operator i, or -1. Operators kept keep their last contact, gap,
// missed flag, pending retry of a lost answer and counts. A new operator with carry[i] set (one the
// clock knew before, by label or by host) starts from that last contact,
// gap and RATE count; one without has no last contact, so the next plan
// asks it. The order and the slots are drawn again from the same seed for
// the new count; the grid and shift phases stay, so the slots of the
// operators that stay active move as little as the new order allows. The
// handover position starts over: no incoming carries over.
func (s *ntsShifts) swap(keep []int, carry []*ntsShiftState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(keep)
	last, gaps := make([]int, n), make([]int, n)
	missed, counts := make([]bool, n), make([]NTSOperatorCounts, n)
	retryAt := make([]int, n)
	for i, j := range keep {
		retryAt[i] = never
		switch {
		case j >= 0:
			last[i], gaps[i], missed[i], counts[i] = s.last[j], s.gaps[j], s.missed[j], s.counts[j]
			retryAt[i] = s.retryAt[j]
		case carry[i] != nil:
			last[i], gaps[i] = carry[i].last, max(carry[i].gap, s.gap)
			counts[i].Rates = carry[i].rates
		default:
			last[i], gaps[i] = never, s.gap
		}
	}
	s.last, s.gaps, s.missed, s.counts, s.retryAt = last, gaps, missed, counts, retryAt
	s.incoming = make([]bool, n)
	phase, shift0 := s.phase, s.shift0
	s.setOrder(s.seed, n)
	s.phase, s.shift0 = phase, shift0
	if s.seeded {
		s.actives = ShiftActives(n)
	}
	s.setSlots()
}

func mod(a, m int) int { return (a%m + m) % m }

// idle moves time on without queries (no coarse time).
func (s *ntsShifts) idle(now int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tick(now)
}

// tick moves to the tick of local time now: one more than the last, or
// the whole ticks since the start round if that is more, but never more
// than one tick ahead of local time. Calls that come faster than a tick
// (a Run whose ticker fired during the start delay) then do not move the
// schedule ahead of local time, where waitGap would refuse its contacts.
func (s *ntsShifts) tick(now int64) {
	if !s.started {
		return
	}
	e := int((now - s.t0) / s.tickNs)
	s.q = max(s.q, min(max(s.q+1, e), e+1))
	s.handover()
}

// plan starts a tick at local time now and returns the operators to ask at
// its start. can says by operator whether a contact would send anything
// (NTS.askable; nil: all); a retry of a lost answer goes out only then.
func (s *ntsShifts) plan(now int64, can []bool) []ntsAsk {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []ntsAsk
	if !s.started {
		s.started, s.t0 = true, now
		for op := range s.last {
			s.mark(op, s.q)
			out = append(out, ntsAsk{op, roleStart})
		}
		return out
	}
	s.tick(now)
	for k, op := range s.slots {
		if s.q >= s.due(k, op) {
			s.mark(op, s.q)
			out = append(out, ntsAsk{op, roleActive})
		}
	}
	// An operator a swap added gets its start-round contact now, active
	// or not. Those with a slot were asked just above.
	for op, l := range s.last {
		if l == never {
			s.mark(op, s.q)
			out = append(out, ntsAsk{op, roleStart})
		}
	}
	for op, at := range s.retryAt {
		if at == never || s.q < at {
			continue
		}
		s.retryAt[op] = never
		// Dropped, with no query and no count: a retry more than a tick
		// late (no Refresh in between), one within NTSShiftStartRetry of
		// the operator's next slot, one to an operator that cannot be asked
		// now, and one past the cap.
		if s.q > at+1 || s.last[op] == s.q || (can != nil && !can[op]) {
			continue
		}
		if k := slices.Index(s.slots, op); k >= 0 && s.due(k, op)-s.q < s.retry {
			continue
		}
		if s.capFull() {
			s.capped++
			continue
		}
		// Not marked: the next slot stays a gap after the lost contact.
		s.fallbackAt = append(s.fallbackAt, s.q)
		out = append(out, ntsAsk{op, roleRetry})
	}
	return out
}

// due is the tick slot k's operator is next asked at: its slot on the grid,
// at least its gap after its last contact.
func (s *ntsShifts) due(k, op int) int {
	if s.last[op] == never {
		return s.q
	}
	g := s.phase + k*s.gap/s.actives
	from := s.last[op] + s.gapOf(op)
	return from + mod(g-from, s.gap)
}

// handover moves the window of actives to the current shift, one place per
// shift. The outgoing leaves now; the incoming takes its slot.
func (s *ntsShifts) handover() {
	c := len(s.order)
	if c <= s.actives {
		return
	}
	for want := (s.q + s.shift0) / s.shiftLen; s.shift < want; s.shift++ {
		out := s.order[s.shift%c]
		in := s.order[(s.shift+s.actives)%c]
		s.slots[slices.Index(s.slots, out)] = in
		s.incoming[in] = true
		s.counts[in].Handovers++
	}
}

// mark records a contact with op as made at tick at. A contact made after
// the start of the tick (a fallback or a burst) is marked at a later tick
// (see after), so the next contact is still a gap after it. Queries counts
// it in result, once a request went out.
func (s *ntsShifts) mark(op, at int) {
	s.last[op] = at
}

func (s *ntsShifts) eligible(op int) bool {
	return s.last[op] == never || s.q-s.last[op] >= s.gapOf(op)
}

// gapOf is op's minimum gap in ticks: NTSShiftStartRetry before the first
// quorum for an operator that was asked, has not answered and sent no RATE,
// else its gap.
func (s *ntsShifts) gapOf(op int) int {
	if s.startRetry(op) {
		return s.retry
	}
	return s.gaps[op]
}

func (s *ntsShifts) startRetry(op int) bool {
	return !s.warm && s.missed[op] && s.counts[op].Answers == 0 && s.counts[op].Rates == 0
}

// minGap is op's minimum gap in local time, for NTS.waitGap.
func (s *ntsShifts) minGap(op int) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.startRetry(op) {
		return NTSShiftStartRetry
	}
	return NTSShiftMinGap
}

// quorum records that a quorum formed: from now on every gap is the full one.
func (s *ntsShifts) quorum() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.warm = true
}

// result records the answer (or not) of a contact. sent: a request went
// out (Queries and Retries count only those). rate: the answer was a
// Kiss-o'-Death RATE, which doubles the operator's gap; an answer halves it
// back towards the base. wide: an answer too wide to use; it counts as a
// loss, but the operator did answer, so it gets no start retry.
func (s *ntsShifts) result(a ntsAsk, ok, rate, wide, sent bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := &s.counts[a.op]
	if sent {
		c.Queries++
		if a.role == roleRetry {
			c.Retries++
		}
	}
	switch {
	case ok:
		c.Answers++
		s.gaps[a.op] = max(s.gaps[a.op]/2, s.gap)
	case rate:
		c.Losses++
		c.Rates++
		s.gaps[a.op] = min(2*s.gaps[a.op], s.maxGap)
		if a.role == roleRetry {
			// The doubled gap runs from this contact, not the lost one.
			s.last[a.op] = max(s.last[a.op], s.q)
		}
	default:
		c.Losses++
	}
	s.missed[a.op] = !ok && !wide
	if s.incoming[a.op] {
		s.incoming[a.op] = false
		if !ok {
			c.FailedHandovers++
		}
	}
}

// capFull drops the fallbacks and retries older than an hour and says
// whether NTSShiftFallbackCap of them are left.
func (s *ntsShifts) capFull() bool {
	s.fallbackAt = s.lastHour(s.fallbackAt)
	return len(s.fallbackAt) >= NTSShiftFallbackCap
}

// lastHour is at without the ticks over an hour old.
func (s *ntsShifts) lastHour(at []int) []int {
	i := 0
	for i < len(at) && s.q-at[i] >= s.hour {
		i++
	}
	return at[i:]
}

// fallback picks a random non-active operator past its gap that can be
// asked now (can, by operator: not stopped by DENY or RSTR, not waiting
// out an NTS-KE backoff), for a contact after ticks after the start of
// this tick (at least 1), for the active lost whose answer was lost. None once
// NTSShiftFallbackCap fallbacks and retries went out in the last hour. If there is no such operator and retry is set (the lost
// contact sent a request and got no answer, no RATE, no wide answer), lost
// is booked to be asked again NTSShiftStartRetry later (plan): once, after
// the first quorum only, while it can be asked and its gap is the base one
// (no RATE backoff). The retry counts toward the cap when it goes out.
func (s *ntsShifts) fallback(lost, after int, retry bool, can []bool) (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.capFull() {
		s.capped++
		return 0, false
	}
	var cand []int
	for op := range s.last {
		if !slices.Contains(s.slots, op) && s.eligible(op) && can[op] {
			cand = append(cand, op)
		}
	}
	if len(cand) == 0 {
		if retry && s.warm && s.retryAt[lost] == never && can[lost] && s.gaps[lost] == s.gap {
			s.retryAt[lost] = s.last[lost] + s.retry
		}
		return 0, false
	}
	op := cand[s.rnd.IntN(len(cand))]
	s.mark(op, s.q+after)
	s.counts[op].Fallbacks++
	s.fallbackAt = append(s.fallbackAt, s.q)
	return op, true
}

// fallbackKE counts a fallback to op that had to run NTS-KE first.
func (s *ntsShifts) fallbackKE(op int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counts[op].FallbackKE++
}

// burst returns every operator past its gap that can be asked now (can,
// as for fallback), for a contact after ticks after the start of this
// tick (at least 1). Each burst contact counts toward NTSShiftBurstCap, and
// a burst stops when it is reached: a host that keeps the fresh samples low
// by dropping answers then gets no more than that many burst queries per
// hour out of the clock.
func (s *ntsShifts) burst(after int, can []bool) []ntsAsk {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.burstAt = s.lastHour(s.burstAt)
	var out []ntsAsk
	for op := range s.last {
		if s.eligible(op) && can[op] {
			if len(s.burstAt) >= NTSShiftBurstCap {
				break
			}
			s.burstAt = append(s.burstAt, s.q)
			s.mark(op, s.q+after)
			s.counts[op].Bursts++
			out = append(out, ntsAsk{op, roleBurst})
		}
	}
	return out
}

// snapshot returns the active operators, the counts by operator name and
// the fallbacks the cap refused.
func (s *ntsShifts) snapshot(names []string) ([]string, map[string]NTSOperatorCounts, int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	act := make([]string, len(s.slots))
	for k, op := range s.slots {
		act[k] = names[op]
	}
	m := make(map[string]NTSOperatorCounts, len(names))
	for op, c := range s.counts {
		m[names[op]] = c
	}
	return act, m, s.capped
}
