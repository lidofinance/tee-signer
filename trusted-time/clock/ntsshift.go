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
//     NTSShiftFallbackCap per hour.
//   - With fewer than NTSShiftBurstBelow fresh samples after the tick's
//     queries, every operator past its minimum gap is asked.
//   - Each operator's minimum gap is NTSShiftMinGap; a Kiss-o'-Death RATE
//     doubles it (up to 1024 s), each answer halves it back.
//   - Two contacts with one operator start at least its gap apart (see
//     mark, and NTS.waitGap for the strict 60 s in local time). A contact
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
	NTSShiftMinServers   = 4 + NTSShiftSpares
	NTSShiftMinGap       = 60 * time.Second
	NTSShiftLength       = 15 * time.Minute
	NTSShiftMaxAge       = 90 * time.Second
	NTSShiftQueryTimeout = time.Second
	NTSShiftStartDelay   = 10 * time.Second
	// NTSShiftBurstBelow: fewer fresh samples than this start a burst. At
	// 3 fresh all 3 must agree (nts.QuorumWrong), so one wrong operator
	// would stop the quorum in the gap after a handover; the burst fills it.
	NTSShiftBurstBelow = 4
	// NTSShiftFallbackCap caps the fallbacks per hour. A host that drops
	// answers of actives can force fallbacks; past the cap a lost answer
	// waits for the operator's next slot. In a simulation, 30 % loss
	// everywhere needed about 65 per hour.
	NTSShiftFallbackCap = 120
	// ntsShiftMaxGap caps the gap a RATE raises an operator to (NTSMaxPoll).
	ntsShiftMaxGap = 1024 * time.Second
)

type ntsRole uint8

const (
	roleStart ntsRole = iota
	roleActive
	roleFallback
	roleBurst
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
	maxGap     int // the most a RATE raises an operator's gap to
	shiftLen   int // ticks per shift
	hour       int // ticks per hour, the window of NTSShiftFallbackCap
	order      []int
	phase      int // tick of slot 0 on the grid, 0 to gap-1
	shift0     int // ticks added before dividing into shifts
	startDelay time.Duration
	rnd        *rand.Rand
	seeded     bool

	started  bool
	t0       int64 // local ns of the start round
	q        int   // the current tick
	shift    int   // shifts done
	slots    []int
	last     []int  // tick of the last contact
	gaps     []int  // minimum gap per operator, in ticks
	incoming []bool // came in at a handover, no answer since
	counts   []NTSOperatorCounts
	// fallbackAt holds the ticks of the fallbacks of the last hour; capped
	// counts the fallbacks the cap refused.
	fallbackAt []int
	capped     int64
}

// newNTSShifts: n operators, a tick of tick. seed nil: a random seed for
// the phase and the start delay, and every operator active until
// reseed. The seed should be fixed per signer, the same after a restart,
// and unknown to the host (the runner derives it from the released key).
func newNTSShifts(n int, seed []byte, tick time.Duration) *ntsShifts {
	ceilTicks := func(d time.Duration) int { return int((d + tick - 1) / tick) }
	s := &ntsShifts{
		tickNs:   int64(tick),
		gap:      ceilTicks(NTSShiftMinGap),
		maxGap:   ceilTicks(ntsShiftMaxGap),
		shiftLen: ceilTicks(NTSShiftLength),
		hour:     ceilTicks(time.Hour),
		last:     make([]int, n),
		gaps:     make([]int, n),
		incoming: make([]bool, n),
		counts:   make([]NTSOperatorCounts, n),
	}
	for i := range s.last {
		s.last[i], s.gaps[i] = never, s.gap
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

func mod(a, m int) int { return (a%m + m) % m }

// idle moves time on without queries (no coarse time).
func (s *ntsShifts) idle(now int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tick(now)
}

// tick moves to the tick of local time now: one more than the last, or
// the whole ticks since the start round if that is more.
func (s *ntsShifts) tick(now int64) {
	if !s.started {
		return
	}
	s.q = max(s.q+1, int((now-s.t0)/s.tickNs))
	s.handover()
}

// plan starts a tick at local time now and returns the operators to ask at
// its start.
func (s *ntsShifts) plan(now int64) []ntsAsk {
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
	return out
}

// due is the tick slot k's operator is next asked at: its slot on the grid,
// at least its gap after its last contact.
func (s *ntsShifts) due(k, op int) int {
	if s.last[op] == never {
		return s.q
	}
	g := s.phase + k*s.gap/s.actives
	from := s.last[op] + s.gaps[op]
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
// (see after), so the next contact is still a gap after it.
func (s *ntsShifts) mark(op, at int) {
	s.last[op] = at
	s.counts[op].Queries++
}

func (s *ntsShifts) eligible(op int) bool {
	return s.last[op] == never || s.q-s.last[op] >= s.gaps[op]
}

// result records the answer (or not) of a contact. rate: the answer was a
// Kiss-o'-Death RATE, which doubles the operator's gap; an answer halves it
// back towards the base.
func (s *ntsShifts) result(a ntsAsk, ok, rate bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := &s.counts[a.op]
	switch {
	case ok:
		c.Answers++
		s.gaps[a.op] = max(s.gaps[a.op]/2, s.gap)
	case rate:
		c.Losses++
		c.Rates++
		s.gaps[a.op] = min(2*s.gaps[a.op], s.maxGap)
	default:
		c.Losses++
	}
	if s.incoming[a.op] {
		s.incoming[a.op] = false
		if !ok {
			c.FailedHandovers++
		}
	}
}

// fallback picks a random non-active operator past its gap, for a contact
// after ticks after the start of this tick (at least 1). None once
// NTSShiftFallbackCap fallbacks went out in the last hour.
func (s *ntsShifts) fallback(after int) (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := 0
	for i < len(s.fallbackAt) && s.q-s.fallbackAt[i] >= s.hour {
		i++
	}
	s.fallbackAt = s.fallbackAt[i:]
	if len(s.fallbackAt) >= NTSShiftFallbackCap {
		s.capped++
		return 0, false
	}
	var cand []int
	for op := range s.last {
		if !slices.Contains(s.slots, op) && s.eligible(op) {
			cand = append(cand, op)
		}
	}
	if len(cand) == 0 {
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

// burst returns every operator past its gap, for a contact after ticks
// after the start of this tick (at least 1).
func (s *ntsShifts) burst(after int) []ntsAsk {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []ntsAsk
	for op := range s.last {
		if s.eligible(op) {
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
