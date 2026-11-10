//go:build nts

package clock

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"math"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/trusted-time/nts"
)

// shiftWorld is a fake world for the shift schedule: a local clock the test
// moves, NTS servers that answer, lose or lie, and a coarse clock that reads
// every 15 s and gives no time 75 s after its last reading (Anchored).
type shiftWorld struct {
	mu       sync.Mutex
	now      int64 // local ns
	tickAt   int64 // local ns of the running tick
	off      int64 // real minus local
	seed     uint64
	loss     map[string]float64
	down     map[string]bool
	wrong    map[string]time.Duration
	blipFrom int64 // no answers and no coarse readings in [blipFrom, blipTo)
	blipTo   int64
	ntsOnly  bool // the blip stops NTS answers only, not coarse readings
	contacts map[string][]int64
	// downUntil: no answers before this local time; rateUntil: a
	// Kiss-o'-Death RATE before this local time.
	downUntil map[string]int64
	rateUntil map[string]int64
}

func (w *shiftWorld) local() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.now
}

func (w *shiftWorld) inBlip(t int64) bool { return t >= w.blipFrom && t < w.blipTo }

// draw is a number in [0, 1) fixed by the seed, the operator and the time,
// so a run does not depend on the order of the goroutines.
func (w *shiftWorld) draw(op string, t int64) float64 {
	h := fnv.New64a()
	fmt.Fprintf(h, "%d/%s/%d", w.seed, op, t)
	return float64(h.Sum64()>>11) / (1 << 53)
}

// query plays one exchange. A lost answer costs the 1 s timeout: whatever
// the clock does next in this tick happens after it.
func (w *shiftWorld) query(op string, t int64) (nts.Sample, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.contacts[op] = append(w.contacts[op], t)
	if t < w.rateUntil[op] {
		return nts.Sample{}, &nts.KissError{Code: "RATE"}
	}
	if w.inBlip(t) || w.down[op] || t < w.downUntil[op] || w.draw(op, t) < w.loss[op] {
		w.now = max(w.now, t+int64(NTSShiftQueryTimeout))
		return nts.Sample{}, errors.New("timeout")
	}
	return nts.Sample{Offset: w.off + int64(w.wrong[op]), Bound: 15 * time.Millisecond, Delay: 30 * time.Millisecond, T4: t}, nil
}

func (w *shiftWorld) Now() (time.Time, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	t := w.now
	const every = int64(15 * time.Second)
	m := t - t%every
	for m >= 0 && w.inBlip(m) && !w.ntsOnly {
		m -= every
	}
	if m < 0 || t-m >= int64(75*time.Second) {
		return time.Time{}, errors.New("coarse: no reading")
	}
	return time.Unix(0, t+w.off), nil
}

// shiftBase is local time at the start of a run: a sample at local 0 would
// not be newer than the drift check's refusedT4 (0).
const shiftBase = time.Hour

type shiftScenario struct {
	name     string
	catalog  int
	dur      time.Duration
	from, to time.Duration // the window that counts
	seed     uint64
	// Operators by place in the signer's order (0 to 4 are the first
	// actives).
	loss    float64 // every operator
	lossy   []int   // these lose half their answers
	down    []int
	wrong   map[int]time.Duration
	blipAt  time.Duration
	blipLen time.Duration
	ntsOnly bool
	// At jumpAt the local counter steps ahead by jump (a host that sets
	// it): real time minus local time drops by jump.
	jumpAt, jump time.Duration
}

type shiftResult struct {
	blocked, longest  time.Duration
	window            time.Duration
	queriesPerHour    float64
	opMax, opMin      float64 // per operator per hour
	minGap            time.Duration
	minGapOp          string
	counts            NTSOperatorCounts // summed over operators
	idleMax           time.Duration     // longest time an operator went without contact
	firstQuorumAfter  time.Duration
	firstQuorumMember int
	// startBursts are the burst queries of the first shiftStartWindow: the
	// start samples age out (joinAge) before every active reaches its first
	// slot, which can be up to 2 x NTSShiftMinGap after the start round.
	startBursts int64
	// maxLead is the most the served time led real time beyond its bound;
	// leadFor the seconds it led beyond its bound.
	maxLead time.Duration
	leadFor time.Duration
	rho     int64 // drift refusals
}

const shiftStartWindow = 2*NTSShiftMinGap + testTick

func sumBursts(n *NTS) (b int64) {
	for _, c := range n.NTSSummary().Operators {
		b += c.Bursts
	}
	return b
}

func (r shiftResult) blockedPct() float64 { return 100 * float64(r.blocked) / float64(r.window) }

func runShiftScenario(t testing.TB, sc shiftScenario) shiftResult {
	t.Helper()
	w := &shiftWorld{off: 1_800_000_000 * int64(time.Second), seed: sc.seed, loss: map[string]float64{}, down: map[string]bool{},
		wrong: map[string]time.Duration{}, contacts: map[string][]int64{}}
	n := &NTS{Coarse: w, Local: w.local, ScheduleSeed: fmt.Appendf(nil, "signer-%d", sc.seed), testQuery: w.queryCtx, noStartDelay: true}
	for i := range sc.catalog {
		n.Servers = append(n.Servers, NTSServer{Host: fmt.Sprintf("op%d.test", i), Operator: fmt.Sprintf("op%d", i)})
	}
	n.init()
	name := func(place int) string { return n.Servers[n.shifts.order[place%sc.catalog]].Operator }
	for i := range sc.catalog {
		w.loss[name(i)] = sc.loss
	}
	for _, p := range sc.lossy {
		w.loss[name(p)] = 0.5
	}
	for _, p := range sc.down {
		w.down[name(p)] = true
	}
	for p, d := range sc.wrong {
		w.wrong[name(p)] = d
	}
	if sc.blipLen > 0 {
		w.blipFrom, w.blipTo = int64(shiftBase+sc.blipAt), int64(shiftBase+sc.blipAt+sc.blipLen)
		w.ntsOnly = sc.ntsOnly
	}
	to := sc.to
	if to == 0 {
		to = sc.dur
	}
	var res shiftResult
	var cur time.Duration
	ctx := context.Background()
	for sec := time.Duration(0); sec < sc.dur; sec += time.Second {
		w.mu.Lock()
		w.now = max(w.now, int64(shiftBase+sec))
		if sc.jump != 0 && sec == sc.jumpAt {
			w.off -= int64(sc.jump)
		}
		tick := sec%testTick == 0
		if tick {
			w.tickAt = w.now
		}
		w.mu.Unlock()
		if tick {
			_ = n.Refresh(ctx)
		}
		if sec == shiftStartWindow {
			res.startBursts = sumBursts(n)
		}
		got, bound, err := n.Bounded()
		if err == nil {
			w.mu.Lock()
			real := time.Unix(0, w.now+w.off)
			w.mu.Unlock()
			if lead := got.Sub(real) - bound; lead > 0 {
				res.maxLead = max(res.maxLead, lead)
				res.leadFor += time.Second
			}
		}
		if err == nil && res.firstQuorumAfter == 0 {
			res.firstQuorumAfter = sec + time.Nanosecond // 0 means none yet
			res.firstQuorumMember = len(n.NTSSummary().Members)
		}
		if sec < sc.from || sec >= to {
			continue
		}
		if err != nil {
			res.blocked += time.Second
			cur += time.Second
			res.longest = max(res.longest, cur)
		} else {
			cur = 0
		}
	}
	res.window = to - sc.from
	hours := sc.dur.Hours()
	res.minGap, res.opMin = time.Duration(math.MaxInt64), math.Inf(1)
	total := 0
	for op, cs := range w.contacts {
		total += len(cs)
		ph := float64(len(cs)) / hours
		res.opMax, res.opMin = max(res.opMax, ph), min(res.opMin, ph)
		for i := 1; i < len(cs); i++ {
			if d := time.Duration(cs[i] - cs[i-1]); d < res.minGap {
				res.minGap, res.minGapOp = d, op
			}
			res.idleMax = max(res.idleMax, time.Duration(cs[i]-cs[i-1]))
		}
	}
	res.queriesPerHour = float64(total) / hours
	res.rho = n.NTSSummary().RhoViolations
	for _, c := range n.NTSSummary().Operators {
		res.counts.Queries += c.Queries
		res.counts.Answers += c.Answers
		res.counts.Losses += c.Losses
		res.counts.Fallbacks += c.Fallbacks
		res.counts.Bursts += c.Bursts
		res.counts.Handovers += c.Handovers
		res.counts.FailedHandovers += c.FailedHandovers
	}
	if res.counts.Queries != int64(total) {
		t.Fatalf("%s: schedule counted %d queries, the servers saw %d", sc.name, res.counts.Queries, total)
	}
	return res
}

// The scenarios of the design reviews: 8 operators (5 active), 15 min
// shifts, 90 s cap; counted from 20 min.
func reviewScenarios(dur time.Duration, seed uint64) []shiftScenario {
	return reviewScenariosN(dur, seed, 8)
}

// reviewScenariosN: the same scenarios with catalog operators.
func reviewScenariosN(dur time.Duration, seed uint64, catalog int) []shiftScenario {
	base := shiftScenario{catalog: catalog, dur: dur, from: 20 * time.Minute, seed: seed}
	with := func(name string, f func(*shiftScenario)) shiftScenario {
		s := base
		s.name = name
		f(&s)
		return s
	}
	return []shiftScenario{
		with("healthy", func(*shiftScenario) {}),
		with("30% loss everywhere", func(s *shiftScenario) { s.loss = 0.3 }),
		with("one active at 50% loss", func(s *shiftScenario) { s.lossy = []int{0} }),
		with("two actives down", func(s *shiftScenario) { s.down = []int{0, 1} }),
		with("one operator wrong", func(s *shiftScenario) { s.wrong = map[int]time.Duration{2: time.Second} }),
		with("two wrong (smear plus one)", func(s *shiftScenario) {
			s.wrong = map[int]time.Duration{2: time.Second, 5: -time.Second}
		}),
	}
}

func blipScenario(seed uint64) shiftScenario {
	return shiftScenario{name: "5-minute blip", catalog: 8, dur: 12000 * time.Second, from: 9000 * time.Second, to: 12000 * time.Second,
		blipAt: 10000 * time.Second, blipLen: 300 * time.Second, seed: seed}
}

func checkMinGap(t *testing.T, name string, r shiftResult) {
	t.Helper()
	if r.minGap < NTSShiftMinGap {
		t.Fatalf("%s: %s contacted twice %v apart", name, r.minGapOp, r.minGap)
	}
}

// Short runs of the scenarios that must never block, and the 60 s minimum
// in local time (the fallback goes out 1 s into the tick).
func TestNTSShiftScenariosShort(t *testing.T) {
	for _, sc := range reviewScenarios(2*time.Hour, 1) {
		r := runShiftScenario(t, sc)
		checkMinGap(t, sc.name, r)
		t.Logf("%s: blocked %v (%.3f%%), longest %v, %.1f q/h, %+v", sc.name, r.blocked, r.blockedPct(), r.longest, r.queriesPerHour, r.counts)
		switch sc.name {
		case "healthy", "one active at 50% loss", "two actives down", "one operator wrong":
			if r.blocked != 0 {
				t.Errorf("%s: blocked %v", sc.name, r.blocked)
			}
		}
		// A healthy run bursts at most at the start dip.
		if sc.name == "healthy" && (r.queriesPerHour < 295 || r.queriesPerHour > 310 || r.counts.Fallbacks != 0 || r.counts.Bursts != r.startBursts) {
			t.Errorf("healthy: %.1f q/h, %+v", r.queriesPerHour, r.counts)
		}
	}
}

// Start: the first tick asks all 8 and the first quorum has all 8.
func TestNTSShiftStartQuorumFromAll(t *testing.T) {
	r := runShiftScenario(t, shiftScenario{name: "start", catalog: 8, dur: 10 * time.Minute, seed: 3})
	if r.firstQuorumAfter != time.Nanosecond || r.firstQuorumMember != 8 {
		t.Fatalf("first quorum after %v with %d members", r.firstQuorumAfter, r.firstQuorumMember)
	}
	checkMinGap(t, "start", r)
}

// A 5-minute blip: coarse is out from about 75 s into it until its first
// reading after it. Every active is overdue then and asked at the first
// tick, so the quorum is back in one tick; no burst is needed.
func TestNTSShiftBlipRecovers(t *testing.T) {
	r := runShiftScenario(t, blipScenario(1))
	checkMinGap(t, "blip", r)
	if r.blocked >= 300*time.Second {
		t.Fatalf("blip: blocked %v, %+v", r.blocked, r.counts)
	}
}

// An NTS-only outage (UDP blocked, coarse fine) of 3 minutes: the clock
// keeps asking, falls below 3 fresh samples and bursts. After the outage
// it is back once 3 operators not asked in the last 60 s have answered:
// up to 60 s, since the bursts asked every operator during the outage.
func TestNTSShiftBurstAfterNTSOutage(t *testing.T) {
	sc := shiftScenario{name: "nts outage", catalog: 8, dur: 30 * time.Minute, from: 10 * time.Minute, to: 30 * time.Minute,
		blipAt: 15 * time.Minute, blipLen: 3 * time.Minute, ntsOnly: true, seed: 4}
	r := runShiftScenario(t, sc)
	checkMinGap(t, sc.name, r)
	if r.counts.Bursts == 0 || r.blocked >= sc.blipLen {
		t.Fatalf("nts outage: blocked %v, %+v", r.blocked, r.counts)
	}
	t.Logf("nts outage 180 s: blocked %v, longest %v, %+v", r.blocked, r.longest, r.counts)
}

// Property: the 60 s minimum holds in local time over random runs with
// random loss, dead operators and blips.
func TestNTSShiftMinGapPropertyLocalTime(t *testing.T) {
	for run := range 12 {
		seed := uint64(100 + run)
		sc := shiftScenario{name: fmt.Sprintf("random %d", run), catalog: 3 + run%10, dur: time.Hour, seed: seed,
			loss: float64(run%5) / 5, down: []int{run % 4}}
		if run%3 == 0 {
			sc.blipAt, sc.blipLen = 20*time.Minute, time.Duration(30+run*20)*time.Second
		}
		r := runShiftScenario(t, sc)
		checkMinGap(t, sc.name, r)
	}
}

// The scenario table: blocked share, gaps and load per scenario (10 seeds
// of 6 h, blip 6 seeds). Long: run with NTS_SHIFT_SIM=1.
func TestNTSShiftScenarioTable(t *testing.T) {
	if os.Getenv("NTS_SHIFT_SIM") == "" {
		t.Skip("NTS_SHIFT_SIM not set")
	}
	var out strings.Builder
	fmt.Fprintf(&out, "| Scenario | Blocked | Longest gap | Queries/h | Per op/h min-max | Fallbacks/h | Bursts/h | Handovers/h | Failed handovers | Min gap | Longest idle |\n")
	fmt.Fprintf(&out, "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n")
	seeds := []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	for _, sc0 := range reviewScenarios(6*time.Hour, 0) {
		var rs []shiftResult
		for _, s := range seeds {
			sc := sc0
			sc.seed = s
			r := runShiftScenario(t, sc)
			checkMinGap(t, sc.name, r)
			rs = append(rs, r)
		}
		var pct, qh, fb, bu, ho, opMin, opMax float64
		var fho int64
		var longest, idle time.Duration
		minGap := time.Duration(math.MaxInt64)
		opMin = math.Inf(1)
		for _, r := range rs {
			pct += r.blockedPct() / float64(len(rs))
			qh += r.queriesPerHour / float64(len(rs))
			fb += float64(r.counts.Fallbacks) / 6 / float64(len(rs))
			bu += float64(r.counts.Bursts) / 6 / float64(len(rs))
			ho += float64(r.counts.Handovers) / 6 / float64(len(rs))
			fho += r.counts.FailedHandovers
			longest, idle, minGap = max(longest, r.longest), max(idle, r.idleMax), min(minGap, r.minGap)
			opMin, opMax = min(opMin, r.opMin), max(opMax, r.opMax)
		}
		fmt.Fprintf(&out, "| %s | %.3f %% | %v | %.1f | %.1f to %.1f | %.1f | %.1f | %.1f | %d | %v | %v |\n", sc0.name, pct, longest, qh, opMin, opMax,
			fb, bu, ho, fho, minGap, idle.Round(time.Minute))
	}
	var blips []string
	var sum time.Duration
	for s := uint64(0); s < 6; s++ {
		r := runShiftScenario(t, blipScenario(s))
		checkMinGap(t, "blip", r)
		blips = append(blips, r.blocked.String())
		sum += r.blocked
	}
	fmt.Fprintf(&out, "\n5-minute blip, blocked in [9000 s, 12000 s): mean %v over 6 seeds: %s\n", sum/6, strings.Join(blips, ", "))
	// The two scenarios that block, over 40 seeds.
	for _, idx := range []int{1, 5} {
		var pcts []float64
		var longest time.Duration
		var qh, mean float64
		for s := uint64(1); s <= 40; s++ {
			sc := reviewScenarios(6*time.Hour, s)[idx]
			r := runShiftScenario(t, sc)
			checkMinGap(t, sc.name, r)
			pcts = append(pcts, r.blockedPct())
			longest = max(longest, r.longest)
			qh += r.queriesPerHour / 40
			mean += r.blockedPct() / 40
		}
		slices.Sort(pcts)
		fmt.Fprintf(&out, "%s, 40 seeds: mean %.3f %% median %.3f %% max %.3f %% longest %v q/h %.1f\n",
			reviewScenarios(time.Hour, 0)[idx].name, mean, pcts[20], pcts[39], longest, qh)
	}
	t.Log("\n" + out.String())
}

// The host steps the local counter 2 s ahead. Under the shift schedule the
// quorum in force shares most members with the next one, so the jump first
// shows as outvoted samples; the drift check refuses once a majority of
// samples is new. Until then the time can lead real time by the jump, at
// most for the sample age limit: the lead budget NTSShiftMaxAge already
// grants a host that runs the counter fast.
func TestNTSShiftCounterJump(t *testing.T) {
	for seed := uint64(1); seed <= 5; seed++ {
		sc := shiftScenario{name: "jump", catalog: 8, dur: 30 * time.Minute, seed: seed, jumpAt: 20 * time.Minute, jump: 2 * time.Second}
		r := runShiftScenario(t, sc)
		t.Logf("seed %d: drift refusals %d, led beyond the bound for %v, by up to %v, blocked %v", seed, r.rho, r.leadFor, r.maxLead, r.blocked)
		if r.rho == 0 {
			t.Errorf("seed %d: the drift check never refused the jump", seed)
		}
		if r.maxLead > sc.jump || r.leadFor > NTSShiftMaxAge {
			t.Errorf("seed %d: led by %v for %v", seed, r.maxLead, r.leadFor)
		}
	}
}

// queryCtx is query as the clock's testQuery hook; the fake world answers
// at once, so it does not wait on ctx.
func (w *shiftWorld) queryCtx(_ context.Context, op string, t int64) (nts.Sample, error) {
	return w.query(op, t)
}

// A tick ends at its deadline (ntsRefreshLimit) even when every server
// hangs, and the rounds after the deadline mark no contact: no fallback,
// no burst, no use of the fallback cap. Takes ntsRefreshLimit of real time.
func TestNTSShiftTickDeadline(t *testing.T) {
	if testing.Short() {
		t.Skip("waits ntsRefreshLimit")
	}
	n := &NTS{Coarse: &coarseClock{}, Shifts: true, ScheduleSeed: []byte("deadline"), noStartDelay: true,
		testQuery: func(ctx context.Context, _ string, _ int64) (nts.Sample, error) {
			<-ctx.Done()
			return nts.Sample{}, ctx.Err()
		}}
	for i := range 8 {
		n.Servers = append(n.Servers, NTSServer{Host: fmt.Sprintf("op%d.test", i), Operator: fmt.Sprintf("op%d", i)})
	}
	start := time.Now()
	if err := n.Refresh(context.Background()); err == nil {
		t.Fatal("a quorum from servers that never answer")
	}
	if d := time.Since(start); d < ntsRefreshLimit || d > ntsRefreshLimit+2*time.Second {
		t.Fatalf("tick took %v, deadline %v", d, ntsRefreshLimit)
	}
	s := n.NTSSummary()
	for op, c := range s.Operators {
		if c.Fallbacks != 0 || c.Bursts != 0 {
			t.Fatalf("%s: %+v after the deadline", op, c)
		}
	}
}

// NTSSummary answers while a Refresh hangs on a server (under -race it
// also checks that it reads no field the polls write), and under shifts
// exactly NTSShiftActives servers report Active.
func TestNTSSummaryDuringRefresh(t *testing.T) {
	release := make(chan struct{})
	n := &NTS{Coarse: &coarseClock{}, Shifts: true, ScheduleSeed: []byte("summary"), noStartDelay: true}
	n.testQuery = func(ctx context.Context, op string, _ int64) (nts.Sample, error) {
		if op == "op0" {
			select {
			case <-release:
			case <-ctx.Done():
			}
			return nts.Sample{}, errors.New("timeout")
		}
		return nts.Sample{Offset: time.Now().UnixNano() - n.local(), Bound: 5 * time.Millisecond, T4: n.local()}, nil
	}
	for i := range 8 {
		n.Servers = append(n.Servers, NTSServer{Host: fmt.Sprintf("op%d.test", i), Operator: fmt.Sprintf("op%d", i)})
	}
	done := make(chan error, 1)
	go func() { done <- n.Refresh(context.Background()) }()
	got := make(chan NTSSummary, 1)
	go func() {
		for {
			s := n.NTSSummary()
			if s.Peers[1].Answers == 1 {
				got <- s
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	select {
	case s := <-got:
		if len(s.Peers) != 8 || s.Peers[0].Queries != 0 {
			t.Fatalf("summary during the refresh: %+v", s.Peers)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("NTSSummary waited for the refresh")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	active := 0
	for _, p := range n.NTSSummary().Peers {
		if p.Active {
			active++
		}
	}
	if active != NTSShiftActives {
		t.Fatalf("%d active, want %d", active, NTSShiftActives)
	}
}

// 7 operators run 4 actives (ShiftActives). The cases that must never
// block with 8 operators must not block with 7 either; two wrong at once
// may, since 3 of 4 must agree.
func TestNTSShiftSevenServers(t *testing.T) {
	if got := ShiftActives(7); got != 4 {
		t.Fatalf("ShiftActives(7) = %d", got)
	}
	for n, want := range map[int]int{3: 3, 5: 5, 6: 5, 8: 5, 12: 5} {
		if got := ShiftActives(n); got != want {
			t.Errorf("ShiftActives(%d) = %d, want %d", n, got, want)
		}
	}
	for _, sc := range reviewScenariosN(2*time.Hour, 1, 7) {
		r := runShiftScenario(t, sc)
		checkMinGap(t, sc.name, r)
		t.Logf("%s: blocked %v (%.3f%%), longest %v, %.1f q/h", sc.name, r.blocked, r.blockedPct(), r.longest, r.queriesPerHour)
		switch sc.name {
		case "healthy", "one active at 50% loss", "two actives down", "one operator wrong":
			if r.blocked != 0 {
				t.Errorf("%s: blocked %v", sc.name, r.blocked)
			}
		}
	}
}

// 7 against 8 operators over 10 seeds of 6 h per scenario: mean and worst
// blocked share and the load. Long: run with NTS_SHIFT_SIM=1.
func TestNTSShiftSevenVersusEight(t *testing.T) {
	if os.Getenv("NTS_SHIFT_SIM") == "" {
		t.Skip("NTS_SHIFT_SIM not set")
	}
	var out strings.Builder
	for _, c := range []int{7, 8} {
		names := reviewScenariosN(time.Hour, 0, c)
		for i := range names {
			var mean, worst, qh float64
			var longest time.Duration
			for seed := uint64(1); seed <= 10; seed++ {
				r := runShiftScenario(t, reviewScenariosN(6*time.Hour, seed, c)[i])
				mean += r.blockedPct() / 10
				worst = max(worst, r.blockedPct())
				longest = max(longest, r.longest)
				qh += r.queriesPerHour / 10
			}
			fmt.Fprintf(&out, "C %d A %d | %-28s | blocked mean %.3f %% worst %.3f %% longest %v | %.1f q/h\n",
				c, ShiftActives(c), names[i].name, mean, worst, longest, qh)
		}
		for seed := uint64(1); seed <= 6; seed++ {
			sc := blipScenario(seed)
			sc.catalog = c
			r := runShiftScenario(t, sc)
			fmt.Fprintf(&out, "C %d A %d | 5-minute blip, seed %d        | blocked %v\n", c, ShiftActives(c), seed, r.blocked)
		}
	}
	t.Log("\n" + out.String())
}
