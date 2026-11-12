// Package clock has the runner's time sources.
//
// System reads the local clock, which the host sets on every platform
// studied here. Anchored reports times it got from authenticated sources
// (HTTPS Date headers). Between two
// readings it advances with the local monotonic clock, but never further
// than MaxAdvance past the last reading, so the host can delay or deny
// time, and can move it forward by at most MaxAdvance, as long as most
// sources are honest. See README.md, "Restart rule and the clock".
package clock

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// System is the local clock plus an optional offset (dev only; the offset
// lets tests play a host that moves the clock).
type System struct{ Offset time.Duration }

func (s System) Now() (time.Time, error) { return time.Now().Add(s.Offset), nil }
func (s System) Source() string {
	if s.Offset != 0 {
		return fmt.Sprintf("system%+v", s.Offset)
	}
	return "system"
}
func (s System) Trusted() bool { return false }

// Protocol is how the NTS clock asks its servers for time. It is here,
// without the build tag nts, with NTSSummary.
type Protocol string

const (
	// ProtocolNTS is NTP with NTS (RFC 8915): every answer is authenticated
	// with keys from an NTS-KE session over TLS. The default.
	ProtocolNTS Protocol = "nts"
	// ProtocolNTP is plain NTP (RFC 5905) without NTS: no NTS-KE, no
	// cookies, and nothing authenticates the answers. The host, or anyone
	// on the path, can forge every answer. Against them the time is only as
	// good as the coarse check: -30 s to +31 s against the coarse clock with
	// the default MaxCoarseDiff, which is itself off real time (about 46 s
	// behind to 196 s ahead in all; behind without a limit where the host
	// sets the local counter; trusted-time/docs/nts.md "Plain NTP").
	// Plain NTP adds precision only against an honest host.
	ProtocolNTP Protocol = "ntp"
)

// ParseProtocol reads "nts" or "ntp". "" is ProtocolNTS.
func ParseProtocol(s string) (Protocol, error) {
	switch Protocol(s) {
	case "", ProtocolNTS:
		return ProtocolNTS, nil
	case ProtocolNTP:
		return ProtocolNTP, nil
	}
	return "", fmt.Errorf("clock: protocol %q: want nts or ntp", s)
}

// NTSSummary is the part of the NTS clock's state that HEALTH reports. It
// is here, without the build tag nts, so the server can ask any clock for
// it (NTSReporter); only the NTS clock has it. SampleAge is the age of the
// oldest sample of the last quorum. Refused says why the clock gives no
// time now; it is empty when Quorum is true.
type NTSSummary struct {
	// Protocol is how the clock asks its servers: ProtocolNTS, or
	// ProtocolNTP (plain NTP, unauthenticated).
	Protocol Protocol
	Quorum   bool
	Refused  string
	BoundNow time.Duration
	// WorstBoundNow is the error one wrong quorum member can cause now:
	// BoundNow with 4 or more fresh samples, and up to twice the widest
	// member's bound with exactly 3, where no wrong sample is outvoted.
	// Signing checks BoundNow only.
	WorstBoundNow  time.Duration
	MaxBound       time.Duration
	OffsetFromHost time.Duration
	Members        []string
	AgeOfQuorum    time.Duration
	SampleAge      time.Duration
	MaxSampleAge   time.Duration
	Refusals       int64
	DriftPPM       float64
	DriftErrPPM    float64
	DriftBaseline  time.Duration
	RhoViolations  int64
	CoarseDiff     time.Duration
	// ServerSwaps counts the server lists NTS.SetServers took since start.
	ServerSwaps int64
	// With the shift schedule (NTS.Shifts): the active operators
	// now, counts per operator since start, and the fallbacks
	// NTSShiftFallbackCap refused.
	Actives         []string
	Operators       map[string]NTSOperatorCounts
	FallbacksCapped int64
	// Peers has one entry per server the clock dials, in Servers order,
	// including servers that never answered.
	Peers []NTSPeerHealth
	// Coarse has one entry per source of the coarse clock, when it keeps
	// stats (SourceStatser): the HTTPS-date hosts of the runner.
	Coarse []SourceStats
}

// NTSPeerHealth is one server in NTSSummary. Queries counts NTP queries,
// Answers those that gave a sample, Losses the rest (timeouts, errors,
// Kiss-o'-Death). KEOK and KEFail count NTS-KE sessions. LastAnswerAge is
// the time since the last answer, -1 for none yet. Off is the Kiss-o'-Death
// code (DENY, RSTR) that stopped the server for now. Active: the shift
// schedule asks it on a slot now; always true without shifts.
type NTSPeerHealth struct {
	Operator, Host           string
	Active                   bool
	Queries, Answers, Losses int64
	Wide                     int64 // losses that were answers over MaxSampleBound
	KEOK, KEFail             int64
	LastAnswerAge            time.Duration
	Off                      string
	LastError                string
}

// NTSOperatorCounts counts the contacts with one operator under the shift
// schedule. Queries counts every contact the schedule made (start, active
// slot, fallback, burst, retry); Fallbacks and Bursts count those made as a
// fallback or in a recovery burst, Retries those that asked this operator
// again NTSShiftStartRetry after a lost answer that found no fallback.
// Handovers counts the shifts this operator came in at, FailedHandovers
// those where its first contact after coming in got no answer. Rates counts
// Kiss-o'-Death RATE answers (also counted as losses). FallbackKE counts
// the fallbacks to this operator that ran NTS-KE first: if it grows, its
// cookies expire while it is idle.
type NTSOperatorCounts struct {
	Queries, Answers, Losses   int64
	Fallbacks, Bursts, Rates   int64
	Handovers, FailedHandovers int64
	FallbackKE                 int64
	Retries                    int64
}

// NTSReporter is a clock that reports an NTSSummary.
type NTSReporter interface {
	NTSSummary() NTSSummary
}

// Source fetches one authenticated time reading. A correct source returns
// a time T with send <= T <= receive in real time: the server made the
// reading after the request left.
type Source interface {
	Fetch(ctx context.Context) (time.Time, error)
	Name() string
}

// Quorum asks every source and returns the median of the answers. It
// needs at least Min answers. With n sources and Min > n/2 the median lies
// between two honest readings while fewer than Min sources lie.
type Quorum struct {
	Sources []Source
	Min     int

	mu    sync.Mutex
	stats []SourceStats // per source, in Sources order; made on first Fetch
}

// SourceStats counts one source of a Quorum since start. LastAnswerAge is
// the time since its last answer when the stats were read, -1 for none.
// LastDiff is its reading minus the quorum's answer, from the last round
// that formed a quorum (a round without one leaves it as it was): a source
// that lags or leads the others shows here before it costs a quorum.
// LastError is its last failure, empty after an answer.
type SourceStats struct {
	Name             string
	Queries, Answers int64
	Failures         int64
	LastAnswerAge    time.Duration
	LastDiff         time.Duration
	LastError        string

	lastAnswer time.Time // local time of the last answer
}

// SourceStatser is a time source that keeps per-source stats (Quorum, or
// an Anchored clock over one).
type SourceStatser interface {
	SourceStats() []SourceStats
}

// SourceStats returns a copy of the per-source stats, one per source.
func (q *Quorum) SourceStats() []SourceStats {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]SourceStats, len(q.Sources))
	for i, s := range q.Sources {
		if q.stats != nil {
			out[i] = q.stats[i]
		}
		out[i].Name = s.Name()
		out[i].LastAnswerAge = -1
		if !out[i].lastAnswer.IsZero() {
			out[i].LastAnswerAge = time.Since(out[i].lastAnswer)
		}
	}
	return out
}

func (q *Quorum) Name() string {
	names := make([]string, len(q.Sources))
	for i, s := range q.Sources {
		names[i] = s.Name()
	}
	return fmt.Sprintf("quorum(%d of %s)", q.Min, strings.Join(names, ","))
}

func (q *Quorum) Fetch(ctx context.Context) (time.Time, error) {
	ch := make(chan quorumAnswer, len(q.Sources))
	for i, s := range q.Sources {
		go func(i int, s Source) {
			t, err := s.Fetch(ctx)
			if err != nil {
				err = fmt.Errorf("%s: %w", s.Name(), err)
			}
			ch <- quorumAnswer{i, t, time.Now(), err}
		}(i, s)
	}
	all := make([]quorumAnswer, 0, len(q.Sources))
	var times []time.Time
	var errs []error
	for range q.Sources {
		r := <-ch
		all = append(all, r)
		if r.err != nil {
			errs = append(errs, r.err)
			continue
		}
		times = append(times, r.t)
	}
	var median time.Time
	ok := len(times) >= q.Min && len(times) > 0
	if ok {
		sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
		// Lower median for an even count: the conservative choice for a
		// clock whose job is to stay at or below real time.
		median = times[(len(times)-1)/2]
	}
	q.record(all, median, ok)
	if !ok {
		return time.Time{}, fmt.Errorf("clock: %d of %d sources answered, need %d: %w",
			len(times), len(q.Sources), q.Min, errors.Join(errs...))
	}
	return median, nil
}

// quorumAnswer is one source's answer in a round: its index, the reading,
// the local time it arrived, or the error.
type quorumAnswer struct {
	i   int
	t   time.Time
	at  time.Time
	err error
}

// record updates the per-source stats with one round. median is the
// quorum's answer when ok.
func (q *Quorum) record(round []quorumAnswer, median time.Time, ok bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.stats == nil {
		q.stats = make([]SourceStats, len(q.Sources))
		for i, s := range q.Sources {
			q.stats[i].Name = s.Name()
		}
	}
	for _, r := range round {
		s := &q.stats[r.i]
		s.Queries++
		if r.err != nil {
			s.Failures++
			s.LastError = r.err.Error()
			continue
		}
		s.Answers++
		s.lastAnswer = r.at
		s.LastError = ""
		if ok {
			s.LastDiff = r.t.Sub(median)
		}
	}
}

// Defaults of an Anchored clock. Interval is how often it takes a reading.
// MaxAge and MaxAdvance default to MissedSyncs times Interval: with a 15 s
// interval, four readings in a row may fail and the clock still runs; the
// fifth missed reading stops it.
const (
	DefaultInterval = 15 * time.Second
	MissedSyncs     = 5
)

// Anchored is a Clock built from authenticated readings.
//
//   - Now returns the last reading plus the local monotonic time since it
//     arrived, at most MaxAdvance. Before, Now stood still between two
//     readings, and on Azure the signer lagged real time by 18 to 57 s
//     with a 60 s interval. The reading is taken to be real time at the
//     moment the answer arrived, so Now is at or just behind real time (a
//     sub-second lag from the HTTP Date resolution and the round trip).
//   - A host that speeds up the local clock gains at most MaxAdvance: the
//     advance is capped, and the next reading ends it.
//   - Now never goes back. It returns the highest value it has returned. A
//     new reading below that value holds the clock still until real time
//     catches up with it.
//   - A reading MaxAge old (measured on the local monotonic clock) makes
//     Now fail, so the signer refuses rather than signs on stale
//     time, and a blocked network stops signing instead of freezing time.
//     A host that slows the local clock can stretch MaxAge, which only keeps
//     the clock behind real time.
//   - Refresh fetches a new reading; Run calls it every Interval.
type Anchored struct {
	Src Source
	// Interval is the time between readings. Required, DefaultInterval in
	// the runner.
	Interval time.Duration
	// MaxAge is how old the last reading may get before Now fails. Zero
	// means MissedSyncs * Interval.
	MaxAge time.Duration
	// MaxAdvance caps how far Now runs ahead of the last reading. Zero
	// means MissedSyncs * Interval.
	MaxAdvance time.Duration
	// TrustedSrc says whether Src resists the host (Quorum of HTTPS or
	// attestation sources: yes; anything read from the host: no).
	TrustedSrc bool

	// Local is the local monotonic clock. Nil means time.Now. A test sets
	// it to play a host that speeds up or slows down the local timer.
	Local func() time.Time

	mu      sync.Mutex
	reading time.Time // the last trusted reading
	fetched time.Time // local time when it arrived
	highest time.Time // the highest value Now has returned
	lastErr error
}

func (a *Anchored) Source() string { return "anchored(" + a.Src.Name() + ")" }

// SourceStats are the per-source stats of Src, nil if it keeps none.
func (a *Anchored) SourceStats() []SourceStats {
	if s, ok := a.Src.(SourceStatser); ok {
		return s.SourceStats()
	}
	return nil
}
func (a *Anchored) Trusted() bool { return a.TrustedSrc }

func (a *Anchored) localNow() time.Time {
	if a.Local != nil {
		return a.Local()
	}
	return time.Now()
}

// MaxAgeOrDefault returns MaxAge, or MissedSyncs * Interval if it is zero.
func (a *Anchored) MaxAgeOrDefault() time.Duration {
	if a.MaxAge > 0 {
		return a.MaxAge
	}
	return MissedSyncs * a.Interval
}

// MaxAdvanceOrDefault returns MaxAdvance, or MissedSyncs * Interval if it
// is zero.
func (a *Anchored) MaxAdvanceOrDefault() time.Duration {
	if a.MaxAdvance > 0 {
		return a.MaxAdvance
	}
	return MissedSyncs * a.Interval
}

// Refresh takes one reading.
func (a *Anchored) Refresh(ctx context.Context) error {
	t, err := a.Src.Fetch(ctx)
	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil {
		a.lastErr = err
		return err
	}
	a.reading = t
	a.fetched = a.localNow()
	a.lastErr = nil
	return nil
}

// Run refreshes every Interval until ctx ends.
func (a *Anchored) Run(ctx context.Context) {
	tick := time.NewTicker(a.Interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			rctx, cancel := context.WithTimeout(ctx, a.Interval)
			_ = a.Refresh(rctx)
			cancel()
		}
	}
}

func (a *Anchored) Now() (time.Time, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.reading.IsZero() {
		return time.Time{}, fmt.Errorf("clock: no reading yet: %v", a.lastErr)
	}
	age := a.localNow().Sub(a.fetched)
	if limit := a.MaxAgeOrDefault(); age >= limit {
		return time.Time{}, fmt.Errorf("clock: last reading is %v old (max %v): %v", age.Round(time.Second), limit, a.lastErr)
	}
	t := a.reading.Add(min(max(age, 0), a.MaxAdvanceOrDefault()))
	if t.Before(a.highest) {
		t = a.highest
	}
	a.highest = t
	return t, nil
}
