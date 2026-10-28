// Package clock has the runner's time sources.
//
// System reads the local clock, which the host sets on every platform
// studied here. Anchored reports times it got from authenticated sources
// (HTTPS Date headers, attestation token iat, NSM timestamps). Between two
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

// NTSSummary is the part of the NTS clock's state that HEALTH reports. It
// is here, without the build tag nts, so the server can ask any clock for
// it (NTSReporter); only the NTS clock has it.
type NTSSummary struct {
	Quorum         bool
	BoundNow       time.Duration
	MaxBound       time.Duration
	OffsetFromHost time.Duration
	Members        []string
	AgeOfQuorum    time.Duration
	Refusals       int64
	DriftPPM       float64
	DriftErrPPM    float64
	DriftBaseline  time.Duration
	RhoViolations  int64
	CoarseDiff     time.Duration
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
}

func (q *Quorum) Name() string {
	names := make([]string, len(q.Sources))
	for i, s := range q.Sources {
		names[i] = s.Name()
	}
	return fmt.Sprintf("quorum(%d of %s)", q.Min, strings.Join(names, ","))
}

func (q *Quorum) Fetch(ctx context.Context) (time.Time, error) {
	type res struct {
		t   time.Time
		err error
	}
	ch := make(chan res, len(q.Sources))
	for _, s := range q.Sources {
		go func(s Source) {
			t, err := s.Fetch(ctx)
			if err != nil {
				err = fmt.Errorf("%s: %w", s.Name(), err)
			}
			ch <- res{t, err}
		}(s)
	}
	var times []time.Time
	var errs []error
	for range q.Sources {
		r := <-ch
		if r.err != nil {
			errs = append(errs, r.err)
			continue
		}
		times = append(times, r.t)
	}
	if len(times) < q.Min || len(times) == 0 {
		return time.Time{}, fmt.Errorf("clock: %d of %d sources answered, need %d: %w",
			len(times), len(q.Sources), q.Min, errors.Join(errs...))
	}
	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
	// Lower median for an even count: the conservative choice for a
	// clock whose job is to stay at or below real time.
	return times[(len(times)-1)/2], nil
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
func (a *Anchored) Trusted() bool  { return a.TrustedSrc }

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
