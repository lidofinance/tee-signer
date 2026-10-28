//go:build nts

package clock

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lidofinance/tee-signer/trusted-time/nts"
)

// Defaults of the NTS clock.
const (
	// NTSInterval is the time between two queries to one server.
	NTSInterval = 32 * time.Second
	// NTSMinPoll is the shortest time between two queries to one server:
	// RFC 5905 MINPOLL = 4, 2^4 s (section 7.2, appendix A.1.1).
	NTSMinPoll = 16 * time.Second
	// NTSMaxPoll caps the poll interval after Kiss-o'-Death RATE backoff
	// (ours; RFC 5905 MAXPOLL is 2^17 s).
	NTSMaxPoll = 1024 * time.Second
	// NTSMaxBound: Now fails when the error bound is larger.
	NTSMaxBound = 100 * time.Millisecond
	// NTSMaxCoarseDiff: NTS time further than this from the coarse clock
	// (the HTTPS-date quorum) is refused. The check only catches gross NTS
	// failures; the safety rules work on epochs of 6.4 minutes. A 2 s limit
	// is too tight: the HTTPS-date quorum can be 2 s or more off.
	NTSMaxCoarseDiff = 30 * time.Second
	// NTSCoarseResolution is the resolution of the coarse readings. An
	// HTTP Date header names the second the server was in, so real time at
	// the server was that second up to one second later.
	NTSCoarseResolution = time.Second
	// ntsDriftBaselinePolls times Interval is the baseline of the drift
	// reading: the check also compares each quorum with the oldest quorum
	// kept, at least this old.
	ntsDriftBaselinePolls = 32
	// ntsExchangeTimeout limits one NTS-KE session or one NTP query.
	ntsExchangeTimeout = 5 * time.Second
)

// NTSServer is one NTS server and the operator who runs it.
type NTSServer struct {
	Host     string
	Operator string
	Roots    *x509.CertPool
	// KEAddr is host:port of NTS-KE; empty means Host:4460.
	KEAddr string
}

// NTS is a clock from NTS servers (RFC 8915) of distinct operators.
//
//   - Each server is asked every Interval (at least NTSMinPoll apart). A
//     Kiss-o'-Death RATE doubles that server's interval up to NTSMaxPoll
//     (RFC 5905 section 7.4); each good answer halves it back. DENY or RSTR
//     stops using the server (RFC 5905 section 7.4); NTSN drops the keys and
//     runs NTS-KE again (RFC 8915 section 5.7). NTS-KE failures back off
//     from Interval to NTSMaxPoll.
//   - The latest sample of each server, at most 4 x Interval old, goes to
//     the Rust quorum (one server may be wrong). The result is an offset
//     from the local monotonic clock and an error bound.
//   - Between quorums the bound grows by nts.RhoPPM of the elapsed
//     monotonic time. Now fails once it is over MaxBound, so the signer
//     refuses rather than signs on a time it cannot vouch for.
//   - Aging by rho holds only if the local clock (nts.Monotonic,
//     CLOCK_MONOTONIC_RAW) keeps within rho of real time. Each quorum is
//     checked against the last one and against a baseline quorum about 32
//     Intervals older; if the offset moved more than the two bounds and rho
//     allow, the quorum is refused and Now fails until the next quorum
//     agrees with it. The short pair catches jumps, the long pair a steady
//     rate over rho that the bounds hide on a short pair.
//   - Coarse, the HTTPS-date quorum, is checked on every quorum: an NTS
//     time more than MaxCoarseDiff from it, after its one-second resolution
//     (NTSCoarseResolution), is refused. The coarse clock must age its
//     reading on the same local clock (Anchored.Local = nts.Monotonic), or a
//     slewed Go monotonic clock adds its error. Coarse also gives
//     the certificate-validity time of NTS-KE and the NTP era. If Coarse has
//     no time, there is no NTS time either. There is no fallback to Coarse.
//   - Now never goes back, as for Anchored.
type NTS struct {
	Servers       []NTSServer
	Coarse        interface{ Now() (time.Time, error) }
	Interval      time.Duration // 0: NTSInterval
	MaxBound      time.Duration // 0: NTSMaxBound
	MaxCoarseDiff time.Duration // 0: NTSMaxCoarseDiff
	Dial          nts.DialFunc  // nil: the default dialer
	// Local is the monotonic clock in ns. Nil: nts.Monotonic, which the
	// samples use too. A test moves it ahead to age the bound.
	Local func() int64
	Log   *slog.Logger // nil: no logs

	minPoll time.Duration // 0: NTSMinPoll; tests set it lower

	once   sync.Once
	rmu    sync.Mutex // one Refresh at a time; Status waits for it
	mu     sync.Mutex // result, highest, lastErr
	peers  []*ntsPeer
	result *ntsResult // served by Now; nil until a quorum passes all checks
	// hist holds the quorums of the drift check, oldest first: the last one
	// (served or refused) at the end, the baseline at index 0. A refused
	// quorum starts a new history.
	hist    []*ntsResult
	highest time.Time
	drift   ntsDrift
	// violations counts quorums refused by the drift check.
	violations int64
	coarseDiff time.Duration
	lastErr    error
	refusals   atomic.Int64
}

// ntsDrift is one reading of the drift check, between quorum a and a later
// quorum b. ppm is the local clock's rate error against NTS: the change of
// offset over the time between them. errPPM is the sum of the two bounds
// over that time: the real rate error lies within ppm +- errPPM. The check
// refuses b when |ppm| > RhoPPM + errPPM, the same test as
// |delta| > bound(a) + bound(b) + rho * dt.
type ntsDrift struct {
	ppm, errPPM float64
	baseline    time.Duration
}

func driftBetween(a, b *ntsResult) (d ntsDrift, delta, allowed time.Duration) {
	dt := time.Duration(b.at - a.at)
	delta = time.Duration(b.offset - a.offset)
	allowed = nts.AddBound(nts.AddBound(a.bound, nts.Drift(dt)), b.bound)
	d = ntsDrift{
		ppm:      float64(delta) / float64(dt) * 1e6,
		errPPM:   float64(a.bound+b.bound) / float64(dt) * 1e6,
		baseline: dt,
	}
	return d, delta, allowed
}

type ntsResult struct {
	offset  int64         // real Unix ns minus local ns
	bound   time.Duration // at `at`
	at      int64         // local ns
	members []string
	lo, hi  int64
}

type ntsPeer struct {
	srv      NTSServer
	assoc    *nts.Association
	ntpAddr  string
	sample   *nts.Sample
	poll     time.Duration
	nextPoll int64
	keWait   time.Duration
	nextKE   int64
	disabled string
	lastErr  error
	stats    NTSPeerStats
}

// NTSPeerStats counts what happened with one server.
type NTSPeerStats struct {
	KEOK, KEFail       int
	Queries, Samples   int
	Kisses             map[string]int
	Errors             int
	LastKE             time.Duration // duration of the last NTS-KE
	CookiesAfterKE     int
	CookiesHeld        int
	LastDelay          time.Duration
	LastBound          time.Duration
	LastOffsetFromHost time.Duration // the sample's time minus the host clock, for logs only
}

func (n *NTS) interval() time.Duration { return cmpOr(n.Interval, NTSInterval) }
func (n *NTS) maxBound() time.Duration { return cmpOr(n.MaxBound, NTSMaxBound) }
func (n *NTS) maxDiff() time.Duration  { return cmpOr(n.MaxCoarseDiff, NTSMaxCoarseDiff) }
func (n *NTS) minPollD() time.Duration { return cmpOr(n.minPoll, NTSMinPoll) }
func (n *NTS) baseline() int64         { return int64(ntsDriftBaselinePolls * n.interval()) }

// coarseRefused says whether the NTS time is too far from the coarse
// reading: diff is the NTS time minus the coarse time, both at the same
// local instant. The coarse reading truncates real time to whole seconds,
// so real time at the coarse source was in [coarse, coarse+res). NTS is
// accepted if some point of that range lies within limit of it:
// -limit <= diff < limit+res. A source really 31 s off is refused at any
// fraction of its second.
func coarseRefused(diff, limit, res time.Duration) bool {
	return diff < -limit || diff >= limit+res
}

func cmpOr(v, d time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return d
}

func (n *NTS) local() int64 {
	if n.Local != nil {
		return n.Local()
	}
	return nts.Monotonic()
}

func (n *NTS) init() {
	n.once.Do(func() {
		for _, s := range n.Servers {
			n.peers = append(n.peers, &ntsPeer{srv: s, poll: max(n.interval(), n.minPollD()), stats: NTSPeerStats{Kisses: map[string]int{}}})
		}
	})
}

func (n *NTS) Source() string {
	ops := make([]string, len(n.Servers))
	for i, s := range n.Servers {
		ops[i] = s.Operator
	}
	return "nts(" + strings.Join(ops, ",") + ")"
}

func (n *NTS) Trusted() bool { return true }

func (n *NTS) logf(level slog.Level, msg string, args ...any) {
	if n.Log != nil {
		n.Log.Log(context.Background(), level, msg, args...)
	}
}

// Refresh asks the servers that are due, then forms a new quorum.
func (n *NTS) Refresh(ctx context.Context) error {
	n.init()
	n.rmu.Lock()
	defer n.rmu.Unlock()
	coarse, err := n.Coarse.Now()
	coarseLocal := n.local()
	if err != nil {
		err = fmt.Errorf("clock: nts: no coarse time: %w", err)
		n.setErr(err)
		return err
	}
	var wg sync.WaitGroup
	now := coarseLocal
	for _, p := range n.peers {
		if p.disabled != "" || now < p.nextPoll {
			continue
		}
		wg.Add(1)
		go func(p *ntsPeer) {
			defer wg.Done()
			n.poll(ctx, p, coarse)
		}(p)
	}
	wg.Wait()
	return n.combine(coarse, coarseLocal)
}

// poll runs NTS-KE if needed, then one query. Only this peer's fields are
// written, and Refresh runs one poll per peer at a time.
func (n *NTS) poll(ctx context.Context, p *ntsPeer, coarse time.Time) {
	now := n.local()
	if p.assoc == nil || p.assoc.Cookies() == 0 {
		if p.assoc != nil {
			p.assoc.Close()
			p.assoc = nil
		}
		if now < p.nextKE {
			return
		}
		kctx, cancel := context.WithTimeout(ctx, ntsExchangeTimeout)
		r, err := nts.KeyExchange(kctx, nts.KEConfig{
			Host: p.srv.Host, Addr: p.srv.KEAddr, Roots: p.srv.Roots, Dial: n.Dial,
			// Certificate validity is checked against the coarse clock, not
			// the host's. Without a coarse time the zero time fails the check.
			Time: func() time.Time {
				t, err := n.Coarse.Now()
				if err != nil {
					return time.Time{}
				}
				return t
			},
		})
		cancel()
		if err != nil {
			p.stats.KEFail++
			p.lastErr = err
			p.keWait = min(max(2*p.keWait, n.interval()), NTSMaxPoll)
			p.nextKE = now + int64(p.keWait)
			n.logf(slog.LevelWarn, "nts: key exchange failed", "operator", p.srv.Operator, "host", p.srv.Host, "retry_in", p.keWait, "err", err)
			return
		}
		p.stats.KEOK++
		p.stats.LastKE = r.Elapsed
		p.stats.CookiesAfterKE = r.Assoc.Cookies()
		p.keWait = 0
		p.assoc, p.ntpAddr = r.Assoc, r.NTPAddr
		n.logf(slog.LevelInfo, "nts: key exchange", "operator", p.srv.Operator, "host", p.srv.Host, "ntp", r.NTPAddr,
			"cookies", p.stats.CookiesAfterKE, "took", r.Elapsed.Round(time.Millisecond))
	}
	qctx, cancel := context.WithTimeout(ctx, ntsExchangeTimeout)
	s, err := p.assoc.Query(qctx, p.ntpAddr, coarse, n.Dial)
	cancel()
	p.stats.Queries++
	p.stats.CookiesHeld = p.assoc.Cookies()
	p.nextPoll = n.local() + int64(p.poll)
	var kiss *nts.KissError
	switch {
	case errors.As(err, &kiss):
		p.stats.Kisses[kiss.Code]++
		p.lastErr = err
		switch kiss.Code {
		case "RATE":
			p.poll = min(2*p.poll, NTSMaxPoll)
			p.nextPoll = n.local() + int64(p.poll)
		case "DENY", "RSTR":
			p.disabled = kiss.Code
			p.sample = nil
		case "NTSN":
			p.assoc.Close()
			p.assoc = nil
		}
		n.logf(slog.LevelWarn, "nts: kiss-o'-death", "operator", p.srv.Operator, "code", kiss.Code, "poll", p.poll)
	case err != nil:
		p.stats.Errors++
		p.lastErr = err
		n.logf(slog.LevelWarn, "nts: query failed", "operator", p.srv.Operator, "err", err)
	default:
		p.stats.Samples++
		p.sample = &s
		p.lastErr = nil
		p.poll = max(p.poll/2, max(n.interval(), n.minPollD()))
		p.stats.LastDelay, p.stats.LastBound = s.Delay, s.Bound
		p.stats.LastOffsetFromHost = time.Duration(s.Offset + nts.Monotonic() - time.Now().UnixNano())
	}
}

// combine forms the quorum of the fresh samples and checks it against the
// coarse time.
func (n *NTS) combine(coarse time.Time, coarseLocal int64) error {
	now := n.local()
	maxAge := int64(4 * n.interval())
	var in []nts.Interval
	var errs []error
	for _, p := range n.peers {
		if p.lastErr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p.srv.Operator, p.lastErr))
		}
		if p.sample == nil || now-p.sample.T4 > maxAge {
			continue
		}
		in = append(in, nts.Interval{Operator: p.srv.Operator, Offset: p.sample.Offset, Bound: p.sample.Bound, T4: p.sample.T4})
	}
	q, err := nts.Quorum(in, now)
	if err != nil {
		err = fmt.Errorf("clock: nts: %d fresh samples: %w (%v)", len(in), err, errors.Join(errs...))
		n.setErr(err)
		n.logf(slog.LevelWarn, "nts: no quorum", "samples", len(in), "err", err)
		return err
	}
	t := time.Unix(0, now+q.Offset)
	// The coarse reading was taken before the polls: move it forward by
	// the local time since then.
	diff := t.Sub(coarse.Add(time.Duration(now - coarseLocal)))
	n.mu.Lock()
	n.coarseDiff = diff
	n.mu.Unlock()
	if coarseRefused(diff, n.maxDiff(), NTSCoarseResolution) {
		err = fmt.Errorf("clock: nts: quorum time %s is %v from the coarse clock (allowed %v to %v with its %v resolution); refused",
			t.UTC().Format(time.RFC3339Nano), diff, -n.maxDiff(), n.maxDiff()+NTSCoarseResolution, NTSCoarseResolution)
		n.setErr(err)
		n.logf(slog.LevelError, "nts: coarse check failed", "diff", diff, "max", n.maxDiff(), "resolution", NTSCoarseResolution)
		return err
	}
	members := make([]string, len(in))
	for i, v := range in {
		members[i] = v.Operator
	}
	cur := &ntsResult{offset: q.Offset, bound: q.Bound, at: now, members: members, lo: q.Lo, hi: q.Hi}
	n.mu.Lock()
	// The bound grows by rho only if the local clock keeps within rho of
	// real time. Check that against the last quorum and the baseline: both
	// intervals of a pair hold the real offset (one server at most wrong in
	// each), and it can move by at most rho times the time between them. If
	// a pair does not fit, the local clock broke rho (or more servers are
	// wrong): this quorum is not served, a new history starts with it, and
	// the next quorum must agree with it first.
	var refs []*ntsResult
	if k := len(n.hist); k > 0 {
		refs = append(refs, n.hist[k-1])
		if k > 1 {
			refs = append(refs, n.hist[0])
		}
	}
	for i, ref := range refs {
		if now <= ref.at {
			continue
		}
		d, delta, allowed := driftBetween(ref, cur)
		// The status shows the longest pair, or the pair that failed.
		if i == len(refs)-1 || delta.Abs() > allowed {
			n.drift = d
		}
		if delta.Abs() > allowed {
			n.hist, n.result = []*ntsResult{cur}, nil
			n.violations++
			err = fmt.Errorf("clock: nts: offset moved %v in %v (%.0f ppm, +-%.0f ppm from the bounds), more than its bounds and rho allow (%v); "+
				"the local clock does not keep within %d ppm: refused until the next quorum agrees", delta, d.baseline.Round(time.Millisecond),
				d.ppm, d.errPPM, allowed, nts.RhoPPM)
			n.lastErr = err
			n.mu.Unlock()
			n.logf(slog.LevelError, "nts: local clock drift over rho", "delta", delta, "interval", d.baseline.Round(time.Millisecond),
				"drift_ppm", int64(d.ppm), "drift_err_ppm", int64(d.errPPM), "allowed", allowed)
			return err
		}
	}
	// Keep the newest quorum at least the baseline old as hist[0], and
	// drop the ones before it.
	n.hist = append(n.hist, cur)
	for len(n.hist) > 2 && now-n.hist[1].at >= n.baseline() {
		n.hist = n.hist[1:]
	}
	prev := ""
	if n.result != nil {
		prev = strings.Join(n.result.members, ",")
	}
	n.result = cur
	n.lastErr = nil
	n.mu.Unlock()
	// Every quorum at debug level; a change of members at info.
	level := slog.LevelDebug
	if joined := strings.Join(members, ","); joined != prev {
		level = slog.LevelInfo
	}
	n.logf(level, "nts: quorum", "members", strings.Join(members, ","), "bound", q.Bound,
		"offset_from_host", time.Duration(now+q.Offset-time.Now().UnixNano()), "coarse_diff", diff)
	return nil
}

func (n *NTS) setErr(err error) {
	n.mu.Lock()
	n.lastErr = err
	n.mu.Unlock()
}

// Run refreshes until ctx ends. It wakes every quarter Interval; each
// server is asked only when it is due.
func (n *NTS) Run(ctx context.Context) {
	tick := time.NewTicker(n.interval() / 4)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			_ = n.Refresh(ctx)
		}
	}
}

// Bounded returns the time and its error bound now.
func (n *NTS) Bounded() (time.Time, time.Duration, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.result == nil {
		return time.Time{}, 0, fmt.Errorf("clock: nts: no quorum yet: %v", n.lastErr)
	}
	now := n.local()
	// AddBound saturates, and a negative bound is refused as well: a bound
	// that wrapped around once let a quorum months old serve time again
	// (TIME-BOUND-01).
	bound := nts.AddBound(n.result.bound, nts.Drift(time.Duration(now-n.result.at)))
	if limit := n.maxBound(); bound < 0 || bound > limit {
		n.refusals.Add(1)
		return time.Time{}, bound, fmt.Errorf("clock: nts: error bound %v over %v (last quorum %v ago): %v",
			bound, limit, time.Duration(now-n.result.at).Round(time.Second), n.lastErr)
	}
	t := time.Unix(0, now+n.result.offset)
	if t.Before(n.highest) {
		t = n.highest
	}
	n.highest = t
	return t, bound, nil
}

// Now is Bounded without the bound.
func (n *NTS) Now() (time.Time, error) {
	t, _, err := n.Bounded()
	return t, err
}

// NTSStatus is a snapshot for logs and tests.
type NTSStatus struct {
	Members []string
	Bound   time.Duration // of the last quorum, at its time
	// BoundNow is Bound grown by rho since the last quorum, AgeOfQuorum
	// that time. OffsetFromHost is the NTS time minus the host clock (for
	// logs; the host clock is not used for anything else).
	BoundNow       time.Duration
	AgeOfQuorum    time.Duration
	OffsetFromHost time.Duration
	Lo, Hi         int64
	// DriftPPM is the local clock's rate error against NTS, measured from
	// a baseline quorum to the last quorum, DriftBaseline apart (up to 32
	// Intervals, about 17 minutes). DriftErrPPM is the sum of the two
	// quorums' bounds over DriftBaseline: the real rate error is within
	// DriftPPM +- DriftErrPPM, so on a short baseline a reading over rho
	// means nothing by itself. RhoViolations counts quorums refused by the
	// drift check, which refuses exactly when |DriftPPM| > rho +
	// DriftErrPPM for the last pair or the baseline pair. After a refusal
	// the three fields describe the pair that failed.
	DriftPPM      float64
	DriftErrPPM   float64
	DriftBaseline time.Duration
	RhoViolations int64
	// CoarseDiff is the NTS time minus the coarse clock at the last
	// quorum. With honest sources it is about 0 to 1 s (the coarse time is
	// truncated to the second); the check allows -MaxCoarseDiff to
	// MaxCoarseDiff + NTSCoarseResolution.
	CoarseDiff time.Duration
	Refusals   int64 // Now calls refused for the bound
	LastError  string
	Peers      map[string]NTSPeerStatus
}

// NTSPeerStatus is one server's part of NTSStatus.
type NTSPeerStatus struct {
	Host     string
	NTPAddr  string
	Disabled string
	Poll     time.Duration
	Sample   *nts.Sample
	LastErr  string
	Stats    NTSPeerStats
}

// NTSSummary is the state for HEALTH. Unlike Status it does not wait for a
// running Refresh (which can take seconds while a server is slow): it reads
// the last quorum. Quorum is true when the clock answers now: a quorum is
// in force and its bound is within MaxBound.
func (n *NTS) NTSSummary() NTSSummary {
	n.mu.Lock()
	defer n.mu.Unlock()
	s := NTSSummary{MaxBound: n.maxBound(), Refusals: n.refusals.Load(), DriftPPM: n.drift.ppm, DriftErrPPM: n.drift.errPPM,
		DriftBaseline: n.drift.baseline, RhoViolations: n.violations, CoarseDiff: n.coarseDiff}
	if r := n.result; r != nil {
		now := n.local()
		s.Members = append([]string(nil), r.members...)
		s.AgeOfQuorum = time.Duration(now - r.at)
		s.BoundNow = nts.AddBound(r.bound, nts.Drift(s.AgeOfQuorum))
		s.Quorum = s.BoundNow <= s.MaxBound
		s.OffsetFromHost = time.Duration(now + r.offset - time.Now().UnixNano())
	}
	return s
}

// Status waits for a running Refresh to end, then takes a snapshot.
func (n *NTS) Status() NTSStatus {
	n.init()
	n.rmu.Lock()
	defer n.rmu.Unlock()
	n.mu.Lock()
	defer n.mu.Unlock()
	st := NTSStatus{Refusals: n.refusals.Load(), Peers: map[string]NTSPeerStatus{}, DriftPPM: n.drift.ppm, DriftErrPPM: n.drift.errPPM,
		DriftBaseline: n.drift.baseline, RhoViolations: n.violations, CoarseDiff: n.coarseDiff}
	if r := n.result; r != nil {
		now := n.local()
		st.Members, st.Bound, st.Lo, st.Hi = r.members, r.bound, r.lo, r.hi
		st.AgeOfQuorum = time.Duration(now - r.at)
		st.BoundNow = nts.AddBound(r.bound, nts.Drift(st.AgeOfQuorum))
		st.OffsetFromHost = time.Duration(now + r.offset - time.Now().UnixNano())
	}
	if n.lastErr != nil {
		st.LastError = n.lastErr.Error()
	}
	for _, p := range n.peers {
		ps := NTSPeerStatus{Host: p.srv.Host, NTPAddr: p.ntpAddr, Disabled: p.disabled, Poll: p.poll, Sample: p.sample, Stats: p.stats}
		if p.lastErr != nil {
			ps.LastErr = p.lastErr.Error()
		}
		st.Peers[p.srv.Operator] = ps
	}
	return st
}
