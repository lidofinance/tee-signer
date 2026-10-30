//go:build nts

package clock

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lidofinance/tee-signer/trusted-time/nts"
	"github.com/lidofinance/tee-signer/trusted-time/ntscore"
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
	// ntsExchangeTimeout limits one NTS-KE session or one NTP query.
	ntsExchangeTimeout = nts.ExchangeTimeout
)

// NTSServer is one NTS server and the operator who runs it. Roots are the
// operator's pinned CA certificates, PEM (nts.RootsPEM for the public
// servers).
type NTSServer struct {
	Host     string
	Operator string
	Roots    []byte
	// KEAddr is host:port of NTS-KE; empty means Host:4460.
	KEAddr string
}

// NTS is a clock from NTS servers (RFC 8915) of distinct operators: the
// client of trusted-time/nts, the C core of trusted-time/ntscore under it,
// with this package's scheduling, logs and status around it.
//
// The rules are the core's (ntscore/client.c): each server is asked every
// Interval (at least NTSMinPoll apart), with the Kiss-o'-Death policy and
// the backoff of RFC 5905; the latest sample of each server, at most 4 x
// Interval old, goes to the quorum (one server may be wrong); between
// quorums the bound grows by nts.RhoPPM of the elapsed monotonic time and
// Now fails once it is over MaxBound; each quorum is checked against the
// last one and a baseline about 32 Intervals older (the drift check) and
// against Coarse, the HTTPS-date quorum (the coarse check); Now never goes
// back. Coarse also dates the certificates of NTS-KE before the first
// quorum; after it, the core's own time does. If Coarse has no time, there
// is no NTS time either; there is no fallback to Coarse.
//
// What this package decides is only when to ask: if it stops asking, the
// bound ages past MaxBound and the core refuses the time.
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
	maxPoll time.Duration // 0: NTSMaxPoll; tests set it lower

	once    sync.Once
	rmu     sync.Mutex // one Refresh at a time; Status waits for it
	mu      sync.Mutex // client, lastErr, hostOffset
	client  *nts.Client
	initErr error
	lastErr error
	// hostOffset is each server's last sample's time minus the host
	// clock, for logs only.
	hostOffset map[int]time.Duration
	refusals   atomic.Int64
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
func (n *NTS) maxPollD() time.Duration { return cmpOr(n.maxPoll, NTSMaxPoll) }

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

// init allocates the client once. Its failure (a bad server list) is
// every Refresh's error.
func (n *NTS) init() {
	n.once.Do(func() {
		servers := make([]nts.Server, len(n.Servers))
		for i, s := range n.Servers {
			servers[i] = nts.Server{Operator: s.Operator, Host: s.Host, KEAddr: s.KEAddr, Roots: s.Roots}
		}
		n.hostOffset = map[int]time.Duration{}
		n.client, n.initErr = nts.NewClient(nts.Config{
			Servers: servers, Interval: n.interval(), MinPoll: n.minPollD(), MaxPoll: n.maxPollD(), MaxBound: n.maxBound(),
			MaxCoarseDiff: n.maxDiff(), CoarseResolution: NTSCoarseResolution, ExchangeTimeout: ntsExchangeTimeout,
			Dial: n.Dial, Local: n.local,
		})
		if n.initErr != nil {
			n.initErr = fmt.Errorf("clock: nts: %w", n.initErr)
			n.lastErr = n.initErr
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
	if n.initErr != nil {
		return n.initErr
	}
	coarse, err := n.Coarse.Now()
	coarseLocal := n.local()
	if err != nil {
		err = fmt.Errorf("clock: nts: no coarse time: %w", err)
		n.setErr(err)
		return err
	}
	var wg sync.WaitGroup
	for _, i := range n.client.Due() {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			n.poll(ctx, i, coarse, coarseLocal)
		}(i)
	}
	wg.Wait()
	return n.combine(coarse, coarseLocal)
}

// poll polls one server through the client and logs what came of it.
func (n *NTS) poll(ctx context.Context, i int, coarse time.Time, coarseLocal int64) {
	s := n.Servers[i]
	before := n.client.Peer(i)
	ps, err := n.client.Poll(ctx, i, coarse, coarseLocal)
	if ps.Stats.KEOK > before.Stats.KEOK {
		n.logf(slog.LevelInfo, "nts: key exchange", "operator", s.Operator, "host", s.Host, "ntp", ps.NTPAddr,
			"cookies", ps.Stats.CookiesAfterKE, "took", ps.Stats.LastKE.Round(time.Millisecond))
	}
	var kiss *nts.KissError
	switch {
	case errors.Is(err, ntscore.ErrNotDue):
	case errors.As(err, &kiss):
		n.logf(slog.LevelWarn, "nts: kiss-o'-death", "operator", s.Operator, "code", kiss.Code, "authenticated", kiss.Authentic, "poll", ps.Poll)
	case ps.Stats.KEFail > before.Stats.KEFail:
		n.logf(slog.LevelWarn, "nts: key exchange failed", "operator", s.Operator, "host", s.Host, "err", err)
	case err != nil:
		n.logf(slog.LevelWarn, "nts: query failed", "operator", s.Operator, "err", err)
	default:
		off := time.Duration(ps.Sample.Offset + nts.Monotonic() - time.Now().UnixNano())
		n.mu.Lock()
		n.hostOffset[i] = off
		n.mu.Unlock()
	}
}

// combine forms the quorum of the fresh samples and checks it against the
// coarse time and the earlier quorums (the core's nts_combine), and logs.
func (n *NTS) combine(coarse time.Time, coarseLocal int64) error {
	err := n.client.Combine(coarse, coarseLocal)
	st := n.client.Status()
	members := n.members(st.Members)
	if err != nil {
		var errs []error
		for i, p := range st.Peers {
			if p.LastErr != nil {
				errs = append(errs, fmt.Errorf("%s: %w", n.Servers[i].Operator, p.LastErr))
			}
		}
		switch {
		case errors.Is(err, ntscore.ErrCoarseCheck):
			t := time.Unix(0, n.local()+st.Offset)
			err = fmt.Errorf("clock: nts: quorum time %s is %v from the coarse clock (allowed %v to %v with its %v resolution); refused",
				t.UTC().Format(time.RFC3339Nano), st.CoarseDiff, -n.maxDiff(), n.maxDiff()+NTSCoarseResolution, NTSCoarseResolution)
			n.logf(slog.LevelError, "nts: coarse check failed", "diff", st.CoarseDiff, "max", n.maxDiff(), "resolution", NTSCoarseResolution)
		case errors.Is(err, ntscore.ErrDrift):
			d := driftReading(st)
			allowed := nts.AddBound(st.DriftBounds, nts.Drift(st.DriftDT))
			err = fmt.Errorf("clock: nts: offset moved %v in %v (%.0f ppm, +-%.0f ppm from the bounds), more than its bounds and rho allow (%v); "+
				"the local clock does not keep within %d ppm: refused until the next quorum agrees", st.DriftDelta, st.DriftDT.Round(time.Millisecond),
				d.ppm, d.errPPM, allowed, nts.RhoPPM)
			n.logf(slog.LevelError, "nts: local clock drift over rho", "delta", st.DriftDelta, "interval", st.DriftDT.Round(time.Millisecond),
				"drift_ppm", int64(d.ppm), "drift_err_ppm", int64(d.errPPM), "allowed", allowed)
		default:
			err = fmt.Errorf("clock: nts: %d fresh samples: %w (%v)", st.LastFresh, err, errors.Join(errs...))
			n.logf(slog.LevelWarn, "nts: no quorum", "samples", st.LastFresh, "err", err)
		}
		n.setErr(err)
		return err
	}
	n.setErr(nil)
	// Every quorum at debug level; a change of members at info.
	level := slog.LevelDebug
	if st.MembersChanged {
		level = slog.LevelInfo
	}
	n.logf(level, "nts: quorum", "members", strings.Join(members, ","), "bound", st.Bound,
		"offset_from_host", time.Duration(n.local()+st.Offset-time.Now().UnixNano()), "coarse_diff", st.CoarseDiff)
	return nil
}

func (n *NTS) members(idx []int) []string {
	out := make([]string, len(idx))
	for i, k := range idx {
		out[i] = n.Servers[k].Operator
	}
	return out
}

// ntsDrift is one reading of the drift check, between two quorums: ppm is
// the local clock's rate error against NTS, the change of offset over the
// time between them; errPPM is the sum of the two bounds over that time:
// the real rate error lies within ppm +- errPPM. The check refuses when
// |ppm| > RhoPPM + errPPM, the same test as |delta| > bounds + rho * dt.
type ntsDrift struct {
	ppm, errPPM float64
	baseline    time.Duration
}

func driftReading(st ntscore.Status) ntsDrift {
	if !st.HaveDrift || st.DriftDT <= 0 {
		return ntsDrift{}
	}
	return ntsDrift{
		ppm:      float64(st.DriftDelta) / float64(st.DriftDT) * 1e6,
		errPPM:   float64(st.DriftBounds) / float64(st.DriftDT) * 1e6,
		baseline: st.DriftDT,
	}
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
	n.init()
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.initErr != nil {
		return time.Time{}, 0, n.initErr
	}
	t, bound, err := n.client.Bounded()
	switch {
	case errors.Is(err, ntscore.ErrNoQuorum):
		return time.Time{}, 0, fmt.Errorf("clock: nts: no quorum yet: %v", n.lastErr)
	case err != nil:
		n.refusals.Add(1)
		st := n.client.Summary()
		age := time.Duration(n.local() - st.At)
		return time.Time{}, bound, fmt.Errorf("clock: nts: error bound %v over %v (last quorum %v ago): %v", bound, n.maxBound(), age.Round(time.Second), n.lastErr)
	}
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
	Host    string
	NTPAddr string
	// Disabled is the DENY or RSTR code this server last sent; it is asked
	// again after NTSMaxPoll, and the field clears on its next good answer.
	Disabled string
	Poll     time.Duration
	Sample   *nts.Sample
	LastErr  string
	Stats    NTSPeerStats
}

func (n *NTS) summaryOf(st ntscore.Status, s *NTSSummary, full *NTSStatus) {
	d := driftReading(st)
	if s != nil {
		s.MaxBound, s.Refusals, s.DriftPPM, s.DriftErrPPM, s.DriftBaseline, s.RhoViolations, s.CoarseDiff =
			n.maxBound(), n.refusals.Load(), d.ppm, d.errPPM, d.baseline, st.Violations, st.CoarseDiff
	}
	if full != nil {
		full.Refusals, full.DriftPPM, full.DriftErrPPM, full.DriftBaseline, full.RhoViolations, full.CoarseDiff =
			n.refusals.Load(), d.ppm, d.errPPM, d.baseline, st.Violations, st.CoarseDiff
	}
	if !st.HaveResult {
		return
	}
	now := n.local()
	members := n.members(st.Members)
	age := time.Duration(now - st.At)
	boundNow := nts.AddBound(st.Bound, nts.Drift(age))
	fromHost := time.Duration(now + st.Offset - time.Now().UnixNano())
	if s != nil {
		s.Members, s.AgeOfQuorum, s.BoundNow, s.OffsetFromHost = members, age, boundNow, fromHost
		s.Quorum = boundNow <= s.MaxBound
	}
	if full != nil {
		full.Members, full.Bound, full.Lo, full.Hi = members, st.Bound, st.Lo, st.Hi
		full.AgeOfQuorum, full.BoundNow, full.OffsetFromHost = age, boundNow, fromHost
	}
}

// NTSSummary is the state for HEALTH. Unlike Status it does not wait for a
// running Refresh (which can take seconds while a server is slow): it reads
// the last quorum. Quorum is true when the clock answers now: a quorum is
// in force and its bound is within MaxBound.
func (n *NTS) NTSSummary() NTSSummary {
	n.init()
	n.mu.Lock()
	defer n.mu.Unlock()
	var s NTSSummary
	if n.initErr != nil {
		s.MaxBound = n.maxBound()
		return s
	}
	n.summaryOf(n.client.Summary(), &s, nil)
	return s
}

// Status waits for a running Refresh to end, then takes a snapshot.
func (n *NTS) Status() NTSStatus {
	n.init()
	n.rmu.Lock()
	defer n.rmu.Unlock()
	n.mu.Lock()
	defer n.mu.Unlock()
	st := NTSStatus{Refusals: n.refusals.Load(), Peers: map[string]NTSPeerStatus{}}
	if n.lastErr != nil {
		st.LastError = n.lastErr.Error()
	}
	if n.initErr != nil {
		return st
	}
	cs := n.client.Status()
	n.summaryOf(cs, nil, &st)
	for i, p := range cs.Peers {
		s := n.Servers[i]
		ps := NTSPeerStatus{Host: s.Host, NTPAddr: p.NTPAddr, Disabled: p.Disabled, Poll: p.Poll, Sample: p.Sample, Stats: NTSPeerStats{
			KEOK: p.Stats.KEOK, KEFail: p.Stats.KEFail, Queries: p.Stats.Queries, Samples: p.Stats.Samples, Kisses: p.Stats.Kisses,
			Errors: p.Stats.Errors, LastKE: p.Stats.LastKE, CookiesAfterKE: p.Stats.CookiesAfterKE, CookiesHeld: p.Stats.CookiesHeld,
			LastDelay: p.Stats.LastDelay, LastBound: p.Stats.LastBound, LastOffsetFromHost: n.hostOffset[i],
		}}
		if p.LastErr != nil {
			ps.LastErr = peerErr(p.LastErr).Error()
		}
		st.Peers[s.Operator] = ps
	}
	return st
}

// peerErr names a peer's last refusal as the client would have returned it.
func peerErr(err error) error {
	var e *ntscore.Error
	if errors.As(err, &e) && errors.Is(e, ntscore.ErrKiss) {
		return &nts.KissError{Code: e.Kiss, Authentic: e.KissAuthentic}
	}
	return err
}
