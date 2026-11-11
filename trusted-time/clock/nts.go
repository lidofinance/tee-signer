//go:build nts

package clock

import (
	"cmp"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math/rand/v2"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lidofinance/tee-signer/trusted-time/nts"
)

// Defaults of the NTS clock.
const (
	// NTSInterval is the time between two queries to one server. It is
	// well under NTSMaxAge: a server that misses one answer usually still
	// has a sample young enough to join a quorum (joinAge) when the next
	// one comes.
	NTSInterval = 16 * time.Second
	// NTSMinPoll is the shortest time between two queries to one server:
	// RFC 5905 MINPOLL = 4, 2^4 s (section 7.2, appendix A.1.1).
	NTSMinPoll = 16 * time.Second
	// NTSMaxPoll caps the poll interval after Kiss-o'-Death RATE backoff
	// (ours; RFC 5905 MAXPOLL is 2^17 s).
	NTSMaxPoll = 1024 * time.Second
	// NTSMaxBound: Now fails when the error bound is larger.
	NTSMaxBound = 100 * time.Millisecond
	// NTSMaxAge: Now fails when the oldest sample of the quorum in force
	// is older, on the local clock. A sample joins a quorum only while it
	// will stay under it until the next quorum (joinAge). The bound ages
	// by rho of the local clock, which the host may run fast while it
	// blocks the servers; this limit keeps the time served then at most
	// NTSMaxAge ahead of real time. It does not cover the slow direction:
	// a host that slows or stops the local clock while it blocks the
	// servers also slows the age, so the time served can lag real time
	// without limit (it never goes back).
	NTSMaxAge = 60 * time.Second
	// NTSMaxCoarseDiff: NTS time further than this from the coarse clock
	// (the HTTPS-date quorum) is refused. The check only catches gross NTS
	// failures; the safety rules work on epochs of 6.4 minutes. A 2 s limit
	// is too tight: the HTTPS-date quorum can be 2 s or more off.
	NTSMaxCoarseDiff = 30 * time.Second
	// NTSCoarseResolution is the resolution of the coarse readings. An
	// HTTP Date header names the second the server was in, so real time at
	// the server was that second up to one second later.
	NTSCoarseResolution = time.Second
	// NTSStartDelay: the first Refresh waits a random time under this
	// before it contacts anyone, so signers that restart together do not
	// reach the servers in the same second.
	NTSStartDelay = 5 * time.Second
	// ntsDriftBaselinePolls times Interval is the baseline of the drift
	// reading: the check also compares each quorum with the oldest quorum
	// kept, at least this old.
	ntsDriftBaselinePolls = 64
	// ntsExchangeTimeout limits one NTS-KE session or one NTP query.
	ntsExchangeTimeout = 5 * time.Second
	// ntsRefreshLimit is the longest a Refresh contacts servers: one NTS-KE
	// and one query, or the deadline of a tick of the shift schedule.
	ntsRefreshLimit = 2 * ntsExchangeTimeout
)

// NTSServer is one NTS server and the operator who runs it.
type NTSServer struct {
	Host     string
	Operator string
	Roots    *x509.CertPool
	// KEAddr is host:port of NTS-KE; empty means Host:4460.
	KEAddr string
	// NTPAddr is host:port of the server's plain NTP service, for
	// ProtocolNTP; empty means Host:123. With NTS the NTS-KE server names
	// the NTP host instead.
	NTPAddr string
}

// NTS is a clock from NTS servers (RFC 8915) of distinct operators.
//
//   - Each server is asked every Interval (at least NTSMinPoll apart). A
//     Kiss-o'-Death RATE doubles that server's interval up to NTSMaxPoll
//     (RFC 5905 section 7.4); each good answer halves it back. DENY or RSTR
//     stops using the server for NTSMaxPoll (RFC 5905 section 7.4 says for
//     good, but a Kiss-o'-Death is not authenticated, so anyone on the path
//     could send it); NTSN drops the keys and runs NTS-KE again (RFC 8915
//     section 5.7). The first Refresh waits a random time under StartDelay
//     before it contacts anyone, so signers that restart together spread
//     their contacts.
//     NTS-KE failures back off from Interval to NTSMaxPoll once a quorum
//     has been served; until then NTS-KE is tried again after a random
//     3/4 to 5/4 Interval (12 to 20 s), so a relay that comes up late does
//     not push the first quorum past the runner's start wait, and signers
//     that failed together do not try again together.
//   - The latest sample of each server goes to the Rust quorum if it will
//     stay under MaxAge until the next quorum (n is the count of such
//     fresh samples, not of the servers; up to (n - 1) / 2 of them may be
//     wrong, and at least 3 must agree, nts.QuorumWrong):
//     at most MaxAge minus a tick of Run and the longest Refresh, 46 s
//     with the defaults (and at most 4 x Interval), 76 s under the shift
//     schedule (no 4 x Interval cap). Refresh refuses a
//     MaxAge that leaves no room for that. The result is an offset from
//     the local monotonic clock and an error bound.
//   - Between quorums the bound grows by nts.RhoPPM of the elapsed
//     monotonic time. Now fails once it is over MaxBound, so the signer
//     refuses rather than signs on a time it cannot vouch for.
//   - Now also fails once the oldest sample of the quorum in force is over
//     MaxAge old. The host sets the rate of the local clock: run fast
//     while the servers are blocked, it moves the time ahead by less than
//     its own count since the samples, so by less than MaxAge. Run slow,
//     it ages the samples slowly too, and the time can lag real time
//     without limit. Neither MaxAge nor the coarse check (on the same
//     local clock) catches that; the drift check does once new samples
//     come.
//   - Aging by rho holds only if the local clock (nts.Monotonic,
//     CLOCK_MONOTONIC_RAW) keeps within rho of real time. Each quorum is
//     checked against the last one and against a baseline quorum about 64
//     Intervals older; if the offset moved more than the two bounds and rho
//     allow, the quorum is refused and Now fails until a quorum of new
//     samples agrees with it. The short pair catches jumps, the long pair a
//     steady rate over rho that the bounds hide on a short pair.
//   - Coarse, the HTTPS-date quorum, is checked on every quorum: an NTS
//     time more than MaxCoarseDiff from it, after its one-second resolution
//     (NTSCoarseResolution), is refused, and Now fails until a quorum
//     passes, as after a drift refusal. The coarse clock must age its
//     reading on the same local clock (Anchored.Local = nts.Monotonic), or a
//     slewed Go monotonic clock adds its error. Coarse also gives
//     the certificate-validity time of NTS-KE and the NTP era. If Coarse has
//     no time, there is no NTS time either. There is no fallback to Coarse.
//   - Now never goes back, as for Anchored.
//   - With Protocol ProtocolNTP the clock asks each server's NTPAddr with
//     plain NTP: no NTS-KE and no cookies, so the NTS-KE retries and the
//     NTSN handling above do not apply. Nothing authenticates the answers,
//     so the host can forge all of them; the quorum, the bound and the
//     drift check then hold only against an honest host, and the coarse
//     check is the one limit left. Everything else is as with NTS.
type NTS struct {
	// Protocol is ProtocolNTS (also "") or ProtocolNTP.
	Protocol Protocol
	Servers  []NTSServer
	Coarse   interface{ Now() (time.Time, error) }
	Interval time.Duration // 0: NTSInterval
	MaxBound time.Duration // 0: NTSMaxBound
	// MaxSampleBound refuses a sample whose own bound is larger at receipt
	// (0: MaxBound). While it waits to join, its bound grows by rho, by at
	// most nts.Drift of the oldest join age (38 ms at 76 s under the shift
	// schedule); a sample under the cap at receipt joins for its whole join
	// age. A host that delays the one honest answer of a small fresh set
	// until its bound is wide lets two wrong servers place the time
	// anywhere inside it while the quorum's bound looks small. The bound is
	// a half-width, so that error is up to twice the cap plus the aging,
	// about 2 x (cap + 38 ms) (about 1 s each way without the cap). A far
	// region, whose samples are wide, raises MaxBound and this cap.
	MaxSampleBound time.Duration
	MaxAge         time.Duration // 0: NTSMaxAge, or NTSShiftMaxAge with Shifts
	MaxCoarseDiff  time.Duration // 0: NTSMaxCoarseDiff
	Dial           nts.DialFunc  // nil: the default dialer
	// StartDelay bounds the random wait of the first Refresh before it
	// contacts anyone. 0: NTSStartDelay (NTSShiftStartDelay with Shifts);
	// negative: none (a one-shot check that calls Refresh once).
	StartDelay time.Duration
	// Local is the monotonic clock in ns. Nil: nts.Monotonic, which the
	// samples use too. A test moves it ahead to age the bound.
	Local func() int64
	Log   *slog.Logger // nil: no logs
	// Shifts turns on the shift schedule (ntsshift.go): Servers is the
	// catalog, MaxAge defaults to NTSShiftMaxAge and an NTP query times out
	// after NTSShiftQueryTimeout. Until a seed is set every server is
	// asked once per NTSShiftMinGap; with one, ShiftActives(n) at a time.
	// Off: every server is asked every Interval.
	Shifts bool
	// ScheduleSeed is the seed of the shift schedule from the start, and
	// turns Shifts on. SetScheduleSeed sets it later. It should be fixed
	// per signer and unknown to the host, so the order cannot be computed
	// ahead from public data and signers spread over the operators. A host
	// that watches the traffic still learns the order within one cycle,
	// and can keep the first window active by restarting the signer
	// (newNTSShifts). Refresh refuses an empty seed: every signer would
	// share its order.
	ScheduleSeed []byte

	minPoll time.Duration // 0: NTSMinPoll; tests set it lower
	maxPoll time.Duration // 0: NTSMaxPoll; tests set it lower
	// randN returns a random number in [0, n). Nil: math/rand/v2 Int64N;
	// tests set a seeded one. Polls call it in parallel.
	randN func(n int64) int64
	// sleep waits d. Nil: a timer; tests move a fake clock.
	sleep func(d time.Duration)
	// started is set by the first Refresh, after its start wait. Under rmu.
	started bool

	shifts *ntsShifts // set by init when ScheduleSeed is set
	// queryTimeout replaces the NTP query timeout in tests; 0: the default.
	queryTimeout time.Duration
	// testQuery, if set, stands in for NTS-KE and the NTP query (tests).
	// at is the local time the query goes out.
	testQuery    func(ctx context.Context, operator string, at int64) (nts.Sample, error)
	noStartDelay bool // tests: no NTSShiftStartDelay before the first tick
	// resolveAnyDial: resolve the NTP host at NTS-KE with a Dial set too
	// (the live test records dials through its own Dial).
	resolveAnyDial bool

	once   sync.Once
	rmu    sync.Mutex // one Refresh at a time; Status waits for it
	mu     sync.Mutex // result, highest, lastErr
	peers  []*ntsPeer
	result *ntsResult // served by Now; nil until a quorum passes all checks
	// served is set once a quorum has passed; before that NTS-KE is tried
	// again after about Interval (3/4 to 5/4 of it), without backoff.
	served atomic.Bool
	// hist holds the quorums of the drift check, oldest first: the last one
	// (served or refused) at the end, the baseline at index 0. A refused
	// quorum starts a new history.
	hist    []*ntsResult
	highest time.Time
	drift   ntsDrift
	// violations counts quorums refused by the drift check.
	violations int64
	// refusedT4 is the newest sample (T4) of the last quorum the drift
	// check refused. Samples up to it do not enter a quorum again.
	refusedT4  int64
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
	sampled int64         // local ns of the oldest sample (T4) in the quorum
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
	disabled string // the kiss code that stopped the server, until reEnable
	reEnable int64
	lastErr  error
	// lostInRow counts the queries in a row that got no answer and no
	// kiss; at ntsKEAfterLost the next contact runs NTS-KE first, once per
	// such streak (lostKE), until an answer ends it.
	lostInRow int
	lostKE    bool
	stats     NTSPeerStats
	// contacted is the local time of the last contact under the shift
	// schedule, 0 for none.
	contacted int64
	// health is what NTSSummary reports of this server. Unlike the fields
	// above it is under n.mu, so HEALTH does not wait for a Refresh.
	health ntsPeerHealth
}

type ntsPeerHealth struct {
	queries, answers, losses int64
	wide                     int64 // losses that were answers over MaxSampleBound
	keOK, keFail             int64
	lastAnswer               int64 // local ns of the last answer, 0 for none
	off, lastErr             string
}

// noteHealth updates p's health under n.mu.
func (n *NTS) noteHealth(p *ntsPeer, f func(h *ntsPeerHealth)) {
	n.mu.Lock()
	defer n.mu.Unlock()
	f(&p.health)
}

// ntsHealthErrMax is the longest last_error HEALTH carries per server, in
// octets. TLS and NTS-KE errors bound the text in practice; this keeps a
// HEALTH frame small whatever a server sends.
const ntsHealthErrMax = 256

// healthErr is err's text for HEALTH, cut at ntsHealthErrMax octets.
func healthErr(err error) string {
	s := err.Error()
	if len(s) > ntsHealthErrMax {
		s = strings.ToValidUTF8(s[:ntsHealthErrMax], "") + "..."
	}
	return s
}

// reEnablePeer clears a server's DENY or RSTR stop once its time is up.
func (n *NTS) reEnablePeer(p *ntsPeer, now int64) {
	if p.disabled != "" && now >= p.reEnable {
		p.disabled = ""
		n.noteHealth(p, func(h *ntsPeerHealth) { h.off = "" })
	}
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
	// Wide counts answers refused for a bound over MaxSampleBound.
	Wide int
}

func (n *NTS) interval() time.Duration { return cmpOr(n.Interval, NTSInterval) }
func (n *NTS) maxBound() time.Duration { return cmpOr(n.MaxBound, NTSMaxBound) }
func (n *NTS) maxSampleBound() time.Duration {
	return cmpOr(n.MaxSampleBound, n.maxBound())
}
func (n *NTS) shiftMode() bool { return n.Shifts || n.ScheduleSeed != nil }

// plain says whether the clock runs plain NTP (ProtocolNTP).
func (n *NTS) plain() bool { return n.Protocol == ProtocolNTP }

// protocol is Protocol with "" read as ProtocolNTS.
func (n *NTS) protocol() Protocol { return cmp.Or(n.Protocol, ProtocolNTS) }

// SetScheduleSeed switches the shift schedule from every operator to
// ShiftActives(n) in the order seed gives, for a clock that starts before
// its seed is known. Contacts made so far keep their minimum gap. No effect
// without Shifts. An empty seed is refused and changes nothing.
func (n *NTS) SetScheduleSeed(seed []byte) error {
	if len(seed) == 0 {
		return errors.New("clock: nts: empty schedule seed")
	}
	n.init()
	if n.shifts != nil {
		n.shifts.reseed(seed)
	}
	return nil
}
func (n *NTS) maxAge() time.Duration {
	if n.shiftMode() {
		return cmpOr(n.MaxAge, NTSShiftMaxAge)
	}
	return cmpOr(n.MaxAge, NTSMaxAge)
}

// sampleMaxAge is the oldest a sample may be to join a quorum, in local ns:
// joinAge, and without the shift schedule also at most 4 x Interval.
func (n *NTS) sampleMaxAge() int64 {
	if n.shiftMode() {
		return int64(n.joinAge())
	}
	return int64(min(4*n.interval(), n.joinAge()))
}
func (n *NTS) maxDiff() time.Duration  { return cmpOr(n.MaxCoarseDiff, NTSMaxCoarseDiff) }
func (n *NTS) minPollD() time.Duration { return cmpOr(n.minPoll, NTSMinPoll) }
func (n *NTS) maxPollD() time.Duration { return cmpOr(n.maxPoll, NTSMaxPoll) }
func (n *NTS) baseline() int64         { return int64(ntsDriftBaselinePolls * n.interval()) }

// joinAge is the oldest a sample may be to join a quorum: it must stay
// under MaxAge until the next quorum can replace that quorum, or Now fails
// in between. Run starts the next Refresh at most a tick (Interval/4) after
// one ends, and a Refresh takes at most ntsRefreshLimit: one NTS-KE and one
// query (the polls run in parallel), or under the shift schedule its
// deadline (refreshShifts). 46 s with the defaults, 76 s under the shift
// schedule. Refresh refuses a MaxAge that leaves it at 0 or below.
func (n *NTS) joinAge() time.Duration {
	return n.maxAge() - n.interval()/4 - ntsRefreshLimit
}

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
		if n.shiftMode() {
			n.shifts = newNTSShifts(len(n.peers), n.ScheduleSeed, n.interval()/4)
		}
	})
}

// startWait is the wait of the first Refresh before it contacts anyone: a
// random time under StartDelay. It moves the whole schedule of this signer,
// so a caller that refreshes on a fixed grid (the runner's start loop) moves
// with it. A wait in nextKE alone would round up to the caller's next call.
func (n *NTS) startWait(ctx context.Context) error {
	d := n.StartDelay
	if d == 0 {
		d = NTSStartDelay
	}
	if d < 0 {
		return nil
	}
	w := time.Duration(n.random(int64(d)))
	if n.sleep != nil {
		n.sleep(w)
		return ctx.Err()
	}
	t := time.NewTimer(w)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// random returns a random number in [0, limit).
func (n *NTS) random(limit int64) int64 {
	if n.randN != nil {
		return n.randN(limit)
	}
	return rand.Int64N(limit)
}

func (n *NTS) Source() string {
	ops := make([]string, len(n.Servers))
	for i, s := range n.Servers {
		ops[i] = s.Operator
	}
	return string(n.protocol()) + "(" + strings.Join(ops, ",") + ")"
}

// Trusted is true for plain NTP too: the coarse check, over authenticated
// HTTPS, still bounds the time against the host (Protocol).
func (n *NTS) Trusted() bool { return true }

// logf logs with protocol=ntp-unauthenticated on every line of a plain NTP
// clock, so no log line passes for NTS.
func (n *NTS) logf(level slog.Level, msg string, args ...any) {
	if n.Log != nil {
		if n.plain() {
			args = append(args, "protocol", "ntp-unauthenticated")
		}
		n.Log.Log(context.Background(), level, msg, args...)
	}
}

// checkServers refuses a list nts.Quorum would refuse at every quorum:
// more than nts.MaxServers servers, an operator label outside 1 to
// nts.MaxOperatorLen octets, or an operator named twice.
func checkServers(servers []NTSServer) error {
	if len(servers) > nts.MaxServers {
		return fmt.Errorf("clock: nts: %d servers, at most %d", len(servers), nts.MaxServers)
	}
	seen := map[string]bool{}
	for _, s := range servers {
		if len(s.Operator) == 0 || len(s.Operator) > nts.MaxOperatorLen {
			return fmt.Errorf("clock: nts: server %q: operator label %q: 1 to %d octets", s.Host, s.Operator, nts.MaxOperatorLen)
		}
		if seen[s.Operator] {
			return fmt.Errorf("clock: nts: operator %q named twice", s.Operator)
		}
		seen[s.Operator] = true
	}
	return nil
}

// Refresh asks the servers that are due, then forms a new quorum.
func (n *NTS) Refresh(ctx context.Context) error {
	n.init()
	n.rmu.Lock()
	defer n.rmu.Unlock()
	if p := n.protocol(); p != ProtocolNTS && p != ProtocolNTP {
		err := fmt.Errorf("clock: nts: protocol %q: want nts or ntp", p)
		n.setErr(err)
		return err
	}
	// A list nts.Quorum refuses would fail every quorum.
	if err := checkServers(n.Servers); err != nil {
		n.setErr(err)
		return err
	}
	if n.ScheduleSeed != nil && len(n.ScheduleSeed) == 0 {
		err := errors.New("clock: nts: empty schedule seed: every signer would share its order")
		n.setErr(err)
		return err
	}
	if n.joinAge() <= 0 {
		err := fmt.Errorf("clock: nts: MaxAge %v is too short: no sample could join a quorum; it must be over %v (a tick of Run and the longest Refresh)",
			n.maxAge(), n.maxAge()-n.joinAge())
		n.setErr(err)
		return err
	}
	if n.shifts != nil {
		return n.refreshShifts(ctx)
	}
	if !n.started {
		n.started = true
		if err := n.startWait(ctx); err != nil {
			return err
		}
	}
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
		n.reEnablePeer(p, now)
		if p.disabled != "" || now < p.nextPoll {
			continue
		}
		wg.Add(1)
		go func(p *ntsPeer) {
			defer wg.Done()
			n.poll(ctx, p, coarse, now)
		}(p)
	}
	wg.Wait()
	return n.combine(coarse, coarseLocal)
}

// refreshShifts is one tick of the shift schedule: the queries due, a
// fallback for each lost answer of an active, a burst if fewer than
// NTSShiftBurstBelow samples are fresh, then the quorum.
func (n *NTS) refreshShifts(ctx context.Context) error {
	if !n.started {
		// Spreads the first contacts of signers that start together. Once
		// per clock, also when the coarse clock has no time yet; none for
		// a negative StartDelay.
		n.started = true
		if !n.noStartDelay && n.StartDelay >= 0 {
			// The seed's delay is under NTSShiftStartDelay; a positive
			// StartDelay scales it to under StartDelay.
			d := n.shifts.startDelay
			if n.StartDelay > 0 {
				d = time.Duration(float64(d) * float64(n.StartDelay) / float64(NTSShiftStartDelay))
			}
			if n.sleep != nil {
				n.sleep(d)
				if err := ctx.Err(); err != nil {
					return err
				}
			} else {
				t := time.NewTimer(d)
				select {
				case <-t.C:
				case <-ctx.Done():
					t.Stop()
					return ctx.Err()
				}
			}
		}
	}
	coarse, err := n.Coarse.Now()
	coarseLocal := n.local()
	if err != nil {
		n.shifts.idle(coarseLocal)
		err = fmt.Errorf("clock: nts: no coarse time: %w", err)
		n.setErr(err)
		return err
	}
	// All rounds share one deadline, so the tick ends within
	// ntsRefreshLimit and the samples that join its quorum (joinAge) are
	// still under MaxAge when the next quorum forms. A round cut short loses
	// its late answers; the next tick asks again.
	ctx, cancel := context.WithTimeout(ctx, ntsRefreshLimit)
	defer cancel()
	// Three rounds, each in parallel: the queries due at the start of the
	// tick, then one fallback per lost active, then the burst. A contact
	// made after the start of the tick counts at a later tick (after), so
	// the next contact with that operator is still NTSShiftMinGap after it.
	tick := int64(n.interval() / 4)
	after := func(at int64) int { return max(1, int((at-coarseLocal+tick-1)/tick)) }
	lost := n.askAll(ctx, coarse, n.shifts.plan(coarseLocal, n.askable(coarseLocal)), coarseLocal)
	// Past the deadline the later rounds would mark contacts, use the
	// fallback cap and back off NTS-KE without sending anything.
	if ctx.Err() != nil {
		return n.combineShifts(coarse, coarseLocal)
	}
	var fallbacks []ntsAsk
	at := n.local()
	can := n.askable(at)
	for _, l := range lost {
		if l.role != roleActive {
			continue
		}
		// A wide answer leaves the quorum short like a lost one, so another
		// operator may stand in. Asking the same operator again soon would
		// most likely give another wide answer, and a RATE asks for less.
		if op, found := n.shifts.fallback(l.op, after(at), l.sent && !l.wide && !l.rate, can); found {
			fallbacks = append(fallbacks, ntsAsk{op, roleFallback})
		}
	}
	n.askAll(ctx, coarse, fallbacks, at)
	if ctx.Err() == nil && n.fresh() < NTSShiftBurstBelow {
		at := n.local()
		n.askAll(ctx, coarse, n.shifts.burst(after(at), n.askable(at)), at)
	}
	return n.combineShifts(coarse, coarseLocal)
}

// askable says by operator whether a contact at local time now would send
// anything: not stopped by DENY or RSTR, and not waiting out an NTS-KE
// backoff without cookies (plain NTP has no NTS-KE). Fallbacks and bursts
// skip the others, so they do not spend the cap or a contact on a server
// they cannot reach.
func (n *NTS) askable(now int64) []bool {
	out := make([]bool, len(n.peers))
	for i, p := range n.peers {
		n.reEnablePeer(p, now)
		needKE := !n.plain() && (p.assoc == nil || p.assoc.Cookies() == 0)
		out[i] = p.disabled == "" && (n.testQuery != nil || !needKE || now >= p.nextKE)
	}
	return out
}

// combineShifts is combine; a quorum ends the start retries of the schedule.
func (n *NTS) combineShifts(coarse time.Time, coarseLocal int64) error {
	err := n.combine(coarse, coarseLocal)
	if err == nil {
		n.shifts.quorum()
	}
	return err
}

// ntsLost is an ask that got no sample. sent: a request went out; wide:
// the server answered with a bound over MaxSampleBound; rate: with a
// Kiss-o'-Death RATE.
type ntsLost struct {
	ntsAsk
	sent, wide, rate bool
}

// askAll polls asks in parallel, sent at local time at, and returns those
// that got no sample. A server stopped by DENY or RSTR counts as lost.
func (n *NTS) askAll(ctx context.Context, coarse time.Time, asks []ntsAsk, at int64) []ntsLost {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var lost []ntsLost
	for _, a := range asks {
		p := n.peers[a.op]
		n.reEnablePeer(p, at)
		wg.Add(1)
		go func() {
			defer wg.Done()
			ke := p.stats.KEOK + p.stats.KEFail
			queries := p.stats.Queries
			// A retry of a lost answer may come NTSShiftStartRetry after it;
			// the next contact is still a full gap after the lost one.
			gap, retry := n.shifts.minGap(a.op), a.role == roleRetry
			if retry {
				gap = NTSShiftStartRetry
			}
			ok := p.disabled == "" && n.waitGap(ctx, p, at, gap, retry) && n.poll(ctx, p, coarse, at)
			if a.role == roleFallback && p.stats.KEOK+p.stats.KEFail != ke {
				n.shifts.fallbackKE(a.op)
			}
			// p.lastErr is this contact's only if a query went out: a
			// contact that failed before (NTS-KE, the gap) leaves the last
			// one's, which must not count again.
			sent := p.stats.Queries != queries
			var kiss *nts.KissError
			var w *wideSampleError
			rate := !ok && sent && errors.As(p.lastErr, &kiss) && kiss.Code == "RATE"
			wide := !ok && sent && errors.As(p.lastErr, &w)
			n.shifts.result(a, ok, rate, wide, sent)
			if !ok {
				mu.Lock()
				lost = append(lost, ntsLost{a, sent, wide, rate})
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return lost
}

// waitGap keeps contacts with p at least gap (NTSShiftMinGap, or
// NTSShiftStartRetry before the first quorum and for the retry of a lost
// answer) apart in local time. The schedule keeps them 15 ticks (5 for a
// retry) apart, but a tick can come a few ms early against the one before
// (the live run saw 59.999 s); waitGap waits out such a shortfall. A
// shortfall over one tick would be a bug of the schedule: no contact then.
// keep: the contact does not count as the last one (the retry of a lost
// answer), so the next is measured from the one before it.
func (n *NTS) waitGap(ctx context.Context, p *ntsPeer, at int64, gap time.Duration, keep bool) bool {
	if p.contacted != 0 {
		if wait := time.Duration(p.contacted + int64(gap) - at); wait > 0 {
			if wait > n.interval()/4 {
				n.logf(slog.LevelError, "nts: contact within the minimum gap refused", "operator", p.srv.Operator, "short_by", wait)
				return false
			}
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return false
			}
			at += int64(wait)
		}
	}
	if !keep {
		p.contacted = at
	}
	return true
}

// fresh counts the samples that would join a quorum now.
func (n *NTS) fresh() int {
	now, c := n.local(), 0
	for _, p := range n.peers {
		if n.joins(p, now, n.sampleMaxAge()) {
			c++
		}
	}
	return c
}

// joins says whether p's sample may join a quorum at local time now: at
// most maxAge old, newer than a refused quorum, and within MaxSampleBound
// at receipt (record refuses wider ones; this keeps that true here). Its
// bound, aged by rho as the quorum ages it, is then at most the cap plus
// nts.Drift(maxAge), 38 ms at the 76 s join age of the shift schedule, so
// a sample under the cap joins for its whole join age. Checking the aged
// bound against the cap alone would let a sample with bound B join for
// only 2 x (cap - B) seconds at 500 ppm, 30 s at 85 ms, less than the 60 s
// until its operator's next contact.
func (n *NTS) joins(p *ntsPeer, now, maxAge int64) bool {
	s := p.sample
	return s != nil && now-s.T4 <= maxAge && s.T4 > n.refusedT4 && s.Bound <= n.maxSampleBound()
}

// certTime is the time NTS-KE checks certificate validity at: the coarse
// clock's, not the host's. Without a coarse time it is the zero time, which
// nts.KeyExchange takes as "no trusted time": it refuses before the dial,
// and during the handshake checks at nts.NoTrustedTime, never at the
// system clock.
func (n *NTS) certTime() time.Time {
	t, err := n.Coarse.Now()
	if err != nil {
		return time.Time{}
	}
	return t
}

// poll runs NTS-KE if needed, then one query, and says whether a sample
// came. at is the local time it starts (for testQuery). Only this peer's fields are written, and Refresh runs one poll per
// peer at a time.
func (n *NTS) poll(ctx context.Context, p *ntsPeer, coarse time.Time, at int64) bool {
	var s nts.Sample
	var err error
	if n.testQuery != nil {
		s, err = n.testQuery(ctx, p.srv.Operator, at)
		p.stats.Queries++
	} else {
		if n.plain() {
			n.plainAddr(ctx, p)
		} else if !n.keyExchange(ctx, p) {
			return false
		}
		timeout := ntsExchangeTimeout
		if n.shifts != nil {
			timeout = NTSShiftQueryTimeout
		}
		timeout = cmpOr(n.queryTimeout, timeout)
		qctx, cancel := context.WithTimeout(ctx, timeout)
		if n.plain() {
			s, err = nts.QueryPlain(qctx, p.ntpAddr, coarse, n.Dial)
		} else {
			s, err = p.assoc.Query(qctx, p.ntpAddr, coarse, n.Dial)
		}
		cancel()
		p.stats.Queries++
		if p.assoc != nil {
			p.stats.CookiesHeld = p.assoc.Cookies()
		}
		if err != nil && ctx.Err() != nil {
			// The caller's deadline (the tick's) cut the query, not the
			// server or its own timeout: no loss, no streak, no HEALTH
			// error for a server that may be fine. The request went out,
			// so its cookie (NTS) is used, and the contact stays marked.
			p.lastErr = err
			return false
		}
	}
	return n.record(p, s, err)
}

// plainAddr sets p.ntpAddr for plain NTP: NTPAddr, or Host:123. Under the
// shift schedule with the default dialer it resolves the name once, as
// keyExchange does at NTS-KE, and again once per streak of
// ntsKEAfterLost lost queries, in case the name moved.
func (n *NTS) plainAddr(ctx context.Context, p *ntsPeer) {
	stale := p.ntpAddr != "" && p.lostInRow >= ntsKEAfterLost && !p.lostKE
	if p.ntpAddr != "" && !stale {
		return
	}
	if stale {
		p.lostKE = true
	}
	addr := p.srv.NTPAddr
	if addr == "" {
		addr = net.JoinHostPort(p.srv.Host, "123")
	}
	if n.shifts != nil && (n.Dial == nil || n.resolveAnyDial) {
		addr = n.resolve(ctx, addr)
	}
	p.ntpAddr = addr
}

// ntsKEAfterLost is how many queries in a row may go unanswered before the
// next contact runs NTS-KE again. A server that rotated its keys should
// answer an old cookie with NTSN, but one that drops it would otherwise
// cost all 8 cookies (8 contacts, 8 minutes on the 60 s grid) first. This
// NTS-KE runs once per streak of losses: on a path that drops NTP but not
// NTS-KE, a server gets one more NTS-KE per streak, not one per 3 queries.
const ntsKEAfterLost = 3

// keyExchange runs NTS-KE if p has no cookies left, or once after
// ntsKEAfterLost lost queries in a row, and says whether p can be queried.
// The second kind keeps the old cookies until NTS-KE succeeds, so a failed
// or backed-off NTS-KE costs nothing.
func (n *NTS) keyExchange(ctx context.Context, p *ntsPeer) bool {
	now := n.local()
	usable := p.assoc != nil && p.assoc.Cookies() > 0
	stale := usable && p.lostInRow >= ntsKEAfterLost && !p.lostKE
	if usable && !stale {
		return true
	}
	if !usable && p.assoc != nil {
		p.assoc.Close()
		p.assoc = nil
	}
	if now < p.nextKE || ctx.Err() != nil {
		return stale
	}
	if stale {
		p.lostKE = true
	}
	kctx, cancel := context.WithTimeout(ctx, ntsExchangeTimeout)
	r, err := nts.KeyExchange(kctx, nts.KEConfig{
		Host: p.srv.Host, Addr: p.srv.KEAddr, Roots: p.srv.Roots, Dial: n.Dial,
		Time: n.certTime,
	})
	cancel()
	if err != nil && ctx.Err() != nil {
		// The caller's deadline ran out, not the server: no backoff, and
		// the re-key of a loss streak is not used up.
		if stale {
			p.lostKE = false
		}
		p.lastErr = err
		n.noteHealth(p, func(h *ntsPeerHealth) { h.lastErr = healthErr(err) })
		return stale
	}
	if err != nil {
		p.stats.KEFail++
		p.lastErr = err
		n.noteHealth(p, func(h *ntsPeerHealth) { h.keFail++; h.lastErr = healthErr(err) })
		if n.served.Load() {
			p.keWait = min(max(2*p.keWait, n.interval()), n.maxPollD())
		} else {
			// No backoff before the first quorum, but random, so signers
			// that failed together do not try again together.
			p.keWait = n.interval()*3/4 + time.Duration(n.random(int64(n.interval()/2)))
		}
		p.nextKE = now + int64(p.keWait)
		n.logf(slog.LevelWarn, "nts: key exchange failed", "operator", p.srv.Operator, "host", p.srv.Host, "retry_in", p.keWait, "err", err)
		return stale
	}
	p.stats.KEOK++
	n.noteHealth(p, func(h *ntsPeerHealth) { h.keOK++ })
	p.stats.LastKE = r.Elapsed
	p.stats.CookiesAfterKE = r.Assoc.Cookies()
	p.keWait = 0
	if p.assoc != nil {
		p.assoc.Close()
	}
	p.assoc, p.ntpAddr = r.Assoc, r.NTPAddr
	if n.shifts != nil && (n.Dial == nil || n.resolveAnyDial) {
		p.ntpAddr = n.resolve(ctx, p.ntpAddr)
	}
	n.logf(slog.LevelInfo, "nts: key exchange", "operator", p.srv.Operator, "host", p.srv.Host, "ntp", r.NTPAddr,
		"cookies", p.stats.CookiesAfterKE, "took", r.Elapsed.Round(time.Millisecond))
	return true
}

// resolve looks up the host of addr (host:port) once, at NTS-KE, so the
// short NTP timeout does not include a DNS lookup. On failure addr stays
// as it is, and each query looks it up. Only for the default dialer: a
// platform dialer (the Nitro UDP relay) resolves on its side.
func (n *NTS) resolve(ctx context.Context, addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || net.ParseIP(host) != nil {
		return addr
	}
	lctx, cancel := context.WithTimeout(ctx, ntsExchangeTimeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(lctx, "ip", host)
	if err != nil || len(ips) == 0 {
		n.logf(slog.LevelWarn, "nts: no address for the NTP host; each query looks it up", "host", host, "err", err)
		return addr
	}
	return net.JoinHostPort(ips[0].Unmap().String(), port)
}

// wideSampleError is an answer whose bound is over MaxSampleBound.
type wideSampleError struct{ bound, limit time.Duration }

func (e *wideSampleError) Error() string {
	return fmt.Sprintf("sample bound %v over the %v limit (MaxSampleBound)", e.bound.Round(time.Microsecond), e.limit)
}

// record takes the outcome of one query.
func (n *NTS) record(p *ntsPeer, s nts.Sample, err error) bool {
	wide := false
	p.nextPoll = n.local() + int64(p.poll)
	var kiss *nts.KissError
	switch {
	case errors.As(err, &kiss):
		p.stats.Kisses[kiss.Code]++
		p.lastErr = err
		switch kiss.Code {
		case "RATE":
			p.poll = min(2*p.poll, n.maxPollD())
			p.nextPoll = n.local() + int64(p.poll)
		case "DENY", "RSTR":
			// A Kiss-o'-Death carries no authenticator, so anyone who sees
			// the request can forge one. Stop for maxPoll, not for good.
			p.disabled = kiss.Code
			p.reEnable = n.local() + int64(n.maxPollD())
			p.sample = nil
		case "NTSN":
			if p.assoc != nil {
				p.assoc.Close()
				p.assoc = nil
			}
		}
		n.logf(slog.LevelWarn, "nts: kiss-o'-death", "operator", p.srv.Operator, "code", kiss.Code, "poll", p.poll)
	case err != nil:
		p.stats.Errors++
		p.lostInRow++
		p.lastErr = err
		n.logf(slog.LevelWarn, "nts: query failed", "operator", p.srv.Operator, "err", err)
	case s.Bound > n.maxSampleBound():
		// An answer, but too wide to join a quorum: it counts as lost (a
		// fallback may follow), and the earlier sample stays until it ages
		// out. It is authenticated, so the cookies work: it ends a loss
		// streak, and the next lost query does not run NTS-KE early.
		p.stats.Wide++
		wide = true
		p.lostInRow, p.lostKE = 0, false
		p.stats.LastDelay, p.stats.LastBound = s.Delay, s.Bound
		err = &wideSampleError{bound: s.Bound, limit: n.maxSampleBound()}
		p.lastErr = err
		n.logf(slog.LevelWarn, "nts: sample too wide", "operator", p.srv.Operator, "bound", s.Bound, "delay", s.Delay, "limit", n.maxSampleBound())
	default:
		p.stats.Samples++
		p.lostInRow, p.lostKE = 0, false
		p.sample = &s
		p.lastErr = nil
		p.poll = max(p.poll/2, max(n.interval(), n.minPollD()))
		p.stats.LastDelay, p.stats.LastBound = s.Delay, s.Bound
		p.stats.LastOffsetFromHost = time.Duration(s.Offset + nts.Monotonic() - time.Now().UnixNano())
	}
	now, off := n.local(), p.disabled
	n.noteHealth(p, func(h *ntsPeerHealth) {
		h.queries++
		h.off = off
		if wide {
			h.wide++
		}
		if err != nil {
			h.losses++
			h.lastErr = healthErr(err)
			return
		}
		h.answers++
		h.lastAnswer = now
		h.lastErr = ""
	})
	return err == nil
}

// combine forms the quorum of the fresh samples and checks it against the
// coarse time.
func (n *NTS) combine(coarse time.Time, coarseLocal int64) error {
	now := n.local()
	maxAge := n.sampleMaxAge()
	var in []nts.Interval
	var errs []error
	for _, p := range n.peers {
		if p.lastErr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p.srv.Operator, p.lastErr))
		}
		if !n.joins(p, now, maxAge) {
			continue
		}
		in = append(in, nts.Interval{Operator: p.srv.Operator, Offset: p.sample.Offset, Bound: p.sample.Bound, T4: p.sample.T4})
	}
	q, err := nts.Quorum(in, now, nts.QuorumWrong(len(in)))
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
	refused := coarseRefused(diff, n.maxDiff(), NTSCoarseResolution)
	if refused {
		err = fmt.Errorf("clock: nts: quorum time %s is %v from the coarse clock (allowed %v to %v with its %v resolution); refused",
			t.UTC().Format(time.RFC3339Nano), diff, -n.maxDiff(), n.maxDiff()+NTSCoarseResolution, NTSCoarseResolution)
	}
	n.mu.Lock()
	n.coarseDiff = diff
	if refused {
		// The quorum in force is not served on: Now fails until a quorum
		// passes this check.
		n.result, n.lastErr = nil, err
	}
	n.mu.Unlock()
	if refused {
		n.logf(slog.LevelError, "nts: coarse check failed", "diff", diff, "max", n.maxDiff(), "resolution", NTSCoarseResolution)
		return err
	}
	members := make([]string, len(in))
	for i, v := range in {
		members[i] = v.Operator
	}
	sampled := now
	for _, v := range in {
		sampled = min(sampled, v.T4)
	}
	cur := &ntsResult{offset: q.Offset, bound: q.Bound, at: now, sampled: sampled, members: members, lo: q.Lo, hi: q.Hi}
	n.mu.Lock()
	// The bound grows by rho only if the local clock keeps within rho of
	// real time. Check that against the last quorum and the baseline: both
	// intervals of a pair hold the real offset (at most a minority of
	// servers wrong in each), and it can move by at most rho times the time between them. If
	// a pair does not fit, the local clock broke rho (or more servers are
	// wrong): this quorum is not served, a new history starts with it, and
	// the next quorum, of new samples only, must agree with it first.
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
			for _, v := range in {
				n.refusedT4 = max(n.refusedT4, v.T4)
			}
			err = fmt.Errorf("clock: nts: offset moved %v in %v (%.0f ppm, +-%.0f ppm from the bounds), more than its bounds and rho allow (%v); "+
				"the local clock does not keep within %d ppm: refused until a quorum of new samples agrees", delta, d.baseline.Round(time.Millisecond),
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
	n.served.Store(true)
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
	bound, _, why := n.check(now)
	if why != "" {
		n.refusals.Add(1)
		return time.Time{}, bound, errors.New("clock: nts: " + why)
	}
	t := time.Unix(0, now+n.result.offset)
	if t.Before(n.highest) {
		t = n.highest
	}
	n.highest = t
	return t, bound, nil
}

// check says why the quorum in force gives no time at local time now, or
// "" when it does, with its bound then and the age of its oldest sample.
// Call with n.mu held.
func (n *NTS) check(now int64) (bound, age time.Duration, why string) {
	r := n.result
	if r == nil {
		return 0, 0, fmt.Sprintf("no quorum yet: %v", n.lastErr)
	}
	// AddBound saturates, and a negative bound is refused as well: a bound
	// that wrapped around once let a quorum months old serve time again
	// (TIME-BOUND-01).
	bound = nts.AddBound(r.bound, nts.Drift(time.Duration(now-r.at)))
	age = time.Duration(now - r.sampled)
	switch {
	case bound < 0 || bound > n.maxBound():
		why = fmt.Sprintf("error bound %v over %v (last quorum %v ago): %v",
			bound, n.maxBound(), time.Duration(now-r.at).Round(time.Second), n.lastErr)
	case age > n.maxAge():
		why = fmt.Sprintf("samples of the last quorum %v old, over %v (no fresh quorum): %v",
			age.Round(time.Millisecond), n.maxAge(), n.lastErr)
	}
	return bound, age, why
}

// Now is Bounded without the bound.
func (n *NTS) Now() (time.Time, error) {
	t, _, err := n.Bounded()
	return t, err
}

// NTSStatus is a snapshot for logs and tests.
type NTSStatus struct {
	Protocol Protocol // ProtocolNTS, or ProtocolNTP (unauthenticated)
	Members  []string
	Bound    time.Duration // of the last quorum, at its time
	// BoundNow is Bound grown by rho since the last quorum, AgeOfQuorum
	// that time, SampleAge the age of its oldest sample. OffsetFromHost is the NTS time minus the host clock (for
	// logs; the host clock is not used for anything else).
	BoundNow       time.Duration
	AgeOfQuorum    time.Duration
	SampleAge      time.Duration
	OffsetFromHost time.Duration
	Lo, Hi         int64
	// DriftPPM is the local clock's rate error against NTS, measured from
	// a baseline quorum to the last quorum, DriftBaseline apart (up to 64
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
	Refusals   int64 // Now calls refused for the bound or the sample age
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
// in force, its bound is within MaxBound and its samples within MaxAge.
// Refused says why not.
func (n *NTS) NTSSummary() NTSSummary {
	n.init()
	n.mu.Lock()
	defer n.mu.Unlock()
	s := NTSSummary{Protocol: n.protocol(), MaxBound: n.maxBound(), MaxSampleAge: n.maxAge(), Refusals: n.refusals.Load(), DriftPPM: n.drift.ppm,
		DriftErrPPM: n.drift.errPPM, DriftBaseline: n.drift.baseline, RhoViolations: n.violations, CoarseDiff: n.coarseDiff}
	now := n.local()
	s.BoundNow, s.SampleAge, s.Refused = n.check(now)
	s.Quorum = s.Refused == ""
	if r := n.result; r != nil {
		s.Members = append([]string(nil), r.members...)
		s.AgeOfQuorum = time.Duration(now - r.at)
		s.OffsetFromHost = time.Duration(now + r.offset - time.Now().UnixNano())
	}
	if n.shifts != nil {
		names := make([]string, len(n.peers))
		for i, p := range n.peers {
			names[i] = p.srv.Operator
		}
		s.Actives, s.Operators, s.FallbacksCapped = n.shifts.snapshot(names)
	}
	s.Peers = make([]NTSPeerHealth, len(n.peers))
	for i, p := range n.peers {
		h := p.health
		ph := NTSPeerHealth{Operator: p.srv.Operator, Host: p.srv.Host, Queries: h.queries, Answers: h.answers, Losses: h.losses, Wide: h.wide,
			KEOK: h.keOK, KEFail: h.keFail, LastAnswerAge: -1, Off: h.off, LastError: h.lastErr,
			Active: n.shifts == nil || slices.Contains(s.Actives, p.srv.Operator)}
		if h.lastAnswer != 0 {
			ph.LastAnswerAge = time.Duration(now - h.lastAnswer)
		}
		s.Peers[i] = ph
	}
	// The coarse clock has its own lock and never calls the NTS clock.
	if c, ok := n.Coarse.(SourceStatser); ok {
		s.Coarse = c.SourceStats()
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
	st := NTSStatus{Protocol: n.protocol(), Refusals: n.refusals.Load(), Peers: map[string]NTSPeerStatus{}, DriftPPM: n.drift.ppm, DriftErrPPM: n.drift.errPPM,
		DriftBaseline: n.drift.baseline, RhoViolations: n.violations, CoarseDiff: n.coarseDiff}
	if r := n.result; r != nil {
		now := n.local()
		st.Members, st.Bound, st.Lo, st.Hi = r.members, r.bound, r.lo, r.hi
		st.AgeOfQuorum = time.Duration(now - r.at)
		st.SampleAge = time.Duration(now - r.sampled)
		st.BoundNow = nts.AddBound(r.bound, nts.Drift(st.AgeOfQuorum))
		st.OffsetFromHost = time.Duration(now + r.offset - time.Now().UnixNano())
	}
	if n.lastErr != nil {
		st.LastError = n.lastErr.Error()
	}
	for _, p := range n.peers {
		ps := NTSPeerStatus{Host: p.srv.Host, NTPAddr: p.ntpAddr, Disabled: p.disabled, Poll: p.poll, Sample: p.sample, Stats: p.stats}
		// A copy: poll writes the map after Status returns.
		ps.Stats.Kisses = maps.Clone(p.stats.Kisses)
		if p.lastErr != nil {
			ps.LastErr = p.lastErr.Error()
		}
		st.Peers[p.srv.Operator] = ps
	}
	return st
}
