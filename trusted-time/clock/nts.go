//go:build nts

package clock

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lidofinance/tee-signer/trusted-time/nts"
	ntscore "github.com/lidofinance/tee-signer/trusted-time/ntscore/go"
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
	// NTSStartWait is how long the start state lasts after a server swap
	// or a policy change left the clock without a quorum (NTS.StartWait):
	// the runner's default wait for the first quorum of a start.
	NTSStartWait = 90 * time.Second
	// ntsExchangeTimeout limits one NTS-KE session or one NTP query.
	ntsExchangeTimeout = nts.ExchangeTimeout
	// ntsRefreshLimit is the longest a Refresh contacts servers: one NTS-KE
	// and one query, or the deadline of a tick of the shift schedule.
	ntsRefreshLimit = 2 * ntsExchangeTimeout
)

// NTSServer is one NTS server and the operator who runs it: Host, Operator,
// Roots (the operator's pinned CA certificates, PEM; nts.RootsPEM for the
// public servers), KEAddr (host:port of NTS-KE; empty means Host:4460) and
// NTPAddr (host:port of the server's plain NTP service, for ProtocolNTP;
// empty means Host:123. With NTS the NTS-KE server names the NTP host).
type NTSServer = nts.Server

// NTS is a clock from NTS servers (RFC 8915) of distinct operators: the
// client of trusted-time/nts, the C core of trusted-time/ntscore under it,
// with this package's schedule, logs and status around it.
//
// The rules that decide the time are the core's (ntscore/c/client.c), and
// nothing here can change them: this package hands the core no sample, no
// time, no quorum rule and no era.
//
//   - Each server is asked every Interval (at least NTSMinPoll apart), with
//     the Kiss-o'-Death policy and the backoff of RFC 5905. Under NTS only
//     an authenticated Kiss-o'-Death is obeyed (anyone on the path can
//     forge another): RATE doubles that server's interval up to
//     NTSMaxPoll, each good answer halves it back; DENY or RSTR stops the
//     server for NTSMaxPoll, not for good; an NTSN (never authenticated)
//     is counted, and NTS-KE runs again when the cookies run out or after
//     3 lost queries in a row, once per such streak, the old cookies kept
//     until it succeeds.
//   - NTS-KE failures back off from Interval to NTSMaxPoll once a quorum
//     has been served; until then NTS-KE is tried again after a random 3/4
//     to 5/4 Interval (12 to 20 s), so a relay that comes up late does not
//     push the first quorum past the runner's start wait, and signers that
//     failed together do not try again together. A server swap or a policy
//     change that leaves no quorum brings these start retries back for
//     StartWait at most; then the backoff applies again, with or without a
//     quorum.
//   - The latest sample of each server goes to the quorum if it will stay
//     under MaxAge until the next quorum: at most MaxAge minus a tick of
//     Run and the longest Refresh (joinAge), 46 s with the defaults (and
//     at most 4 x Interval), 76 s under the shift schedule (no 4 x
//     Interval cap). Refresh refuses a MaxAge that leaves no room for
//     that. Of n such fresh samples (not of the servers) up to (n - 1) / 2
//     may be wrong, and at least 3 must agree (nts.QuorumWrong): the core
//     counts that itself. A sample wider than MaxSampleBound less its
//     aging over the join age is refused at receipt.
//   - Between quorums the bound grows by nts.RhoPPM of the elapsed
//     monotonic time and Now fails once it is over MaxBound, or once the
//     oldest sample of the quorum in force is over MaxAge old (the host
//     sets the rate of the local clock: run fast while the servers are
//     blocked, it moves the time ahead by less than MaxAge; run slow, the
//     time can lag real time without limit, which the drift check catches
//     once new samples come).
//   - Each quorum is checked against the last one and a baseline about 64
//     Intervals older (the drift check: a refused quorum's samples do not
//     enter a quorum again; a monotonic counter that went back is drift
//     too), against Coarse, the HTTPS-date quorum (the coarse check), and
//     against the sanity window of the NTP era: no time before
//     nts.FloorTime or over 20 years past the highest time served. The era
//     is read around that highest time, never around the coarse clock.
//   - Now never goes back. Coarse also dates the certificates of NTS-KE
//     before the first quorum; after it, the core's own time does. If
//     Coarse has no time, there is no NTS time either. Now has no fallback
//     to Coarse; CoarseNow reads it for a caller that allows its error.
//   - With Protocol ProtocolNTP the core asks each server's NTPAddr with
//     plain NTP: no NTS-KE and no cookies. Nothing authenticates the
//     answers, so the host can forge all of them; the quorum, the bound
//     and the drift check then hold only against an honest host, and the
//     coarse check is the one limit left. A plain Kiss-o'-Death RATE, DENY
//     or RSTR is obeyed as it comes. Everything else is as with NTS.
//
// What this package decides is only when to ask: if it stops asking, the
// bound ages past MaxBound and the core refuses the time. The first Refresh
// waits a random time under StartDelay before it contacts anyone, so
// signers that restart together spread their contacts. With Shifts it asks
// on the shift schedule (ntsshift.go).
//
// SetServers and SetPolicy change the core's configuration on a running
// clock. They are for the trusted configuration path only (the setup, a
// signed config update whose signatures the caller has checked); nothing
// driven by the network may reach them.
type NTS struct {
	// Protocol is ProtocolNTS (also "") or ProtocolNTP. Protocol, MaxBound
	// and MaxSampleBound are set before the first Refresh; SetPolicy
	// changes them on a running clock.
	Protocol Protocol
	Servers  []NTSServer
	Coarse   interface{ Now() (time.Time, error) }
	Interval time.Duration // 0: NTSInterval
	MaxBound time.Duration // 0: NTSMaxBound
	// MaxSampleBound caps a sample's bound (0: MaxBound; else MaxBound to
	// nts.MaxSampleBound). At receipt the bound must leave room for the
	// aging over the join age (nts.Drift, 38 ms at 76 s under the shift
	// schedule; receiptBound), so the aged bound stays within the cap for
	// as long as the sample may join. A host that delays the honest
	// answers of a small fresh set until their bounds are wide lets wrong
	// servers place the time anywhere inside them while the quorum's bound
	// looks small: two wrong of 4 or 5 fresh samples, and one wrong of
	// exactly 3, where none is outvoted (HEALTH worst_bound_ms shows that
	// case). The bound is a half-width, so that error is up to twice the
	// cap (about 1 s each way without the cap). A far region, whose
	// samples are wide, raises MaxBound and this cap.
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
	// StartWait limits the start state the clock goes back to when a
	// server swap or a policy change leaves it without a quorum
	// (SetServers, SetPolicy). 0: NTSStartWait. The runner sets its
	// -nts-wait, the time a real start has before the runner gives up. Set
	// before the first Refresh.
	StartWait time.Duration

	minPoll time.Duration // 0: NTSMinPoll; tests set it lower
	maxPoll time.Duration // 0: NTSMaxPoll; tests set it lower
	// randN returns a random number in [0, n), for the start wait. Nil:
	// math/rand/v2 Int64N; tests set a seeded one. (The key exchange
	// retry's random is the core's, from its CSPRNG.)
	randN func(n int64) int64
	// sleep waits d. Nil: a timer; tests move a fake clock.
	sleep func(d time.Duration)
	// started is set by the first Refresh, after its start wait. Under rmu.
	started bool
	// queryTimeout replaces the NTP query timeout in tests; 0: the default.
	queryTimeout time.Duration
	noStartDelay bool // tests: no NTSShiftStartDelay before the first tick
	// resolveAnyDial: resolve the NTP host once per NTS-KE with a Dial set
	// too (the live test records dials through its own Dial).
	resolveAnyDial bool
	// ops replaces the host operations of the client (tests: a virtual
	// world, ntsworld). The core still does all of its own work on the
	// bytes that world hands it. roundDone, if set, is called after each
	// round of parallel polls (the virtual world moves its clock past the
	// lost answers then).
	ops       ntscore.HostOps
	roundDone func()

	once    sync.Once
	inited  atomic.Bool // once has run
	rmu     sync.Mutex  // one Refresh at a time; Status, SetServers and SetPolicy wait for it
	mu      sync.Mutex  // client, peers, Servers, the three policy fields, lastErr, swaps
	client  *nts.Client
	initErr error
	lastErr error
	// peers is this package's side of each server, in the order of
	// Servers (the core's): what the schedule and HEALTH need. Replaced
	// under rmu and mu.
	peers  []*ntsPeer
	shifts *ntsShifts // set by init with the shift schedule
	// coldSched: the schedule is in the start state a swap or a policy
	// change began (the core's Status.Cold); endCold ends it. Under rmu.
	coldSched bool
	// refusedT4 is the newest sample (T4) at the last quorum the drift
	// check refused: the core lets no sample up to it join again, and
	// fresh, which only decides whether to ask more servers, does not
	// count them either. Under rmu.
	refusedT4 int64
	// swaps counts the server lists SetServers took. Under mu.
	swaps int64
	// left holds the servers swaps took out, by label and by host
	// (leftKeys). Under rmu.
	left map[string]ntsLeft
}

// ntsPeer is what this package keeps of one server: nothing the time
// rests on. The keys, the cookies, the sample and the poll interval are
// the core's.
type ntsPeer struct {
	srv NTSServer
	// contacted is the local time of the last contact under the shift
	// schedule, 0 for none. Under rmu.
	contacted int64
	// stop and stopUntil carry a DENY or RSTR stop over a swap: a server
	// that left while stopped and came back (by label or by host) is a new
	// peer to the core, so the schedule does not ask it before stopUntil.
	// Under rmu.
	stop      string
	stopUntil int64
	// health and hostOffset are under n.mu, so HEALTH does not wait for a
	// Refresh. hostOffset is the last sample's time minus the host clock,
	// for logs only.
	health     ntsPeerHealth
	hostOffset time.Duration
}

type ntsPeerHealth struct {
	queries, answers, losses int64
	wide                     int64 // losses that were answers over MaxSampleBound
	keOK, keFail             int64
	lastAnswer               int64 // local ns of the last answer, 0 for none
	off, lastErr             string
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

// receiptBound is the widest bound a sample may have at receipt: the cap
// less the aging over the join age (nts.Drift, 38 ms at the 76 s join age
// of the shift schedule), and never below half the cap. The core computes
// and applies it (ntscore: nts_config.max_sample_bound_ns); this copy is
// for logs and for fresh.
func (n *NTS) receiptBound() time.Duration {
	c := n.maxSampleBound()
	return max(c-nts.Drift(n.sampleMaxAge()), c/2)
}

func (n *NTS) shiftMode() bool { return n.Shifts || n.ScheduleSeed != nil }

// plain says whether the clock runs plain NTP (ProtocolNTP).
func (n *NTS) plain() bool { return n.Protocol == ProtocolNTP }

// protocol is Protocol with "" read as ProtocolNTS.
func (n *NTS) protocol() Protocol { return cmp.Or(n.Protocol, ProtocolNTS) }

// coreProtocol is p as the core names it.
func coreProtocol(p Protocol) (nts.Protocol, error) {
	switch cmp.Or(p, ProtocolNTS) {
	case ProtocolNTS:
		return nts.ProtocolNTS, nil
	case ProtocolNTP:
		return nts.ProtocolNTP, nil
	}
	return 0, fmt.Errorf("clock: nts: protocol %q: want nts or ntp", p)
}

func (n *NTS) maxAge() time.Duration {
	if n.shiftMode() {
		return cmpOr(n.MaxAge, NTSShiftMaxAge)
	}
	return cmpOr(n.MaxAge, NTSMaxAge)
}

// sampleMaxAge is the oldest a sample may be to join a quorum: joinAge, and
// without the shift schedule also at most 4 x Interval. It is the core's
// join age (nts.Config.JoinAge).
func (n *NTS) sampleMaxAge() time.Duration {
	if n.shiftMode() {
		return n.joinAge()
	}
	return min(4*n.interval(), n.joinAge())
}
func (n *NTS) maxDiff() time.Duration    { return cmpOr(n.MaxCoarseDiff, NTSMaxCoarseDiff) }
func (n *NTS) minPollD() time.Duration   { return cmpOr(n.minPoll, NTSMinPoll) }
func (n *NTS) maxPollD() time.Duration   { return cmpOr(n.maxPoll, NTSMaxPoll) }
func (n *NTS) startWaitD() time.Duration { return cmpOr(n.StartWait, NTSStartWait) }

// joinAge is the oldest a sample may be to join a quorum: it must stay
// under MaxAge until the next quorum can replace that quorum, or Now fails
// in between. Run starts the next Refresh at most a tick (Interval/4) after
// one ends, and a Refresh takes at most ntsRefreshLimit: one NTS-KE and one
// query (the polls run in parallel), or under the shift schedule its
// deadline (refreshShifts). 46 s with the defaults, 76 s under the shift
// schedule. init refuses a MaxAge that leaves it at 0 or below.
func (n *NTS) joinAge() time.Duration {
	return n.maxAge() - n.interval()/4 - ntsRefreshLimit
}

func cmpOr(v, d time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return d
}

// dial is Dial as it is at the time of the call, so that a change of Dial
// reaches the client after it was made (tests block the host's network
// this way).
func (n *NTS) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if n.Dial != nil {
		return n.Dial(ctx, network, addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

func (n *NTS) local() int64 {
	switch {
	case n.ops != nil:
		return n.ops.Monotonic()
	case n.Local != nil:
		return n.Local()
	}
	return nts.Monotonic()
}

// ntsSwapMinServers is the fewest servers SetServers takes: the runner's
// ntsMinServers. With 3, one slow server would stop the quorum.
const ntsSwapMinServers = 4

// checkServers refuses a list the core would refuse, with the reason in
// words: more than nts.MaxServers servers, an operator label outside 1 to
// nts.MaxOperatorLen octets, or an operator named twice. It also refuses
// fewer than min servers (the runner's policy, not the core's). With
// distinct, it also refuses a Host or a set NTPAddr named twice: one
// server would get two votes. The core checks all but the minimum again.
func checkServers(servers []NTSServer, min int, distinct bool) error {
	if len(servers) < min {
		return fmt.Errorf("clock: nts: %d servers, want at least %d", len(servers), min)
	}
	if len(servers) > nts.MaxServers {
		return fmt.Errorf("clock: nts: %d servers, at most %d", len(servers), nts.MaxServers)
	}
	ops, hosts, addrs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, s := range servers {
		if len(s.Operator) == 0 || len(s.Operator) > nts.MaxOperatorLen {
			return fmt.Errorf("clock: nts: server %q: operator label %q: 1 to %d octets", s.Host, s.Operator, nts.MaxOperatorLen)
		}
		if ops[s.Operator] {
			return fmt.Errorf("clock: nts: operator %q named twice", s.Operator)
		}
		ops[s.Operator] = true
		if !distinct {
			continue
		}
		if hosts[s.Host] {
			return fmt.Errorf("clock: nts: host %q named twice", s.Host)
		}
		hosts[s.Host] = true
		if s.NTPAddr != "" {
			if addrs[s.NTPAddr] {
				return fmt.Errorf("clock: nts: NTP address %q named twice", s.NTPAddr)
			}
			addrs[s.NTPAddr] = true
		}
	}
	return nil
}

// precheck refuses, before a client exists and at every Refresh, what
// could never serve: an unknown protocol, a list the core refuses, an
// empty schedule seed, a MaxAge that lets no sample join a quorum. No
// server is contacted then, and a corrected value takes.
func (n *NTS) precheck() error {
	if _, err := coreProtocol(n.Protocol); err != nil {
		return err
	}
	if err := checkServers(n.Servers, 0, false); err != nil {
		return err
	}
	if n.ScheduleSeed != nil && len(n.ScheduleSeed) == 0 {
		return errors.New("clock: nts: empty schedule seed: every signer would share its order")
	}
	if n.joinAge() <= 0 {
		return fmt.Errorf("clock: nts: MaxAge %v is too short: no sample could join a quorum; it must be over %v (a tick of Run and the longest Refresh)",
			n.maxAge(), n.maxAge()-n.joinAge())
	}
	return nil
}

// init allocates the client once. Its failure (a configuration the core
// refuses) is every Refresh's error. What precheck refuses is refused
// before the client exists, so that a corrected value takes.
func (n *NTS) init() error {
	if !n.inited.Load() {
		if err := n.precheck(); err != nil {
			return err
		}
	}
	n.once.Do(func() {
		defer n.inited.Store(true)
		if n.Local == nil && n.ops == nil && !nts.MonotonicRaw() {
			n.logf(slog.LevelWarn, "nts: CLOCK_MONOTONIC_RAW is not available; Go's monotonic clock serves, which an NTP daemon on the host may slew")
		}
		proto, _ := coreProtocol(n.Protocol)
		var queryTimeout time.Duration
		if n.shiftMode() {
			queryTimeout = NTSShiftQueryTimeout
		}
		n.client, n.initErr = nts.NewClient(nts.Config{
			Servers: n.Servers, Interval: n.interval(), MinPoll: n.minPollD(), MaxPoll: n.maxPollD(), MaxBound: n.maxBound(), MaxAge: n.maxAge(),
			JoinAge: n.sampleMaxAge(), MaxCoarseDiff: n.maxDiff(), CoarseResolution: NTSCoarseResolution, ExchangeTimeout: ntsExchangeTimeout,
			Protocol: proto, MaxSampleBound: n.MaxSampleBound, QueryTimeout: cmpOr(n.queryTimeout, queryTimeout), StartWait: n.startWaitD(),
			// SetServers may set any list the core takes.
			Capacity: nts.MaxServers,
			// The name is looked up once per NTS-KE only under the shift
			// schedule, whose query timeout is short, and only for the
			// default dialer: a platform dialer (the Nitro UDP relay)
			// resolves on its side.
			ResolveNTP: n.shiftMode() && (n.Dial == nil || n.resolveAnyDial),
			Warn:       func(msg string, args ...any) { n.logf(slog.LevelWarn, msg, args...) },
			Dial:       n.dial, Local: n.local, Ops: n.ops,
		})
		if n.initErr != nil {
			n.initErr = fmt.Errorf("clock: nts: %w", n.initErr)
			return
		}
		for _, s := range n.Servers {
			n.peers = append(n.peers, &ntsPeer{srv: s})
		}
		if n.shiftMode() {
			n.shifts = newNTSShifts(len(n.peers), n.ScheduleSeed, n.interval()/4)
		}
	})
	return n.initErr
}

// Close wipes the client's keys and frees the core. For a clock that is
// not used again (tests make many); every call after it is refused.
func (n *NTS) Close() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.client != nil {
		n.client.Close()
	}
}

// SetScheduleSeed switches the shift schedule from every operator to
// ShiftActives(n) in the order seed gives, for a clock that starts before
// its seed is known. Contacts made so far keep their minimum gap. No effect
// without Shifts. An empty seed is refused and changes nothing.
func (n *NTS) SetScheduleSeed(seed []byte) error {
	if len(seed) == 0 {
		return errors.New("clock: nts: empty schedule seed")
	}
	_ = n.init()
	if n.shifts != nil {
		n.shifts.reseed(seed)
	}
	return nil
}

// ntsLeft is what the clock keeps of a server a swap took out (removed, or
// changed under the same label), by label and by host, so the label or
// the host coming back does not get a fresh gap or a lifted stop.
type ntsLeft struct {
	at        int64 // local ns of the swap that took it out
	contacted int64 // ntsPeer.contacted
	disabled  string
	reEnable  int64
	shift     *ntsShiftState // nil without the shift schedule
}

// merge keeps the stricter of l and o: the later contact, the longer gap,
// the later stop.
func (l ntsLeft) merge(o ntsLeft) ntsLeft {
	l.at, l.contacted = max(l.at, o.at), max(l.contacted, o.contacted)
	if o.disabled != "" && o.reEnable > l.reEnable {
		l.disabled, l.reEnable = o.disabled, o.reEnable
	}
	if l.shift == nil {
		l.shift = o.shift
	} else if o.shift != nil {
		l.shift = &ntsShiftState{max(l.shift.last, o.shift.last), max(l.shift.gap, o.shift.gap), max(l.shift.rates, o.shift.rates)}
	}
	return l
}

func leftKeys(s NTSServer) [2]string { return [2]string{"op\x00" + s.Operator, "host\x00" + s.Host} }

// sameServer says whether a and b are the same server to the core, which
// then keeps its state: every field equal (ntscore: same_server).
func sameServer(a, b NTSServer) bool {
	return a.Operator == b.Operator && a.Host == b.Host && a.KEAddr == b.KEAddr && a.NTPAddr == b.NTPAddr && bytes.Equal(a.Roots, b.Roots)
}

// stopOf is the DENY or RSTR stop of peer i at local time now, "" if it
// may be asked: the core's (it stops a server for NTSMaxPoll and names the
// code until the server's next good answer), or one a swap carried over.
func (n *NTS) stopOf(i int, ps ntscore.PeerStatus, now int64) (code string, until int64) {
	p := n.peers[i]
	if p.stop != "" && now >= p.stopUntil {
		p.stop = ""
	}
	if ps.Disabled != "" && now < ps.NextPoll {
		code, until = ps.Disabled, ps.NextPoll
	}
	if p.stop != "" && p.stopUntil > until {
		code, until = p.stop, p.stopUntil
	}
	return code, until
}

// coarseForConfig is the coarse reading for a configuration call, which
// checks the quorum that forms again against it. Without one the zero
// time goes to the core, where no quorum passes: fail closed.
func (n *NTS) coarseForConfig() (time.Time, int64) {
	t, err := n.Coarse.Now()
	if err != nil {
		t = time.Time{}
	}
	return t, n.local()
}

// configure runs one configuration call of the core. The core refuses it
// during a poll (ntscore.ErrBusy); rmu, which the caller holds, keeps
// polls out, so that is not expected, but a signed update must not be
// lost to it: the call is tried again until the poll is over, and its
// error is the caller's if it never is.
func (n *NTS) configure(call func() error) error {
	deadline := time.Now().Add(ntsRefreshLimit)
	for {
		err := call()
		if !errors.Is(err, ntscore.ErrBusy) || time.Now().After(deadline) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// SetServers replaces the server list of a running clock, for a config
// update that changes the time servers. It refuses fewer than
// max(minServers, 4) servers, a Host or NTPAddr named twice and the lists
// checkServers refuses; on refusal nothing changes.
//
// The caller must be the trusted configuration path (see NTS).
//
// It waits for a Refresh in flight, which finishes on the old list; the
// next Refresh uses the new one. A server that stays, with the same
// Operator, Host, KEAddr, NTPAddr and Roots, keeps its state in the core
// (association and cookies, sample, poll interval, Kiss-o'-Death stop,
// loss streak) and here (health counters and last contact). Any other
// gets a new peer. What a removed server held is wiped. Its sample, and
// the old sample of an operator whose server changed, leave the quorum at
// once: if one was a member of the quorum in force, that quorum stops
// serving and the core forms it again from the samples left. If that
// fails (too few samples left, no coarse time, a check refuses it), Now
// fails until a Refresh forms a quorum, and the start retries apply again
// until then, for StartWait at most.
//
// A server that left (removed, or changed under its label) is kept by
// label and by host for NTSMaxPoll. If its label or its host comes back,
// the new peer keeps its DENY or RSTR stop and its last contact in local
// time, and under the shift schedule its last contact, gap and RATE
// count: it is asked at its next slot (or fallback or burst) past its
// gap, not at once.
//
// Under the shift schedule the seed and the grid phase stay. The order and
// the active slots are drawn again for the new set (ShiftActives of the
// new count), so the handover position starts over. Operators that stay
// keep their last contact, gap and counts, so the minimum gap holds across
// the swap. A new operator is asked at the next tick, as in the start
// round. Without the shift schedule there are no gaps to keep: every new
// peer, a changed or returning server included, is asked at the next
// Refresh unless it is stopped.
func (n *NTS) SetServers(servers []NTSServer, minServers int) error {
	if err := checkServers(servers, max(minServers, ntsSwapMinServers), true); err != nil {
		return err
	}
	n.rmu.Lock()
	defer n.rmu.Unlock()
	if err := n.init(); err != nil {
		return err
	}
	now := n.local()
	before := n.client.Status()
	byOp := map[string]int{}
	for j, p := range n.peers {
		byOp[p.srv.Operator] = j
	}
	keep := make([]int, len(servers))
	kept := make([]bool, len(n.peers))
	for i, s := range servers {
		keep[i] = -1
		if j, ok := byOp[s.Operator]; ok && sameServer(n.peers[j].srv, s) {
			keep[i], kept[j] = j, true
		}
	}
	// What limits the servers that go, read before the core wipes it.
	gone := map[int]ntsLeft{}
	var removed []string
	for j, p := range n.peers {
		if kept[j] {
			continue
		}
		removed = append(removed, p.srv.Operator)
		l := ntsLeft{at: now, contacted: p.contacted}
		if j < len(before.Peers) {
			l.disabled, l.reEnable = n.stopOf(j, before.Peers[j], now)
		}
		if n.shifts != nil {
			st := n.shifts.state(j)
			l.shift = &st
		}
		gone[j] = l
	}
	again := slices.ContainsFunc(before.Members, func(m int) bool { return m < len(kept) && !kept[m] })
	coarse, coarseLocal := n.coarseForConfig()
	// NTSSummary reads the client, the peers and the schedule under mu: all
	// change together. In the core a quorum with a removed member stops
	// serving in the same call, so no Now in between uses it.
	var after ntscore.Status
	err := n.configure(func() error {
		n.mu.Lock()
		defer n.mu.Unlock()
		if err := n.client.SetServers(servers, coarse, coarseLocal); err != nil {
			return err
		}
		// Keep what limits the servers that went, then drop what no
		// longer limits anything.
		if n.left == nil {
			n.left = map[string]ntsLeft{}
		}
		for j, l := range gone {
			for _, k := range leftKeys(n.peers[j].srv) {
				if o, ok := n.left[k]; ok {
					l = l.merge(o)
				}
				n.left[k] = l
			}
		}
		for k, l := range n.left {
			if now-l.at >= int64(n.maxPollD()) && now >= l.reEnable {
				delete(n.left, k)
			}
		}
		peers := make([]*ntsPeer, len(servers))
		carry := make([]*ntsShiftState, len(servers))
		for i, s := range servers {
			if keep[i] >= 0 {
				peers[i] = n.peers[keep[i]]
				continue
			}
			p := &ntsPeer{srv: s}
			var l ntsLeft
			found := false
			for _, k := range leftKeys(s) {
				if o, ok := n.left[k]; ok {
					l, found = l.merge(o), true
					delete(n.left, k)
				}
			}
			if found {
				p.contacted = l.contacted
				if l.disabled != "" && now < l.reEnable {
					p.stop, p.stopUntil = l.disabled, l.reEnable
					p.health.off = l.disabled
				}
				carry[i] = l.shift
			}
			peers[i] = p
		}
		if n.shifts != nil {
			n.shifts.swap(keep, carry)
		}
		n.peers = peers
		n.Servers = slices.Clone(servers)
		n.swaps++
		after = n.client.Status()
		return nil
	})
	if err != nil {
		return fmt.Errorf("clock: nts: server list not taken: %w", err)
	}
	names := make([]string, len(servers))
	for i, s := range servers {
		names[i] = s.Operator
	}
	n.logf(slog.LevelInfo, "nts: server list swapped", "operators", strings.Join(names, ","), "removed", strings.Join(removed, ","))
	if again && !after.HaveResult {
		// A removed operator was in the quorum in force, and the core
		// formed none without it: no time until a quorum forms. The
		// approvers took that operator out, so its sample must not count
		// any more.
		err := fmt.Errorf("clock: nts: no quorum without the removed operators %s: %w", strings.Join(removed, ","), n.combineErr(after, after.LastErr))
		n.setErr(err)
		n.cold()
		n.logf(slog.LevelError, "nts: no quorum after the server swap", "removed", strings.Join(removed, ","), "err", err)
	}
	return nil
}

// SetPolicy sets the protocol and both bounds of a running clock, for a
// config update of the setup's time_policy. It refuses a protocol other
// than ProtocolNTS and ProtocolNTP, a maxBound of 0 or less, and a
// maxSampleBound below maxBound or above nts.MaxSampleBound; on refusal
// nothing changes. Like SetServers, it waits for a Refresh in flight, and
// its caller must be the trusted configuration path.
//
// The bounds apply at once. Now checks the quorum in force against the new
// maxBound at its next call. A lower maxSampleBound also drops each sample
// over it, and if one was a member of the quorum in force, that quorum
// stops serving and forms again from the samples left, or Now fails until
// a Refresh forms one (as SetServers after a removal).
//
// A new protocol starts the core over, failing closed: every association
// is wiped, every sample and the quorum in force are dropped, and so is
// the drift history, which the other protocol's answers made. Now fails
// until a Refresh forms a quorum on the new protocol, and the start
// retries apply until then, for StartWait at most. What limits the
// contacts stays: the schedule seed, the grid, each server's last contact
// and gap, its poll interval and its DENY or RSTR stop. Now still never
// goes back.
func (n *NTS) SetPolicy(protocol Protocol, maxBound, maxSampleBound time.Duration) error {
	protocol = cmp.Or(protocol, ProtocolNTS)
	proto, err := coreProtocol(protocol)
	if err != nil {
		return err
	}
	if maxBound <= 0 || maxSampleBound < maxBound || maxSampleBound > nts.MaxSampleBound {
		return fmt.Errorf("clock: nts: max bound %v and max sample bound %v: want a max bound over 0 and a sample bound from it to %v",
			maxBound, maxSampleBound, nts.MaxSampleBound)
	}
	n.rmu.Lock()
	defer n.rmu.Unlock()
	if err := n.init(); err != nil {
		return err
	}
	restart := protocol != n.protocol()
	before := n.client.Status()
	coarse, coarseLocal := n.coarseForConfig()
	var after ntscore.Status
	err = n.configure(func() error {
		n.mu.Lock()
		defer n.mu.Unlock()
		if err := n.client.SetPolicy(proto, maxBound, maxSampleBound, coarse, coarseLocal); err != nil {
			return err
		}
		// Every read of the three fields holds rmu or mu.
		n.Protocol, n.MaxBound, n.MaxSampleBound = protocol, maxBound, maxSampleBound
		if restart {
			n.lastErr = fmt.Errorf("clock: nts: protocol changed to %s; no quorum on it yet", protocol)
		}
		after = n.client.Status()
		return nil
	})
	if err != nil {
		return fmt.Errorf("clock: nts: policy not taken: %w", err)
	}
	if restart {
		n.cold()
		n.logf(slog.LevelWarn, "nts: protocol changed; no time until a quorum forms on it", "max_bound", maxBound, "max_sample_bound", maxSampleBound)
		return nil
	}
	var dropped []string
	again := false
	for i, p := range before.Peers {
		if p.Sample != nil && i < len(after.Peers) && after.Peers[i].Sample == nil {
			dropped = append(dropped, n.peers[i].srv.Operator)
			again = again || slices.Contains(before.Members, i)
		}
	}
	n.logf(slog.LevelInfo, "nts: bounds changed", "max_bound", maxBound, "max_sample_bound", maxSampleBound, "dropped", strings.Join(dropped, ","))
	if again && !after.HaveResult {
		err := fmt.Errorf("clock: nts: no quorum under the max sample bound %v: %w", maxSampleBound, n.combineErr(after, after.LastErr))
		n.setErr(err)
		n.cold()
		n.logf(slog.LevelError, "nts: no quorum after the bounds changed", "err", err)
	}
	return nil
}

// cold notes that the core is back in its start state (a configuration
// call left no quorum; ntscore: nts_config.start_wait_ns) and puts the
// shift schedule there too: the start retries (NTSShiftStartRetry) apply
// until a quorum forms, or until StartWait is over (endCold). A real start
// has the same limit: the runner gives up after its start wait. The core
// keeps the limit for its NTS-KE retries itself. The caller holds rmu.
func (n *NTS) cold() {
	n.coldSched = true
	if n.shifts != nil {
		n.shifts.cold()
	}
}

// endCold ends the schedule's start state once the core's is over without
// a quorum (StartWait passed). The clock goes on as after a start that
// formed one: under the shift schedule every gap is the full one, with
// the retry of a lost answer and the bursts under their hourly caps. Now
// still fails until a quorum forms. Refresh calls it, under rmu.
func (n *NTS) endCold() {
	if !n.coldSched {
		return
	}
	st := n.client.Summary()
	if st.Cold {
		return
	}
	n.coldSched = false
	if n.shifts != nil {
		n.shifts.quorum()
	}
	if !st.HaveResult {
		n.logf(slog.LevelWarn, "nts: still no quorum after the start wait; the start retries end", "wait", n.startWaitD())
	}
}

// startWait is the wait of the first Refresh before it contacts anyone: a
// random time under StartDelay. It moves the whole schedule of this signer,
// so a caller that refreshes on a fixed grid (the runner's start loop) moves
// with it. A wait in the core's key exchange schedule alone would round up
// to the caller's next call.
func (n *NTS) startWait(ctx context.Context) error {
	d := n.StartDelay
	if d == 0 {
		d = NTSStartDelay
	}
	if d < 0 {
		return nil
	}
	return n.wait(ctx, time.Duration(n.random(int64(d))))
}

// wait waits d, or until ctx ends.
func (n *NTS) wait(ctx context.Context, d time.Duration) error {
	if n.sleep != nil {
		n.sleep(d)
		return ctx.Err()
	}
	t := time.NewTimer(d)
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
	n.mu.Lock()
	defer n.mu.Unlock()
	ops := make([]string, len(n.Servers))
	for i, s := range n.Servers {
		ops[i] = s.Operator
	}
	return string(n.protocol()) + "(" + strings.Join(ops, ",") + ")"
}

// Trusted is true for plain NTP too: the coarse check, over authenticated
// HTTPS, still bounds the time against the host (Protocol).
func (n *NTS) Trusted() bool { return true }

// CoarseNow is the reading of Coarse, the HTTPS-date quorum, also while
// Now fails, for a caller whose checks allow its error of about 30 s
// (NTSMaxCoarseDiff and NTSCoarseResolution): the runner's config updates,
// whose change delays are days (tee-signer/server, Updates.readNow).
// Signing never uses it.
func (n *NTS) CoarseNow() (time.Time, error) {
	if n.Coarse == nil {
		return time.Time{}, errors.New("clock: nts: no coarse clock")
	}
	return n.Coarse.Now()
}

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

// Refresh asks the servers that are due, then forms a new quorum.
func (n *NTS) Refresh(ctx context.Context) error {
	n.rmu.Lock()
	defer n.rmu.Unlock()
	err := n.init()
	if err == nil {
		// The list and the seed are checked at every Refresh, as before
		// the client existed.
		err = n.precheck()
	}
	if err != nil {
		n.setErr(err)
		return err
	}
	n.endCold()
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
	for _, i := range n.client.Due() {
		if code, _ := n.stopOf(i, ntscore.PeerStatus{}, coarseLocal); code != "" {
			continue // a stop a swap carried over
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			n.poll(ctx, i, coarse, coarseLocal)
		}(i)
	}
	wg.Wait()
	n.settled()
	return n.combine(coarse, coarseLocal)
}

// settled marks the end of a round of parallel polls.
func (n *NTS) settled() {
	if n.roundDone != nil {
		n.roundDone()
	}
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
			if err := n.wait(ctx, d); err != nil {
				return err
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
	// its late answers; the next tick asks again. The core counts an
	// exchange this deadline cut as cancelled: no loss and no backoff.
	ctx, cancel := context.WithTimeout(ctx, ntsRefreshLimit)
	defer cancel()
	// Three rounds, each in parallel: the queries due at the start of the
	// tick, then one fallback per lost active, then the burst. A contact
	// made after the start of the tick counts at a later tick (after), so
	// the next contact with that operator is still NTSShiftMinGap after it.
	tick := int64(n.interval() / 4)
	after := func(at int64) int { return max(1, int((at-coarseLocal+tick-1)/tick)) }
	lost := n.askAll(ctx, n.shifts.plan(coarseLocal, n.askable(coarseLocal)), coarseLocal, coarse, coarseLocal)
	// Past the deadline the later rounds would mark contacts and use the
	// fallback cap without sending anything.
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
	n.askAll(ctx, fallbacks, at, coarse, coarseLocal)
	if ctx.Err() == nil && n.fresh() < NTSShiftBurstBelow {
		at := n.local()
		n.askAll(ctx, n.shifts.burst(after(at), n.askable(at)), at, coarse, coarseLocal)
	}
	return n.combineShifts(coarse, coarseLocal)
}

// askable says by operator whether a contact at local time now would send
// anything: not stopped by DENY or RSTR, and not waiting out an NTS-KE
// backoff without cookies (plain NTP has no NTS-KE). Fallbacks and bursts
// skip the others, so they do not spend the cap or a contact on a server
// they cannot reach. No poll runs meanwhile.
func (n *NTS) askable(now int64) []bool {
	out := make([]bool, len(n.peers))
	for i := range n.peers {
		ps := n.client.Peer(i)
		code, _ := n.stopOf(i, ps, now)
		out[i] = code == "" && (!ps.NeedKE || now >= ps.NextKE)
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
// Kiss-o'-Death RATE the core obeyed.
type ntsLost struct {
	ntsAsk
	sent, wide, rate bool
}

// askAll polls asks in parallel, sent at local time at, and returns those
// that got no sample. A server stopped by DENY or RSTR counts as lost.
func (n *NTS) askAll(ctx context.Context, asks []ntsAsk, at int64, coarse time.Time, coarseLocal int64) []ntsLost {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var lost []ntsLost
	for _, a := range asks {
		p := n.peers[a.op]
		stop, _ := n.stopOf(a.op, n.client.Peer(a.op), at)
		wg.Add(1)
		go func() {
			defer wg.Done()
			// A retry of a lost answer may come NTSShiftStartRetry after it;
			// the next contact is still a full gap after the lost one.
			gap, retry := n.shifts.minGap(a.op), a.role == roleRetry
			if retry {
				gap = NTSShiftStartRetry
			}
			var o ntsOutcome
			if stop == "" && n.waitGap(ctx, p, at, gap, retry) {
				o = n.poll(ctx, a.op, coarse, coarseLocal)
			}
			if a.role == roleFallback && o.ke {
				n.shifts.fallbackKE(a.op)
			}
			n.shifts.result(a, o.ok, o.rate, o.wide, o.sent)
			if !o.ok {
				mu.Lock()
				lost = append(lost, ntsLost{a, o.sent, o.wide, o.rate})
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	n.settled()
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

// fresh counts the samples that would join a quorum now, for the burst:
// it decides only whether more servers are asked. The quorum's own count
// is the core's. No poll runs meanwhile.
func (n *NTS) fresh() int {
	now, c := n.local(), 0
	maxAge, widest := int64(n.sampleMaxAge()), n.receiptBound()
	for i := range n.peers {
		if s := n.client.Peer(i).Sample; s != nil && now-s.T4 <= maxAge && s.T4 > n.refusedT4 && s.Bound <= widest {
			c++
		}
	}
	return c
}

// ntsOutcome is what one poll came to. ok: a sample; sent: a query went
// out; ke: NTS-KE ran; rate: a Kiss-o'-Death RATE the core obeyed; wide:
// an answer over the receipt bound.
type ntsOutcome struct {
	ok, sent, ke, rate, wide bool
}

// poll polls one server through the client (NTS-KE if the core needs it,
// then one query), logs what came of it and keeps the counts of HEALTH.
// The core has already taken the outcome: nothing here feeds back into it.
func (n *NTS) poll(ctx context.Context, i int, coarse time.Time, coarseLocal int64) ntsOutcome {
	p := n.peers[i]
	s := p.srv
	before := n.client.Peer(i)
	ps, err := n.client.Poll(ctx, i, coarse, coarseLocal)
	keOK, keFail := ps.Stats.KEOK > before.Stats.KEOK, ps.Stats.KEFail > before.Stats.KEFail
	o := ntsOutcome{ok: err == nil, sent: ps.Stats.Queries > before.Stats.Queries, ke: keOK || keFail}
	if keOK {
		n.logf(slog.LevelInfo, "nts: key exchange", "operator", s.Operator, "host", s.Host, "ntp", ps.NTPAddr,
			"cookies", ps.Stats.CookiesAfterKE, "took", ps.Stats.LastKE.Round(time.Millisecond))
	}
	if keFail {
		args := []any{"operator", s.Operator, "host", s.Host, "retry_in", time.Duration(ps.NextKE - n.local())}
		if !o.sent {
			args = append(args, "err", err)
		}
		n.logf(slog.LevelWarn, "nts: key exchange failed", args...)
	}
	var kiss *nts.KissError
	cancelled := errors.Is(err, ntscore.ErrHostCancelled)
	switch {
	case err == nil, errors.Is(err, ntscore.ErrNotDue), cancelled:
		// A sample; nothing done; or the caller's deadline (the tick's)
		// cut the exchange, not the server: no loss for a server that may
		// be fine.
	case errors.As(err, &kiss):
		// RATE moves the schedule's gap only when the core obeyed it:
		// authenticated, or plain NTP, where none can be.
		o.rate = kiss.Code == "RATE" && (kiss.Authentic || n.plain())
		n.logf(slog.LevelWarn, "nts: kiss-o'-death", "operator", s.Operator, "code", kiss.Code, "authenticated", kiss.Authentic, "poll", ps.Poll)
	case errors.Is(err, ntscore.ErrSampleWide):
		// An answer, but too wide to join a quorum: it counts as lost (a
		// fallback may follow), and the earlier sample stays until it ages
		// out.
		o.wide = true
		n.logf(slog.LevelWarn, "nts: sample too wide", "operator", s.Operator, "bound", ps.Stats.LastBound, "delay", ps.Stats.LastDelay, "limit", n.receiptBound())
	case o.sent:
		n.logf(slog.LevelWarn, "nts: query failed", "operator", s.Operator, "err", err)
	}
	if n.plain() && o.sent && !o.ok && ps.LostInRow == nts.KEAfterLost {
		// Plain NTP has no key exchange to look the name up again: once
		// per streak of lost queries, in case the name moved.
		n.client.ForgetAddr(i)
	}
	stop, _ := n.stopOf(i, ps, n.local())
	n.mu.Lock()
	defer n.mu.Unlock()
	h := &p.health
	if keOK {
		h.keOK++
	}
	if keFail {
		h.keFail++
	}
	h.off = stop
	switch {
	case errors.Is(err, ntscore.ErrNotDue):
	case err == nil:
		h.queries++
		h.answers++
		h.lastAnswer = ps.Sample.T4
		h.lastErr = ""
		p.hostOffset = time.Duration(ps.Sample.Offset + nts.Monotonic() - time.Now().UnixNano())
	case cancelled:
		if !o.sent {
			// A key exchange the deadline cut: named, not counted.
			h.lastErr = healthErr(err)
		}
	case !o.sent:
		// The key exchange failed, or nothing could be sent.
		h.lastErr = healthErr(err)
	default:
		h.queries++
		h.losses++
		if o.wide {
			h.wide++
		}
		h.lastErr = healthErr(err)
	}
	return o
}

// combineErr words a refusal of the core's combine: err, with the status
// st taken after it.
func (n *NTS) combineErr(st ntscore.Status, err error) error {
	switch {
	case err == nil:
		return errors.New("no quorum")
	case errors.Is(err, ntscore.ErrCoarseCheck):
		if !st.HaveCoarseDiff {
			return fmt.Errorf("clock: nts: %w", err)
		}
		return fmt.Errorf("clock: nts: quorum time is %v from the coarse clock (allowed %v to %v with its %v resolution); refused",
			st.CoarseDiff, -n.maxDiff(), n.maxDiff()+NTSCoarseResolution, NTSCoarseResolution)
	case errors.Is(err, ntscore.ErrEraWindow):
		pivot := time.Unix(0, st.EraPivot).UTC().Format(time.RFC3339Nano)
		var e *ntscore.Error
		if errors.As(err, &e) && e.Detail == 0 {
			return fmt.Errorf("clock: nts: quorum time is before the era anchor %s; refused", nts.FloorTime.Format(time.RFC3339))
		}
		return fmt.Errorf("clock: nts: quorum time is more than %v after the era pivot %s; refused", ntscore.EraWindow, pivot)
	case errors.Is(err, ntscore.ErrDrift):
		d := driftReading(st)
		allowed := ntscore.AddBound(st.DriftBounds, ntscore.Drift(st.DriftDT))
		return fmt.Errorf("clock: nts: offset moved %v in %v (%.0f ppm, +-%.0f ppm from the bounds), more than its bounds and rho allow (%v); "+
			"the local clock does not keep within %d ppm: refused until a quorum of new samples agrees", st.DriftDelta, st.DriftDT.Round(time.Millisecond),
			d.ppm, d.errPPM, allowed, nts.RhoPPM)
	}
	var errs []error
	for i, p := range st.Peers {
		if p.LastErr != nil && i < len(n.peers) {
			errs = append(errs, fmt.Errorf("%s: %w", n.peers[i].srv.Operator, peerErr(p.LastErr)))
		}
	}
	return fmt.Errorf("clock: nts: %d fresh samples: %w (%v)", st.LastFresh, err, errors.Join(errs...))
}

// combine forms the quorum of the fresh samples and checks it against the
// sanity window of the era, the coarse time and the earlier quorums (the
// core's nts_combine), and logs.
func (n *NTS) combine(coarse time.Time, coarseLocal int64) error {
	err := n.client.Combine(coarse, coarseLocal)
	st := n.client.Status()
	if err != nil {
		werr := n.combineErr(st, err)
		switch {
		case errors.Is(err, ntscore.ErrCoarseCheck):
			n.logf(slog.LevelError, "nts: coarse check failed", "diff", st.CoarseDiff, "max", n.maxDiff(), "resolution", NTSCoarseResolution)
		case errors.Is(err, ntscore.ErrEraWindow):
			n.logf(slog.LevelError, "nts: quorum outside the sanity window", "err", werr)
		case errors.Is(err, ntscore.ErrDrift):
			// The samples of the refused quorum do not join again (the
			// core's rule); fresh leaves them out of its count too.
			for _, p := range st.Peers {
				if p.Sample != nil {
					n.refusedT4 = max(n.refusedT4, p.Sample.T4)
				}
			}
			d := driftReading(st)
			n.logf(slog.LevelError, "nts: local clock drift over rho", "delta", st.DriftDelta, "interval", st.DriftDT.Round(time.Millisecond),
				"drift_ppm", int64(d.ppm), "drift_err_ppm", int64(d.errPPM), "allowed", ntscore.AddBound(st.DriftBounds, ntscore.Drift(st.DriftDT)))
		default:
			n.logf(slog.LevelWarn, "nts: no quorum", "samples", st.LastFresh, "err", werr)
		}
		n.setErr(werr)
		return werr
	}
	n.setErr(nil)
	n.coldSched = false
	// Every quorum at debug level; a change of members at info.
	level := slog.LevelDebug
	if st.MembersChanged {
		level = slog.LevelInfo
	}
	n.logf(level, "nts: quorum", "members", strings.Join(n.members(st.Members), ","), "bound", st.Bound,
		"offset_from_host", time.Duration(st.Now+st.Offset-time.Now().UnixNano()), "coarse_diff", st.CoarseDiff)
	return nil
}

// members names the servers idx of the core's list. With rmu or mu held.
func (n *NTS) members(idx []int) []string {
	out := make([]string, 0, len(idx))
	for _, k := range idx {
		if k < len(n.peers) {
			out = append(out, n.peers[k].srv.Operator)
		}
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
}

func driftReading(st ntscore.Status) ntsDrift {
	if !st.HaveDrift || st.DriftDT <= 0 {
		return ntsDrift{}
	}
	return ntsDrift{
		ppm:    float64(st.DriftDelta) / float64(st.DriftDT) * 1e6,
		errPPM: float64(st.DriftBounds) / float64(st.DriftDT) * 1e6,
	}
}

func (n *NTS) setErr(err error) {
	n.mu.Lock()
	n.lastErr = err
	n.mu.Unlock()
}

// Run refreshes until ctx ends. It wakes every quarter Interval; each
// server is asked only when it is due. A refresh is bounded: one key
// exchange and one query per server, ntsExchangeTimeout each, so a host
// operation that never returns ends with the refresh and the next one
// runs, instead of holding the refresh lock (and with it Status and every
// later poll) until restart.
func (n *NTS) Run(ctx context.Context) {
	tick := time.NewTicker(n.interval() / 4)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			rctx, cancel := context.WithTimeout(ctx, n.interval()+ntsRefreshLimit)
			_ = n.Refresh(rctx)
			cancel()
		}
	}
}

// Bounded returns the time and its error bound now.
func (n *NTS) Bounded() (time.Time, time.Duration, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.init(); err != nil {
		return time.Time{}, 0, err
	}
	t, bound, err := n.client.Bounded()
	if err != nil {
		return time.Time{}, bound, errors.New("clock: nts: " + n.why(err, bound, n.client.Summary()))
	}
	return t, bound, nil
}

// why words a refusal of the core: err, with the bound then, and the
// snapshot st taken with it. Call with n.mu held.
func (n *NTS) why(err error, bound time.Duration, st ntscore.Status) string {
	switch {
	case errors.Is(err, ntscore.ErrNoQuorum):
		return fmt.Sprintf("no quorum yet: %v", n.lastErr)
	case errors.Is(err, ntscore.ErrSamplesTooOld):
		return fmt.Sprintf("samples of the last quorum %v old, over %v (no fresh quorum): %v",
			st.SampleAge.Round(time.Millisecond), n.maxAge(), n.lastErr)
	}
	return fmt.Sprintf("error bound %v over %v (last quorum %v ago): %v",
		bound, n.maxBound(), time.Duration(st.Now-st.At).Round(time.Second), n.lastErr)
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
	// that time, SampleAge the age of its oldest sample. OffsetFromHost is
	// the NTS time minus the host clock (for logs; the host clock is not
	// used for anything else).
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
	Refusals   int64 // Now calls refused for the bound or the sample age (the core's count)
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
		s.MaxBound, s.MaxSampleAge, s.Refusals, s.DriftPPM, s.DriftErrPPM, s.DriftBaseline, s.RhoViolations, s.CoarseDiff =
			n.maxBound(), n.maxAge(), st.Refusals, d.ppm, d.errPPM, st.DriftDT, st.Violations, st.CoarseDiff
		// The core's verdict at the snapshot: what Now would answer then.
		s.Quorum, s.BoundNow, s.SampleAge = st.Refusal == nil, st.BoundNow, st.SampleAge
		if st.Refusal != nil {
			s.Refused = n.why(st.Refusal, st.BoundNow, st)
		}
	}
	if full != nil {
		full.Refusals, full.DriftPPM, full.DriftErrPPM, full.DriftBaseline, full.RhoViolations, full.CoarseDiff =
			st.Refusals, d.ppm, d.errPPM, st.DriftDT, st.Violations, st.CoarseDiff
	}
	if !st.HaveResult {
		return
	}
	now := st.Now
	members := n.members(st.Members)
	age := time.Duration(now - st.At)
	fromHost := time.Duration(now + st.Offset - time.Now().UnixNano())
	if s != nil {
		s.Members, s.AgeOfQuorum, s.OffsetFromHost = members, age, fromHost
		// What a single wrong member may have caused, aged like the bound
		// (the core's worst: with exactly 3 samples none is outvoted).
		s.WorstBoundNow = nts.AddBound(st.Worst, nts.Drift(age))
	}
	if full != nil {
		full.Members, full.Bound, full.Lo, full.Hi = members, st.Bound, st.Lo, st.Hi
		full.AgeOfQuorum, full.BoundNow, full.SampleAge, full.OffsetFromHost = age, st.BoundNow, st.SampleAge, fromHost
	}
}

// NTSSummary is the state for HEALTH. Unlike Status it does not wait for a
// running Refresh (which can take seconds while a server is slow): it reads
// the last quorum. Quorum is true when the clock answers now: a quorum is
// in force, its bound is within MaxBound and its samples within MaxAge.
// Refused says why not.
func (n *NTS) NTSSummary() NTSSummary {
	n.mu.Lock()
	defer n.mu.Unlock()
	s := NTSSummary{Protocol: n.protocol()}
	// The coarse clock has its own lock and never calls the NTS clock.
	if c, ok := n.Coarse.(SourceStatser); ok {
		s.Coarse = c.SourceStats()
	}
	if err := n.init(); err != nil {
		s.MaxBound, s.MaxSampleAge, s.Refused = n.maxBound(), n.maxAge(), err.Error()
		return s
	}
	st := n.client.Summary()
	n.summaryOf(st, &s, nil)
	s.ServerSwaps = n.swaps
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
			ph.LastAnswerAge = time.Duration(st.Now - h.lastAnswer)
		}
		s.Peers[i] = ph
	}
	return s
}

// Status waits for a running Refresh to end, then takes a snapshot.
func (n *NTS) Status() NTSStatus {
	n.rmu.Lock()
	defer n.rmu.Unlock()
	n.mu.Lock()
	defer n.mu.Unlock()
	st := NTSStatus{Protocol: n.protocol(), Peers: map[string]NTSPeerStatus{}}
	if n.lastErr != nil {
		st.LastError = n.lastErr.Error()
	}
	if err := n.init(); err != nil {
		if st.LastError == "" {
			st.LastError = err.Error()
		}
		return st
	}
	cs := n.client.Status()
	n.summaryOf(cs, nil, &st)
	for i, p := range cs.Peers {
		if i >= len(n.peers) {
			break
		}
		gp := n.peers[i]
		disabled, _ := n.stopOf(i, ntscore.PeerStatus{}, cs.Now)
		ps := NTSPeerStatus{Host: gp.srv.Host, NTPAddr: p.NTPAddr, Disabled: cmp.Or(p.Disabled, disabled), Poll: p.Poll, Sample: p.Sample, Stats: NTSPeerStats{
			KEOK: p.Stats.KEOK, KEFail: p.Stats.KEFail, Queries: p.Stats.Queries, Samples: p.Stats.Samples, Kisses: p.Stats.Kisses,
			Errors: p.Stats.Errors, LastKE: p.Stats.LastKE, CookiesAfterKE: p.Stats.CookiesAfterKE, CookiesHeld: p.Cookies,
			LastDelay: p.Stats.LastDelay, LastBound: p.Stats.LastBound, Wide: p.Stats.Wide, LastOffsetFromHost: gp.hostOffset,
		}}
		if p.LastErr != nil {
			ps.LastErr = peerErr(p.LastErr).Error()
		}
		st.Peers[gp.srv.Operator] = ps
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
