//go:build nts

package ntscore

/*
#include <stdlib.h>
#include <string.h>
#include "nts_core.h"

void ntsgo_make_ops(nts_host_ops *ops, uintptr_t handle);
*/
import "C"

import (
	"errors"
	"fmt"
	"math"
	"net"
	"runtime/cgo"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// Protocol is what the core asks the servers with: nts_protocol of
// nts_core.h. It is configuration: it enters by New and SetPolicy only.
type Protocol int

const (
	// ProtocolNTS is NTS (RFC 8915): every answer authenticated.
	ProtocolNTS Protocol = C.NTS_PROTO_NTS
	// ProtocolNTP is plain NTP (RFC 5905) without NTS: nothing
	// authenticates an answer, so whoever sees the requests can forge all
	// of them, and the coarse check is the one limit left. A core built
	// with NTS_NO_PLAIN_NTP refuses it (PlainSupported).
	ProtocolNTP Protocol = C.NTS_PROTO_NTP
)

func (p Protocol) String() string {
	switch p {
	case ProtocolNTS:
		return "nts"
	case ProtocolNTP:
		return "ntp"
	}
	return fmt.Sprintf("protocol(%d)", int(p))
}

// Server is one NTS server: the operator who runs it, its TLS name, where
// NTS-KE is dialed, and the operator's pinned roots (PEM). It is
// configuration of the core and must come by a trusted path.
type Server struct {
	Operator string
	Host     string
	KEAddr   string // host:port of NTS-KE; "" means Host:4460
	Roots    []byte
	NTPAddr  string // host:port of plain NTP, for ProtocolNTP; "" means Host:123. Unused with NTS
}

// Config is the core's configuration: nts_config of nts_core.h. Every
// duration must be set.
type Config struct {
	Servers  []Server
	Interval time.Duration // between two queries to one server
	MinPoll  time.Duration // the shortest poll interval
	MaxPoll  time.Duration // the longest, after Kiss-o'-Death backoff
	MaxBound time.Duration // Bounded refuses over it
	MaxAge   time.Duration // Bounded refuses once the quorum's oldest sample is older
	// JoinAge is the oldest a sample may be to enter a quorum, at most
	// MaxAge (0: MaxAge): under MaxAge by the host's room for its next
	// Combine, so a quorum stays under MaxAge until the next one can
	// replace it.
	JoinAge            time.Duration
	MaxCoarseDiff      time.Duration // a quorum further from the coarse time is refused
	CoarseResolution   time.Duration // the coarse reading names the second it was in
	ExchangeTimeout    time.Duration // one NTS-KE session or one query
	KissGrace          time.Duration // how long a query reads on after a Kiss-o'-Death
	DriftBaselinePolls int           // times Interval: the baseline of the drift check
	FloorUnix          time.Time     // a time known at build to be in the past: the anchor of the NTP era pivot; no time before it is served
	Protocol           Protocol
	// MaxSampleBound is the cap of one sample's bound: 0 is MaxBound, else
	// MaxBound to MaxSampleBound (the constant). An answer is refused over
	// the cap less the aging over JoinAge (ErrSampleWide).
	MaxSampleBound time.Duration
	QueryTimeout   time.Duration // one query; 0: the shorter of ExchangeTimeout and Interval / 2
	// StartWait is how long the start state lasts after SetServers or
	// SetPolicy left no quorum (0: no start state then).
	StartWait time.Duration
	// Capacity is the most servers SetServers may set later: 0 is
	// len(Servers), MaxServers for a core whose list may grow to the most.
	// Each takes about 70 kB.
	Capacity int
}

// HostOps is what the core asks of its host. Random, Monotonic and
// KeyExchange's TLS session are trusted operations: inside a TEE they must
// be the TEE's. The sockets are not: they move bytes, and the core takes
// nothing from them unchecked.
type HostOps interface {
	// Random fills buf from a CSPRNG.
	Random(buf []byte) error
	// Monotonic is nanoseconds of a monotonic clock that keeps within
	// RhoPPM of real time.
	Monotonic() int64
	// KeyExchange runs one NTS-KE session with srv: TLS 1.3 with ALPN
	// ntske/1 and no other, the chain checked to srv.Roots with the
	// certificate validity at validity, req written, the response read
	// into resp until KEComplete says done (or resp is full, or the
	// server closes), the two keys exported with ExporterLabel and
	// ExporterContext. timeout bounds it all.
	KeyExchange(peer int, srv *Server, validity time.Time, timeout time.Duration, req, resp []byte) (n int, c2s, s2c []byte, elapsed time.Duration, err error)
	// UDPOpen is a connected UDP socket to addr (host:port); timeout
	// bounds the whole exchange.
	UDPOpen(peer int, addr string, timeout time.Duration) (UDPConn, error)
}

// UDPConn is one socket of HostOps.UDPOpen.
type UDPConn interface {
	Send(p []byte) error
	// Recv reads one datagram, waiting at most wait. A timeout is an error
	// with Timeout() true (net.Error).
	Recv(buf []byte, wait time.Duration) (int, error)
	Close()
}

// Error is a refusal of the core: its code and detail, and the host's
// error when a host operation failed. Kiss is set for a Kiss-o'-Death.
type Error struct {
	Code, Detail  int
	Host          error
	Kiss          string
	KissAuthentic bool
}

func (e *Error) Error() string {
	switch {
	case e.Host != nil && e.Code == codeHostTimeout && e.Detail != 0:
		return fmt.Sprintf("%v (and earlier: %v)", e.Host, CodeError(e.Detail, 0))
	case e.Host != nil:
		return e.Host.Error()
	case e.Code == codeKiss:
		if e.KissAuthentic {
			return fmt.Sprintf("Kiss-o'-Death %q", e.Kiss)
		}
		return fmt.Sprintf("Kiss-o'-Death %q (not authenticated)", e.Kiss)
	}
	return CodeError(e.Code, e.Detail).Error()
}

// Unwrap gives the core's error and the host's, so errors.Is and As find
// either.
func (e *Error) Unwrap() []error {
	out := []error{CodeError(e.Code, e.Detail)}
	if e.Host != nil {
		out = append(out, e.Host)
	}
	if e.Code == codeHostTimeout && e.Detail != 0 {
		out = append(out, CodeError(e.Detail, 0))
	}
	return out
}

// Class is which step refused.
func (e *Error) Class() CodeClass { return ClassOf(e.Code) }

// Is matches another *Error with the same code (a KissError match, say).
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code
}

// PeerStats counts what happened with one server.
type PeerStats struct {
	KEOK, KEFail     int
	Queries, Samples int
	Kisses           map[string]int
	Errors           int
	LastKE           time.Duration
	CookiesAfterKE   int
	Wide             int           // answers refused as ErrSampleWide
	LastDelay        time.Duration // of the last measured answer, a wide one included
	LastBound        time.Duration
}

// PeerStatus is one server's state.
type PeerStatus struct {
	Sample   *Sample // the latest, nil if none
	Poll     time.Duration
	Disabled string // the DENY or RSTR obeyed, "" otherwise
	LastErr  error  // the last poll's refusal, nil after a sample
	NTPAddr  string
	Cookies  int
	Stats    PeerStats
	// NextPoll and NextKE are the monotonic times of the next poll due and
	// of the earliest next NTS-KE. NeedKE (NTS only): no keys or no
	// cookies, so the next poll starts with NTS-KE, once NextKE has come.
	// LostInRow counts the queries in a row without an answer.
	NextPoll, NextKE int64
	NeedKE           bool
	LostInRow        int
}

// Status is a snapshot of the client.
type Status struct {
	HaveResult bool
	Offset     int64 // real Unix ns minus monotonic ns, at At
	Bound      time.Duration
	At         int64
	Lo, Hi     int64
	Sampled    int64 // the monotonic time of the quorum's oldest sample (T4)
	Members    []int // the servers of the quorum, by index
	// Now is the monotonic time of the snapshot; Refusal is what Bounded
	// would refuse with then (nil if it gives a time), BoundNow the bound
	// and SampleAge the age of the quorum's oldest sample then.
	Now            int64
	Refusal        error
	BoundNow       time.Duration
	SampleAge      time.Duration
	HaveDrift      bool
	DriftDelta     time.Duration // the offset's change over DriftDT
	DriftDT        time.Duration
	DriftBounds    time.Duration // the two bounds of the pair
	Violations     int64
	Refusals       int64
	HaveCoarseDiff bool
	CoarseDiff     time.Duration
	LastErr        error // what refused the last Combine, nil after a served quorum
	LastFresh      int
	MembersChanged bool
	Busy           bool // a poll was under way: no Peers (the core's check of its contract)
	// Protocol is what the core asks with, and so what the result in force
	// was made from. Worst is the largest error a wrong member of that
	// result may have caused: its bound, or with exactly 3 members twice
	// the widest member's aged bound. MaxWrong is how many of its samples
	// were allowed wrong. Cold: the start state after SetServers or
	// SetPolicy left no quorum. EraPivot is the Unix time (ns) NTP
	// timestamps are read around.
	Protocol Protocol
	Worst    time.Duration
	MaxWrong int
	Cold     bool
	EraPivot int64
	Peers    []PeerStatus
}

// Core is the client: the C state, the host operations and their Go
// implementation.
//
// Polls of different servers may run at the same time, on their own
// goroutines. Combine, Status, SetServers and SetPolicy exclude the polls:
// during a poll they are refused with ErrBusy and change nothing (Status:
// Busy set, no Peers), they never wait for one, and a poll that starts
// while one of them runs waits until it has returned. The core keeps the
// same exclusion itself (nts_core.h), so it does not rest on this lock
// alone. Bounded and Summary may run at any time. Close waits for the
// polls under way; every call after it is refused with ErrClosed. The
// caller of SetServers and SetPolicy must be the trusted side
// (nts_core.h).
type Core struct {
	mu sync.Mutex
	// polls is shared by a poll and exclusive for everything that reads or
	// writes more than one peer: Combine, Status, SetServers and SetPolicy
	// take it with TryLock (ErrBusy during a poll), Close waits for it (the
	// core is freed between polls only). Taken before mu.
	polls    sync.RWMutex
	c        *C.nts_core
	st       *hostState
	h        cgo.Handle
	n        atomic.Int32 // the servers of the current list
	capacity int
}

type hostState struct {
	ops HostOps
	mu  sync.Mutex
	err map[int]error // the last failure of a host operation, per server
}

func (st *hostState) setErr(peer int, err error) {
	st.mu.Lock()
	st.err[peer] = err
	st.mu.Unlock()
}

// rawHostCode is a host operation's failure that reaches the core as this
// code, whatever it is: what a host written in C could return. Unexported,
// so only this package's tests can make one (hostile_test.go).
type rawHostCode int

func (e rawHostCode) Error() string { return fmt.Sprintf("host operation returned code %d", int(e)) }

// hostCode is the core's code for a failed host operation: cancelled by the
// caller, timed out (a receive only), or failed.
func hostCode(err error, recv bool) C.int {
	var ne net.Error
	var raw rawHostCode
	switch {
	case errors.As(err, &raw):
		return C.int(raw)
	case errors.Is(err, ErrHostCancelled):
		return C.NTS_ERR_HOST_CANCELLED
	case recv && errors.As(err, &ne) && ne.Timeout():
		return C.NTS_ERR_HOST_TIMEOUT
	}
	return C.NTS_ERR_HOST
}

func (st *hostState) takeErr(peer int) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	err := st.err[peer]
	delete(st.err, peer)
	return err
}

func checkServers(servers []Server) error {
	if len(servers) > MaxServers {
		return fmt.Errorf("%w: %d servers, at most %d", ErrBadConfig, len(servers), MaxServers)
	}
	for _, s := range servers {
		switch {
		case len(s.Operator) < 1 || len(s.Operator) > MaxOperatorLen:
			return fmt.Errorf("%w: operator label %q empty or over %d octets", ErrBadConfig, s.Operator, MaxOperatorLen)
		case len(s.Host) < 1 || len(s.Host) > MaxServerName:
			return fmt.Errorf("%w: host %q empty or over %d octets", ErrBadConfig, s.Host, MaxServerName)
		case len(s.KEAddr) > MaxAddrLen:
			return fmt.Errorf("%w: NTS-KE address %q over %d octets", ErrBadConfig, s.KEAddr, MaxAddrLen)
		case len(s.NTPAddr) > MaxAddrLen:
			return fmt.Errorf("%w: NTP address %q over %d octets", ErrBadConfig, s.NTPAddr, MaxAddrLen)
		case len(s.Roots) > MaxRootsLen:
			return fmt.Errorf("%w: roots of %s: %d octets, at most %d", ErrBadConfig, s.Operator, len(s.Roots), MaxRootsLen)
		}
	}
	return nil
}

func serverToC(s *Server, cs *C.nts_server) {
	cs.op_len = C.size_t(copy(unsafe.Slice((*byte)(unsafe.Pointer(&cs.op[0])), MaxOperatorLen), s.Operator))
	cs.host_len = C.size_t(copy(unsafe.Slice((*byte)(unsafe.Pointer(&cs.host[0])), MaxServerName), s.Host))
	cs.ke_addr_len = C.size_t(copy(unsafe.Slice((*byte)(unsafe.Pointer(&cs.ke_addr[0])), MaxAddrLen), s.KEAddr))
	cs.ntp_addr_len = C.size_t(copy(unsafe.Slice((*byte)(unsafe.Pointer(&cs.ntp_addr[0])), MaxAddrLen), s.NTPAddr))
	cs.roots_len = C.size_t(copy(unsafe.Slice((*byte)(unsafe.Pointer(&cs.roots[0])), MaxRootsLen), s.Roots))
}

// New allocates a core with cfg and ops. Close frees it.
func New(cfg Config, ops HostOps) (*Core, error) {
	if err := checkServers(cfg.Servers); err != nil {
		return nil, err
	}
	capacity := cfg.Capacity
	if capacity == 0 {
		capacity = len(cfg.Servers)
	}
	if capacity < len(cfg.Servers) || capacity > MaxServers {
		return nil, fmt.Errorf("%w: capacity %d for %d servers, at most %d", ErrBadConfig, cfg.Capacity, len(cfg.Servers), MaxServers)
	}
	ccfg := (*C.nts_config)(C.calloc(1, C.sizeof_nts_config))
	defer C.free(unsafe.Pointer(ccfg))
	ccfg.nservers = C.size_t(len(cfg.Servers))
	for i := range cfg.Servers {
		serverToC(&cfg.Servers[i], &ccfg.servers[i])
	}
	ccfg.interval_ns = C.int64_t(cfg.Interval)
	ccfg.min_poll_ns = C.int64_t(cfg.MinPoll)
	ccfg.max_poll_ns = C.int64_t(cfg.MaxPoll)
	ccfg.max_bound_ns = C.int64_t(cfg.MaxBound)
	ccfg.max_age_ns = C.int64_t(cfg.MaxAge)
	ccfg.join_age_ns = C.int64_t(cfg.JoinAge)
	ccfg.max_coarse_diff_ns = C.int64_t(cfg.MaxCoarseDiff)
	ccfg.coarse_resolution_ns = C.int64_t(cfg.CoarseResolution)
	ccfg.exchange_timeout_ns = C.int64_t(cfg.ExchangeTimeout)
	ccfg.kiss_grace_ns = C.int64_t(cfg.KissGrace)
	ccfg.drift_baseline_polls = C.int(cfg.DriftBaselinePolls)
	ccfg.floor_unix_ns = C.int64_t(cfg.FloorUnix.UnixNano())
	ccfg.protocol = C.int(cfg.Protocol)
	ccfg.max_sample_bound_ns = C.int64_t(cfg.MaxSampleBound)
	ccfg.query_timeout_ns = C.int64_t(cfg.QueryTimeout)
	ccfg.start_wait_ns = C.int64_t(cfg.StartWait)

	st := &hostState{ops: ops, err: map[int]error{}}
	// The core is sized for its capacity: most of it is the servers' buffers.
	size := C.nts_core_size_for(C.size_t(capacity))
	core := &Core{c: (*C.nts_core)(C.calloc(1, size)), st: st, h: cgo.NewHandle(st), capacity: capacity}
	core.n.Store(int32(len(cfg.Servers)))
	var cops C.nts_host_ops
	C.ntsgo_make_ops(&cops, C.uintptr_t(core.h))
	if rc := C.nts_core_init(core.c, &cops, ccfg, size); rc != 0 {
		core.free()
		return nil, CodeError(int(rc), 0)
	}
	return core, nil
}

// SetServers replaces the server list of a running core
// (nts_core_set_servers): at most the capacity New was given; refused
// (ErrBadConfig, nothing changed) for an operator, a host or a set NTPAddr
// named twice. A server that is as before in every field keeps its state;
// any other is a new peer. If a removed or changed server was a member of
// the quorum in force, that quorum stops serving at once and forms again
// from the samples left, with coarse (read at the monotonic time
// coarseLocal) as in Combine; if none forms, no time is served until a
// Combine forms one (Status: HaveResult false, LastErr, Cold). The time
// never goes back. ErrBusy during a poll. Server i of the new list is peer
// i from here on.
func (core *Core) SetServers(servers []Server, coarse time.Time, coarseLocal int64) error {
	if err := checkServers(servers); err != nil {
		return err
	}
	// No poll may start while the peers are wiped and given to other
	// servers, and none may be under way.
	if !core.polls.TryLock() {
		return &Error{Code: codeBusy}
	}
	defer core.polls.Unlock()
	return core.setServers(servers, coarse, coarseLocal)
}

// setServers is SetServers without this binding's lock against the polls:
// what then keeps a poll off the peers is the core's own exclusion
// (nts_core.h), which the tests check through here.
func (core *Core) setServers(servers []Server, coarse time.Time, coarseLocal int64) error {
	core.mu.Lock()
	defer core.mu.Unlock()
	if core.c == nil {
		return ErrClosed
	}
	if len(servers) > core.capacity {
		return fmt.Errorf("%w: %d servers, capacity %d", ErrBadConfig, len(servers), core.capacity)
	}
	cs := (*C.nts_server)(C.calloc(C.size_t(max(len(servers), 1)), C.sizeof_nts_server))
	defer C.free(unsafe.Pointer(cs))
	arr := unsafe.Slice(cs, len(servers))
	for i := range servers {
		serverToC(&servers[i], &arr[i])
	}
	if rc := C.nts_core_set_servers(core.c, cs, C.size_t(len(servers)), C.int64_t(unixNanos(coarse)), C.int64_t(coarseLocal)); rc != 0 {
		return &Error{Code: int(rc)}
	}
	core.n.Store(int32(len(servers)))
	// The host errors kept were of the old list's positions.
	core.st.mu.Lock()
	clear(core.st.err)
	core.st.mu.Unlock()
	return nil
}

// SetPolicy sets the protocol and the two bounds of a running core
// (nts_core_set_policy): refused (ErrBadConfig, nothing changed) unless
// the protocol is known and built, maxBound is over 0 and maxSampleBound
// is from maxBound to MaxSampleBound. A new protocol starts the core over:
// every association, sample, the quorum in force and the drift history go,
// and no time is served until a Combine forms a quorum on it. With the
// protocol unchanged the bounds apply at once, and samples over the new
// receipt bound leave, as servers removed by SetServers do. The time never
// goes back. ErrBusy during a poll.
func (core *Core) SetPolicy(p Protocol, maxBound, maxSampleBound time.Duration, coarse time.Time, coarseLocal int64) error {
	if !core.polls.TryLock() {
		return &Error{Code: codeBusy}
	}
	defer core.polls.Unlock()
	return core.setPolicy(p, maxBound, maxSampleBound, coarse, coarseLocal)
}

// setPolicy is SetPolicy without this binding's lock against the polls
// (see setServers).
func (core *Core) setPolicy(p Protocol, maxBound, maxSampleBound time.Duration, coarse time.Time, coarseLocal int64) error {
	core.mu.Lock()
	defer core.mu.Unlock()
	if core.c == nil {
		return ErrClosed
	}
	rc := C.nts_core_set_policy(core.c, C.int(p), C.int64_t(maxBound), C.int64_t(maxSampleBound), C.int64_t(unixNanos(coarse)), C.int64_t(coarseLocal))
	if rc != 0 {
		return &Error{Code: int(rc)}
	}
	return nil
}

func (core *Core) free() {
	C.free(unsafe.Pointer(core.c))
	core.c = nil
	core.h.Delete()
}

// Close wipes the keys and the cookies and frees the core, once the polls
// under way have returned. Every call after it is refused with ErrClosed.
func (core *Core) Close() {
	core.polls.Lock()
	defer core.polls.Unlock()
	core.mu.Lock()
	defer core.mu.Unlock()
	if core.c == nil {
		return
	}
	C.nts_core_wipe(core.c)
	core.free()
}

// Due is the servers due for a poll at the monotonic time now.
func (core *Core) Due(now int64) []int {
	core.polls.RLock()
	defer core.polls.RUnlock()
	if core.c == nil {
		return nil
	}
	mask := uint32(C.nts_due(core.c, C.int64_t(now)))
	var out []int
	for i := 0; i < int(core.n.Load()); i++ {
		if mask&(1<<i) != 0 {
			out = append(out, i)
		}
	}
	return out
}

// Poll polls server i: NTS-KE if needed, then one query, under the
// Kiss-o'-Death policy and the backoff. coarse is the host's coarse time
// read at the monotonic time coarseLocal; it dates the certificate before
// the first quorum. The peer's state after the poll comes back with the
// refusal, if any (an *Error; ErrNotDue when nothing was done; ErrBusy,
// with nothing done, if a poll of the same server is under way; ErrClosed
// after Close).
func (core *Core) Poll(i int, coarse time.Time, coarseLocal int64) (PeerStatus, error) {
	core.polls.RLock()
	defer core.polls.RUnlock()
	if core.c == nil {
		return PeerStatus{}, ErrClosed
	}
	rc := C.nts_poll(core.c, C.size_t(i), C.int64_t(unixNanos(coarse)), C.int64_t(coarseLocal))
	v, ps := core.peer(i)
	if rc == 0 {
		return ps, nil
	}
	return ps, core.pollError(i, int(rc), int(v.last_detail), v)
}

// Peer is server i's state, as its last poll left it. It reads only that
// server; it may run while other servers' polls do.
func (core *Core) Peer(i int) PeerStatus {
	core.polls.RLock()
	defer core.polls.RUnlock()
	if core.c == nil {
		return PeerStatus{}
	}
	_, ps := core.peer(i)
	return ps
}

// peer is server i's view and its status; under polls.RLock.
func (core *Core) peer(i int) (*C.nts_peer_view, PeerStatus) {
	var v C.nts_peer_view
	C.nts_peer_get(core.c, C.size_t(i), &v)
	return &v, core.peerStatus(i, &v)
}

func (core *Core) pollError(i, code, detail int, v *C.nts_peer_view) *Error {
	e := &Error{Code: code, Detail: detail}
	if ClassOf(code) == ClassHost {
		e.Host = core.st.takeErr(i)
		if e.Host == nil {
			e.Host = CodeError(code, 0)
		}
	}
	if code == codeKiss {
		e.Kiss, e.KissAuthentic = C.GoStringN(&v.last_kiss[0], 4), bool(v.last_kiss_authentic)
	}
	return e
}

func (core *Core) peerStatus(i int, v *C.nts_peer_view) PeerStatus {
	ps := PeerStatus{
		Poll: time.Duration(v.poll_ns), NTPAddr: C.GoStringN(&v.ntp_addr[0], C.int(v.ntp_addr_len)), Cookies: int(v.cookies),
		Stats: PeerStats{
			KEOK: int(v.stats.ke_ok), KEFail: int(v.stats.ke_fail), Queries: int(v.stats.queries), Samples: int(v.stats.samples),
			Errors: int(v.stats.errors), LastKE: time.Duration(v.stats.last_ke_ns), CookiesAfterKE: int(v.stats.cookies_after_ke),
			Kisses: map[string]int{}, Wide: int(v.stats.wide), LastDelay: time.Duration(v.stats.last_delay), LastBound: time.Duration(v.stats.last_bound),
		},
		NextPoll: int64(v.next_poll), NextKE: int64(v.next_ke), NeedKE: bool(v.need_ke), LostInRow: int(v.lost_in_row),
	}
	for code, n := range map[string]C.int64_t{"RATE": v.stats.kiss_rate, "NTSN": v.stats.kiss_ntsn, "DENY": v.stats.kiss_deny, "RSTR": v.stats.kiss_rstr, "OTHER": v.stats.kiss_other} {
		if n != 0 {
			ps.Stats.Kisses[code] = int(n)
		}
	}
	if v.have_sample {
		s := sampleFromC(&v.sample)
		ps.Sample = &s
	}
	if v.is_disabled {
		ps.Disabled = C.GoStringN(&v.disabled[0], 4)
	}
	if v.last_err != 0 {
		// The host's error of this poll was taken by Poll; what is left is
		// the code.
		e := &Error{Code: int(v.last_err), Detail: int(v.last_detail)}
		if e.Code == codeKiss {
			e.Kiss, e.KissAuthentic = C.GoStringN(&v.last_kiss[0], 4), bool(v.last_kiss_authentic)
		}
		if ClassOf(e.Code) == ClassHost {
			core.st.mu.Lock()
			e.Host = core.st.err[i]
			core.st.mu.Unlock()
		}
		ps.LastErr = e
	}
	return ps
}

// Combine forms the quorum of the fresh samples, checks it against the
// coarse time (read at the monotonic time coarseLocal) and against the
// earlier quorums, and serves it. The refusal is an *Error (ErrBusy during
// a poll), or ErrClosed.
func (core *Core) Combine(coarse time.Time, coarseLocal int64) error {
	if !core.polls.TryLock() {
		return &Error{Code: codeBusy}
	}
	defer core.polls.Unlock()
	core.mu.Lock()
	defer core.mu.Unlock()
	if core.c == nil {
		return ErrClosed
	}
	if rc := C.nts_combine(core.c, C.int64_t(unixNanos(coarse)), C.int64_t(coarseLocal)); rc != 0 {
		e := &Error{Code: int(rc)}
		if rc == C.NTS_ERR_ERA_WINDOW {
			st := new(C.nts_status)
			C.nts_summary_get(core.c, st)
			e.Detail = int(st.last_detail)
		}
		return e
	}
	return nil
}

// Bounded is the time now and its error bound, or a refusal (an *Error:
// no quorum, the bound over the limit, or the quorum's samples over the
// age limit; the bound comes back with it).
func (core *Core) Bounded() (time.Time, time.Duration, error) {
	core.mu.Lock()
	defer core.mu.Unlock()
	if core.c == nil {
		return time.Time{}, 0, ErrClosed
	}
	var t, b C.int64_t
	rc := C.nts_bounded(core.c, &t, &b)
	if rc != 0 {
		return time.Time{}, time.Duration(b), &Error{Code: int(rc)}
	}
	return time.Unix(0, int64(t)), time.Duration(b), nil
}

// Status is a full snapshot; during a poll it is the summary with Busy
// set and no Peers. Summary is the snapshot without the peers; it may run
// during polls.
func (core *Core) Status() Status  { return core.snapshot(true) }
func (core *Core) Summary() Status { return core.snapshot(false) }

func (core *Core) snapshot(peers bool) Status {
	// The peers are read with the polls kept out; during one, the summary.
	held := peers && core.polls.TryLock()
	if held {
		defer core.polls.Unlock()
	}
	core.mu.Lock()
	defer core.mu.Unlock()
	if core.c == nil {
		return Status{}
	}
	st := new(C.nts_status)
	if !held {
		C.nts_summary_get(core.c, st)
		out := core.statusFromC(st)
		out.Busy = peers
		return out
	}
	C.nts_status_get(core.c, st)
	out := core.statusFromC(st)
	for i := 0; i < int(st.npeers) && !out.Busy; i++ {
		out.Peers = append(out.Peers, core.peerStatus(i, &st.peers[i]))
	}
	return out
}

func (core *Core) statusFromC(st *C.nts_status) Status {
	out := Status{
		HaveResult: bool(st.have_result), Offset: int64(st.offset), Bound: time.Duration(st.bound), At: int64(st.at), Lo: int64(st.lo), Hi: int64(st.hi),
		HaveDrift: bool(st.have_drift), DriftDelta: time.Duration(st.drift_delta), DriftDT: time.Duration(st.drift_dt), DriftBounds: time.Duration(st.drift_bounds),
		Violations: int64(st.violations), Refusals: int64(st.refusals), HaveCoarseDiff: bool(st.have_coarse_diff), CoarseDiff: time.Duration(st.coarse_diff),
		LastFresh: int(st.last_fresh), MembersChanged: bool(st.members_changed), Busy: bool(st.busy),
		Sampled: int64(st.sampled), Now: int64(st.now), BoundNow: time.Duration(st.bound_now), SampleAge: time.Duration(st.sample_age),
		Protocol: Protocol(st.protocol), Worst: time.Duration(st.worst), MaxWrong: int(st.max_wrong), Cold: bool(st.cold), EraPivot: int64(st.era_pivot),
	}
	if st.refusal != 0 {
		out.Refusal = &Error{Code: int(st.refusal)}
	}
	for i := 0; i < int(st.npeers); i++ {
		if uint32(st.members)&(1<<i) != 0 {
			out.Members = append(out.Members, i)
		}
	}
	if st.last_err != 0 {
		out.LastErr = &Error{Code: int(st.last_err), Detail: int(st.last_detail)}
	}
	return out
}

// unixNanos is t in Unix nanoseconds, saturated: time.Time.UnixNano is
// undefined outside 1678 to 2262, and the zero time (no coarse reading)
// must reach the core as a time before every floor, never as the
// arbitrary value that would give.
func unixNanos(t time.Time) int64 {
	switch {
	case t.Before(time.Unix(0, math.MinInt64)):
		return math.MinInt64
	case t.After(time.Unix(0, math.MaxInt64)):
		return math.MaxInt64
	}
	return t.UnixNano()
}

func serverFromC(s *C.nts_server) Server {
	return Server{
		Operator: C.GoStringN(&s.op[0], C.int(s.op_len)),
		Host:     C.GoStringN(&s.host[0], C.int(s.host_len)),
		KEAddr:   C.GoStringN(&s.ke_addr[0], C.int(s.ke_addr_len)),
		NTPAddr:  C.GoStringN(&s.ntp_addr[0], C.int(s.ntp_addr_len)),
		Roots:    C.GoBytes(unsafe.Pointer(&s.roots[0]), C.int(s.roots_len)),
	}
}

func stateOf(h C.uintptr_t) *hostState { return cgo.Handle(h).Value().(*hostState) }

type udpSock struct {
	conn UDPConn
	peer int
}

//export ntsgoRandom
func ntsgoRandom(h C.uintptr_t, buf *C.uint8_t, n C.size_t) C.int {
	if err := stateOf(h).ops.Random(unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(n))); err != nil {
		return C.NTS_ERR_HOST
	}
	return C.NTS_OK
}

//export ntsgoMonotonic
func ntsgoMonotonic(h C.uintptr_t) C.int64_t { return C.int64_t(stateOf(h).ops.Monotonic()) }

//export ntsgoKeyExchange
func ntsgoKeyExchange(h C.uintptr_t, peer C.size_t, srv *C.nts_server, validity, timeout C.int64_t, req *C.uint8_t, reqlen C.size_t,
	resp *C.uint8_t, respcap C.size_t, resplen *C.size_t, c2s, s2c *C.uint8_t, elapsed *C.int64_t) C.int {
	st := stateOf(h)
	s := serverFromC(srv)
	reqb := unsafe.Slice((*byte)(unsafe.Pointer(req)), int(reqlen))
	respb := unsafe.Slice((*byte)(unsafe.Pointer(resp)), int(respcap))
	n, k1, k2, el, err := st.ops.KeyExchange(int(peer), &s, time.Unix(0, int64(validity)), time.Duration(timeout), reqb, respb)
	*elapsed = C.int64_t(el)
	if err == nil && (len(k1) != KeyLen || len(k2) != KeyLen || n < 0 || n > int(respcap)) {
		err = errors.New("nts-ke: the host gave keys or a response of the wrong length")
	}
	if err != nil {
		clear(k1)
		clear(k2)
		st.setErr(int(peer), err)
		return hostCode(err, false)
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(c2s)), KeyLen), k1)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(s2c)), KeyLen), k2)
	clear(k1)
	clear(k2)
	*resplen = C.size_t(n)
	return C.NTS_OK
}

//export ntsgoUDPOpen
func ntsgoUDPOpen(h C.uintptr_t, peer C.size_t, addr *C.char, addrlen C.size_t, timeout C.int64_t, out *C.uintptr_t) C.int {
	st := stateOf(h)
	conn, err := st.ops.UDPOpen(int(peer), C.GoStringN(addr, C.int(addrlen)), time.Duration(timeout))
	if err != nil {
		st.setErr(int(peer), err)
		return hostCode(err, false)
	}
	*out = C.uintptr_t(cgo.NewHandle(&udpSock{conn: conn, peer: int(peer)}))
	return C.NTS_OK
}

func sockOf(s C.uintptr_t) *udpSock { return cgo.Handle(s).Value().(*udpSock) }

//export ntsgoUDPSend
func ntsgoUDPSend(h C.uintptr_t, sock C.uintptr_t, p *C.uint8_t, n C.size_t) C.int {
	s := sockOf(sock)
	if err := s.conn.Send(unsafe.Slice((*byte)(unsafe.Pointer(p)), int(n))); err != nil {
		stateOf(h).setErr(s.peer, err)
		return hostCode(err, false)
	}
	return C.NTS_OK
}

//export ntsgoUDPRecv
func ntsgoUDPRecv(h C.uintptr_t, sock C.uintptr_t, buf *C.uint8_t, capacity C.size_t, n *C.size_t, wait C.int64_t) C.int {
	s := sockOf(sock)
	got, err := s.conn.Recv(unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(capacity)), time.Duration(wait))
	if err != nil {
		stateOf(h).setErr(s.peer, err)
		return hostCode(err, true)
	}
	*n = C.size_t(got)
	return C.NTS_OK
}

//export ntsgoUDPClose
func ntsgoUDPClose(h C.uintptr_t, sock C.uintptr_t) {
	s := sockOf(sock)
	s.conn.Close()
	cgo.Handle(sock).Delete()
}
