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
	"net"
	"runtime/cgo"
	"sync"
	"time"
	"unsafe"
)

// Server is one NTS server: the operator who runs it, its TLS name, where
// NTS-KE is dialed, and the operator's pinned roots (PEM). It is
// configuration of the core and must come by a trusted path.
type Server struct {
	Operator string
	Host     string
	KEAddr   string // host:port of NTS-KE; "" means Host:4460
	Roots    []byte
}

// Config is the core's configuration: nts_config of nts_core.h. Every
// duration must be set.
type Config struct {
	Servers            []Server
	Interval           time.Duration // between two queries to one server
	MinPoll            time.Duration // the shortest poll interval
	MaxPoll            time.Duration // the longest, after Kiss-o'-Death backoff
	MaxBound           time.Duration // Bounded refuses over it
	MaxCoarseDiff      time.Duration // a quorum further from the coarse time is refused
	CoarseResolution   time.Duration // the coarse reading names the second it was in
	ExchangeTimeout    time.Duration // one NTS-KE session or one query
	KissGrace          time.Duration // how long a query reads on after a Kiss-o'-Death
	DriftBaselinePolls int           // times Interval: the baseline of the drift check
	FloorUnix          time.Time     // a time known at build to be in the past: the NTP era pivot
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
	CookiesHeld      int
	LastDelay        time.Duration
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
}

// Status is a snapshot of the client.
type Status struct {
	HaveResult     bool
	Offset         int64 // real Unix ns minus monotonic ns, at At
	Bound          time.Duration
	At             int64
	Lo, Hi         int64
	Members        []int // the servers of the quorum, by index
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
	Peers          []PeerStatus
}

// Core is the client: the C state, the host operations and their Go
// implementation.
//
// Polls of different servers may run at the same time, on their own
// goroutines; Combine, Status and Close may not run during a poll (the
// caller serializes them, as clock.NTS does with its refresh lock). Bounded
// and Summary may run at any time.
type Core struct {
	mu      sync.Mutex
	c       *C.nts_core
	st      *hostState
	h       cgo.Handle
	servers []Server
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

func (st *hostState) takeErr(peer int) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	err := st.err[peer]
	delete(st.err, peer)
	return err
}

// New allocates a core with cfg and ops. Close frees it.
func New(cfg Config, ops HostOps) (*Core, error) {
	if len(cfg.Servers) > MaxServers {
		return nil, fmt.Errorf("%w: %d servers, at most %d", ErrBadConfig, len(cfg.Servers), MaxServers)
	}
	for _, s := range cfg.Servers {
		switch {
		case len(s.Operator) < 1 || len(s.Operator) > MaxOperatorLen:
			return nil, fmt.Errorf("%w: operator label %q empty or over %d octets", ErrBadConfig, s.Operator, MaxOperatorLen)
		case len(s.Host) < 1 || len(s.Host) > MaxServerName:
			return nil, fmt.Errorf("%w: host %q empty or over %d octets", ErrBadConfig, s.Host, MaxServerName)
		case len(s.KEAddr) > C.NTS_MAX_ADDR_LEN:
			return nil, fmt.Errorf("%w: NTS-KE address %q over %d octets", ErrBadConfig, s.KEAddr, C.NTS_MAX_ADDR_LEN)
		case len(s.Roots) > MaxRootsLen:
			return nil, fmt.Errorf("%w: roots of %s: %d octets, at most %d", ErrBadConfig, s.Operator, len(s.Roots), MaxRootsLen)
		}
	}
	ccfg := (*C.nts_config)(C.calloc(1, C.sizeof_nts_config))
	defer C.free(unsafe.Pointer(ccfg))
	ccfg.nservers = C.size_t(len(cfg.Servers))
	for i, s := range cfg.Servers {
		cs := &ccfg.servers[i]
		cs.op_len = C.size_t(copy(unsafe.Slice((*byte)(unsafe.Pointer(&cs.op[0])), MaxOperatorLen), s.Operator))
		cs.host_len = C.size_t(copy(unsafe.Slice((*byte)(unsafe.Pointer(&cs.host[0])), MaxServerName), s.Host))
		cs.ke_addr_len = C.size_t(copy(unsafe.Slice((*byte)(unsafe.Pointer(&cs.ke_addr[0])), C.NTS_MAX_ADDR_LEN), s.KEAddr))
		cs.roots_len = C.size_t(copy(unsafe.Slice((*byte)(unsafe.Pointer(&cs.roots[0])), MaxRootsLen), s.Roots))
	}
	ccfg.interval_ns = C.int64_t(cfg.Interval)
	ccfg.min_poll_ns = C.int64_t(cfg.MinPoll)
	ccfg.max_poll_ns = C.int64_t(cfg.MaxPoll)
	ccfg.max_bound_ns = C.int64_t(cfg.MaxBound)
	ccfg.max_coarse_diff_ns = C.int64_t(cfg.MaxCoarseDiff)
	ccfg.coarse_resolution_ns = C.int64_t(cfg.CoarseResolution)
	ccfg.exchange_timeout_ns = C.int64_t(cfg.ExchangeTimeout)
	ccfg.kiss_grace_ns = C.int64_t(cfg.KissGrace)
	ccfg.drift_baseline_polls = C.int(cfg.DriftBaselinePolls)
	ccfg.floor_unix_ns = C.int64_t(cfg.FloorUnix.UnixNano())

	st := &hostState{ops: ops, err: map[int]error{}}
	core := &Core{c: (*C.nts_core)(C.calloc(1, C.nts_core_size())), st: st, h: cgo.NewHandle(st)}
	core.servers = append([]Server(nil), cfg.Servers...)
	var cops C.nts_host_ops
	C.ntsgo_make_ops(&cops, C.uintptr_t(core.h))
	if rc := C.nts_core_init(core.c, &cops, ccfg); rc != 0 {
		core.free()
		return nil, CodeError(int(rc), 0)
	}
	return core, nil
}

func (core *Core) free() {
	C.free(unsafe.Pointer(core.c))
	core.c = nil
	core.h.Delete()
}

// Close wipes the keys and the cookies and frees the core.
func (core *Core) Close() {
	core.mu.Lock()
	defer core.mu.Unlock()
	if core.c == nil {
		return
	}
	C.nts_core_wipe(core.c)
	core.free()
}

// Servers is the configuration, by index.
func (core *Core) Servers() []Server { return core.servers }

// Due is the servers due for a poll at the monotonic time now.
func (core *Core) Due(now int64) []int {
	mask := uint32(C.nts_due(core.c, C.int64_t(now)))
	var out []int
	for i := range core.servers {
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
// refusal, if any (an *Error; ErrNotDue when nothing was done).
func (core *Core) Poll(i int, coarse time.Time, coarseLocal int64) (PeerStatus, error) {
	rc := C.nts_poll(core.c, C.size_t(i), C.int64_t(coarse.UnixNano()), C.int64_t(coarseLocal))
	var v C.nts_peer_view
	C.nts_peer_get(core.c, C.size_t(i), &v)
	ps := core.peerStatus(i, &v)
	if rc == 0 {
		return ps, nil
	}
	return ps, core.pollError(i, int(rc), int(v.last_detail), &v)
}

// Peer is server i's state, as its last poll left it. It reads only that
// server; it may run while other servers' polls do.
func (core *Core) Peer(i int) PeerStatus {
	var v C.nts_peer_view
	C.nts_peer_get(core.c, C.size_t(i), &v)
	return core.peerStatus(i, &v)
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
			CookiesHeld: int(v.stats.cookies_held), LastDelay: time.Duration(v.stats.last_delay_ns), LastBound: time.Duration(v.stats.last_bound_ns),
			Kisses: map[string]int{},
		},
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
// earlier quorums, and serves it. The refusal is an *Error.
func (core *Core) Combine(coarse time.Time, coarseLocal int64) error {
	core.mu.Lock()
	defer core.mu.Unlock()
	rc := C.nts_combine(core.c, C.int64_t(coarse.UnixNano()), C.int64_t(coarseLocal))
	if rc == 0 {
		return nil
	}
	var st C.nts_status
	C.nts_summary_get(core.c, &st)
	return &Error{Code: int(rc), Detail: int(st.last_detail)}
}

// Bounded is the time now and its error bound, or a refusal (an *Error:
// no quorum, or the bound over the limit; the bound comes back with it).
func (core *Core) Bounded() (time.Time, time.Duration, error) {
	core.mu.Lock()
	defer core.mu.Unlock()
	var t, b C.int64_t
	rc := C.nts_bounded(core.c, &t, &b)
	if rc != 0 {
		return time.Time{}, time.Duration(b), &Error{Code: int(rc)}
	}
	return time.Unix(0, int64(t)), time.Duration(b), nil
}

// Status is a full snapshot; no poll may run meanwhile.
func (core *Core) Status() Status {
	core.mu.Lock()
	defer core.mu.Unlock()
	var st C.nts_status
	C.nts_status_get(core.c, &st)
	out := core.statusFromC(&st)
	for i := range core.servers {
		out.Peers = append(out.Peers, core.peerStatus(i, &st.peers[i]))
	}
	return out
}

// Summary is the snapshot without the peers; it may run during polls.
func (core *Core) Summary() Status {
	core.mu.Lock()
	defer core.mu.Unlock()
	var st C.nts_status
	C.nts_summary_get(core.c, &st)
	return core.statusFromC(&st)
}

func (core *Core) statusFromC(st *C.nts_status) Status {
	out := Status{
		HaveResult: bool(st.have_result), Offset: int64(st.offset), Bound: time.Duration(st.bound), At: int64(st.at), Lo: int64(st.lo), Hi: int64(st.hi),
		HaveDrift: bool(st.have_drift), DriftDelta: time.Duration(st.drift_delta), DriftDT: time.Duration(st.drift_dt), DriftBounds: time.Duration(st.drift_bounds),
		Violations: int64(st.violations), Refusals: int64(st.refusals), HaveCoarseDiff: bool(st.have_coarse_diff), CoarseDiff: time.Duration(st.coarse_diff),
		LastFresh: int(st.last_fresh), MembersChanged: bool(st.members_changed),
	}
	for i := range core.servers {
		if uint32(st.members)&(1<<i) != 0 {
			out.Members = append(out.Members, i)
		}
	}
	if st.last_err != 0 {
		out.LastErr = &Error{Code: int(st.last_err), Detail: int(st.last_detail)}
	}
	return out
}

func serverFromC(s *C.nts_server) Server {
	return Server{
		Operator: C.GoStringN(&s.op[0], C.int(s.op_len)),
		Host:     C.GoStringN(&s.host[0], C.int(s.host_len)),
		KEAddr:   C.GoStringN(&s.ke_addr[0], C.int(s.ke_addr_len)),
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
		st.setErr(int(peer), err)
		return C.NTS_ERR_HOST
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
		return C.NTS_ERR_HOST
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
		return C.NTS_ERR_HOST
	}
	return C.NTS_OK
}

//export ntsgoUDPRecv
func ntsgoUDPRecv(h C.uintptr_t, sock C.uintptr_t, buf *C.uint8_t, capacity C.size_t, n *C.size_t, wait C.int64_t) C.int {
	s := sockOf(sock)
	got, err := s.conn.Recv(unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(capacity)), time.Duration(wait))
	if err != nil {
		stateOf(h).setErr(s.peer, err)
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return C.NTS_ERR_HOST_TIMEOUT
		}
		return C.NTS_ERR_HOST
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
