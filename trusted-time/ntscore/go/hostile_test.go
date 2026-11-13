//go:build nts

package ntscore

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/devkit/fuzzcheck"
)

// A hostile host. The wrapper is the network: whatever the untrusted
// operations hand the core, an attacker on the wire could hand it too. So
// here they hand it everything the fuzzer can think of, and the trusted
// operations (random bytes, the monotonic clock, the TLS session's keys)
// stay honest, and the properties the core promises must hold whatever
// the untrusted side does:
//
//   - a sample is taken only when the honest answer to the core's own live
//     request was delivered, and it measures that server's clock within
//     its bound;
//   - every request the core sends verifies under the C2S key, carries a
//     cookie the key exchange or an authentic answer issued and that never
//     went out before (RFC 8915 section 5.7, a send the host said failed
//     included), and a Unique Identifier never used before;
//   - the jar never holds more than MaxCookies cookies;
//   - a time is served only from a quorum of at least MinServers operators
//     with fresh samples; while no more of its members lie than the core
//     allowed wrong in it (QuorumWrong of its samples) it is within its
//     bound of the true time, and with up to QuorumWrong of all the
//     servers lying (authentic answers, colluding or not) it is never
//     further from it than the bound and one sample's cap, since at least
//     three members agree and one of them is honest; it never goes back;
//     its bound ages;
//   - the key exchange request is the one the RFC asks for, and the NTP
//     address is the one the key exchange named;
//   - a host operation that reports the caller cancelled it costs no
//     error, no loss streak and no backoff, and a cookie still goes out
//     once;
//   - a coarse reading 2^32 s off (another NTP era) never gets a time of
//     that era served;
//   - nothing crashes (the sanitizer run of scripts/test-modules.sh).
//
// The configuration calls are not the host's: they are the trusted side's,
// and the harness issues them between rounds as such, with legal and
// illegal values. After a removal no quorum in force has the removed
// operator as a member, an illegal call changes nothing, and the time
// never goes back across either call.
//
// Plain NTP is the weaker promise the header states: the world sees the
// transmit timestamp and forges answers freely, so what must hold there is
// only that the served time passed the coarse check against a coarse
// reading the world gave, is not before the floor, and never goes back;
// and that the core never runs a key exchange and sends the bare header
// with a transmit timestamp never used before.
//
// The honest answers are built by the server side of ntp_test.go and
// ke_test.go, on ntstest's independent AES-SIV. The clock is virtual and
// advances by amounts the fuzzer picks, including hours, so the bound's
// ageing and refusal are exercised too. TestHostileHostRounds runs the
// harness on fixed seeds; FuzzHostileHost runs it under the fuzzing
// engine.

// decisions is the fuzzer's byte stream. Exhausted, it reads as zero,
// which is the honest choice everywhere: the run then ends with honest
// behaviour and the quorum forms.
type decisions struct {
	data []byte
	at   int
}

func (d *decisions) next() byte {
	if d.at >= len(d.data) {
		d.at++
		return 0
	}
	b := d.data[d.at]
	d.at++
	return b
}

func (d *decisions) pick(n int) int { return int(d.next()) % n }
func (d *decisions) done() bool     { return d.at > len(d.data)+16 }

// hostileServer is one operator's honest server, as the harness plays it:
// the keys the TLS exporter would give, the cookies it issued, and its
// clock's error against true time (0 for an honest server, the liar's lie
// otherwise).
type hostileServer struct {
	op      string
	host    string // the TLS name in the current list ("": nts-<op>.test); a change of it makes the core's peer a new one
	renamed bool   // host changed since the last list (policy_test.go's swap)
	c2s     []byte
	s2c     []byte
	offset  int64  // the server's clock minus true time
	ntpAddr string // the server's plain NTP address in the list, "" for none
	last    []byte // the last answer, for replays
}

// cookie is a fresh cookie of s, remembered as its. Its length is the
// fuzzer's pick: 100 octets (the honest default); under the 12 octets a
// field must carry (padded with zeros in the request, so the padded form
// is remembered too; at least 4 octets, so that two random cookies are
// never the same); 12; and the longest allowed, with which no placeholder
// fits the request.
func (w *hostileWorld) cookie(s *hostileServer) []byte {
	n := w.cookieLen
	if n == 0 {
		n = []int{100, 4, 7, 11, 12, 1024}[w.d.pick(6)]
	}
	c := w.rng.bytes(n)
	w.issued[hex.EncodeToString(c)] = s
	if padded := (max(n, 12) + 3) / 4 * 4; padded != n {
		w.issued[hex.EncodeToString(append(append([]byte(nil), c...), make([]byte, padded-n)...))] = s
	}
	return c
}

// hostileWorld is the host: the virtual clock, the servers, and what each
// poll under way has been given.
type hostileWorld struct {
	t           testing.TB
	d           *decisions
	rng         testRng // the trusted CSPRNG: honest, deterministic here
	now         int64   // the virtual monotonic clock, ns
	trueOffset  int64   // true Unix ns = now + trueOffset
	servers     []*hostileServer
	live        map[int]*clientRequest // the request of the poll under way, per peer
	honest      map[int]bool           // the honest answer to it was delivered
	uids        map[[UniqueIDLen]byte]bool
	answers     [][]byte                  // every honest answer ever sent, for replays
	issued      map[string]*hostileServer // every cookie ever issued, by which server
	named       map[int]string            // the NTP address the last key exchange response named, per peer
	dialed      map[int]string            // the address of an earlier key exchange the core took (it dialed it), per peer
	got         []string                  // what the poll under way was given, for the failure message
	coarse      int64                     // the coarse time the host gave, at the monotonic time coarseLocal
	coarseLocal int64
	sent        map[string]bool // every cookie a request carried
	failed      error

	// Set by the tests of client_test.go, never by the fuzzer: an honest
	// host otherwise. The zero values are the harness as the fuzzer runs it.
	keNoServerPort bool          // the key exchange names no NTP server or port
	keServer       string        // the NTP server the key exchange names, if not ntp-<op>.test
	keBad          int           // 1: a C2S key of 31 octets, 2: an S2C key of 33, 3: a response length over the buffer
	drop           int           // this many next queries get no answer
	kiss           string        // every answer is an authentic Kiss-o'-Death with this code
	kissThenAnswer string        // every answer is an authentic Kiss-o'-Death with this code, then the real answer
	sendFail       bool          // the send goes out, but the host reports a failure
	keFail         int           // this many next key exchanges fail to connect
	keNoServer     bool          // the key exchange names no NTP server (the port stays)
	keNoPort       bool          // the key exchange names no NTP port (the server stays)
	kePort         uint16        // the NTP port the key exchange names; 0 means 1234
	randomFail     bool          // the CSPRNG fails
	cookieLen      int           // every cookie issued is this long; 0: the fuzzer picks
	opens          int           // UDP sockets opened
	keValidity     int64         // the certificate time the last key exchange was given
	core           *Core         // the core under test, for the certificate rule
	rootDispersion uint32        // the root dispersion of every answer (NTP short format); 0: the fuzzer picks
	cancelAt       int           // the caller cancels at this operation: 1 key exchange, 2 open, 3 send, 4 receive
	onOpen         func()        // called from UDPOpen, during the poll
	onClose        func()        // called when the poll's socket is closed, still during the poll
	onMono         func()        // called from Monotonic: during whatever call of the core reads the clock
	silent         bool          // the NTP side takes every request and answers none, and checks nothing
	rawCode        [5]int        // the host operation (cancelAt's numbers) fails with this code as it is, not one of the host's three
	openTimeout    time.Duration // the timeout the last socket was opened with
	plainKiss      string        // every answer is a Kiss-o'-Death with this code and no authenticator (under NTS)

	// The current list: server i of the core is list[i]. nil: servers.
	list []*hostileServer
	// Plain NTP: no key exchange, the header alone, and the world forges.
	plain      bool
	transmits  map[[8]byte]bool // every transmit timestamp a plain request carried
	forge      bool             // the fuzzer forges plain answers (runHostile); the tests of client_test.go get honest ones
	cancelFuzz bool             // the fuzzer cancels operations at random
	kes        int              // key exchanges run
}

func (w *hostileWorld) server(peer int) *hostileServer {
	if w.list != nil {
		return w.list[peer]
	}
	return w.servers[peer]
}

// cancelled says whether the caller cancels operation op (cancelAt's
// numbers) now, and gives the error a host returns then.
func (w *hostileWorld) cancelled(op int) error {
	if w.cancelAt == op || (w.cancelFuzz && w.d.pick(16) == 15) {
		return fmt.Errorf("the tick's deadline: %w", ErrHostCancelled)
	}
	return nil
}

func (w *hostileWorld) fail(format string, args ...any) {
	if w.failed == nil {
		w.failed = fmt.Errorf(format, args...)
	}
}

func (w *hostileWorld) trueNow() int64 { return w.now + w.trueOffset }

// advance moves the virtual clock by an amount the fuzzer picks: usually
// microseconds to milliseconds, sometimes seconds, hours or days.
func (w *hostileWorld) advance() {
	var d int64
	switch w.d.pick(16) {
	case 15:
		d = int64(time.Second) * int64(1+w.d.pick(60))
	case 14:
		d = int64(time.Hour) * int64(1+w.d.pick(48))
	case 13:
		d = int64(24*time.Hour) * int64(1+w.d.pick(300))
	case 11, 12:
		d = int64(time.Millisecond) * int64(1+w.d.pick(200))
	default:
		d = int64(time.Microsecond) * int64(1+w.d.pick(2000))
	}
	w.now += d
}

func (w *hostileWorld) Random(buf []byte) error {
	if w.randomFail {
		return errors.New("the CSPRNG failed")
	}
	copy(buf, w.rng.bytes(len(buf)))
	return nil
}

func (w *hostileWorld) Monotonic() int64 {
	if w.onMono != nil {
		w.onMono()
	}
	w.now += int64(time.Microsecond)
	return w.now
}

// mutated is a copy of b changed by the fuzzer: random_test.go's mutate.
func (w *hostileWorld) mutated(b []byte) []byte {
	seed := testRng(binary.LittleEndian.Uint64(w.rng.bytes(8)))
	return mutate(&seed, b)
}

func (w *hostileWorld) garbage() []byte { return w.rng.bytes(w.d.pick(1300)) }

// KeyExchange: the TLS session is trusted, so the keys are the server's;
// what comes through it is not.
func (w *hostileWorld) KeyExchange(peer int, srv *Server, validity time.Time, timeout time.Duration, req, resp []byte) (int, []byte, []byte, time.Duration, error) {
	s := w.server(peer)
	w.kes++
	if w.plain {
		w.fail("peer %d: a key exchange under plain NTP", peer)
	}
	if !bytes.Equal(req, KERequest()) {
		w.fail("peer %d: NTS-KE request %x", peer, req)
	}
	if srv.Operator != s.op || (s.host != "" && srv.Host != s.host) {
		w.fail("peer %d: the core named operator %q at %q", peer, srv.Operator, srv.Host)
	}
	// The certificate is dated by the core's own time while it would serve
	// it (then within its bound, so within a second, of the true time), and
	// by the coarse time the host gave, moved forward, otherwise. The
	// snapshot is a few microseconds after the core's own reading, so near
	// the age or bound limit either is accepted.
	// A coarse reading below the era pivot (a time the core served) is
	// raised to it: no certificate is dated before the pivot.
	coarseDate := w.coarse + (w.now - w.coarseLocal)
	var st Status
	if w.core != nil {
		st = w.core.Summary()
		if validity.UnixNano() < st.EraPivot {
			w.fail("peer %d: certificate validity %v, before the era pivot %v", peer, validity, time.Unix(0, st.EraPivot))
		}
		coarseDate = max(coarseDate, st.EraPivot)
	}
	fromCoarse := validity.UnixNano() - coarseDate
	fromTrue := validity.UnixNano() - max(w.trueNow(), st.EraPivot)
	within := func(d int64) bool { return d <= int64(time.Second) && -d <= int64(time.Second) }
	ok := within(fromCoarse) || within(fromTrue)
	if w.core != nil {
		switch {
		case st.Refusal == nil && st.SampleAge < 4*time.Second && st.BoundNow < 50*time.Millisecond:
			ok = within(fromTrue)
		case st.Refusal != nil && (errors.Is(st.Refusal, ErrNoQuorum) || st.SampleAge > 6*time.Second || st.BoundNow > 150*time.Millisecond):
			ok = within(fromCoarse)
		}
	}
	if !ok {
		w.fail("peer %d: certificate validity %v, true time %v, coarse %v", peer, validity, time.Unix(0, w.trueNow()), time.Unix(0, w.coarse))
	}
	w.keValidity = validity.UnixNano()
	if err := w.cancelled(1); err != nil {
		return 0, nil, nil, 0, err
	}
	if w.rawCode[1] != 0 {
		return 0, nil, nil, 0, rawHostCode(w.rawCode[1])
	}
	if w.keFail > 0 {
		w.keFail--
		return 0, nil, nil, 0, errors.New("nts-ke: connection refused")
	}
	w.advance()
	honest := func(from *hostileServer, n int) []byte {
		var cookies [][]byte
		for i := 0; i < n; i++ {
			cookies = append(cookies, w.cookie(from))
		}
		records := goodKERecords(cookies)
		if !w.keNoServerPort && !w.keNoServer {
			name := w.keServer
			if name == "" {
				name = fmt.Sprintf("ntp-%s.test", s.op)
			}
			records = append(records, keRec(true, RecServer, []byte(name)))
		}
		if !w.keNoServerPort && !w.keNoPort {
			port := w.kePort
			if port == 0 {
				port = 1234
			}
			records = append(records, keRec(false, RecPort, []byte{byte(port >> 8), byte(port)}))
		}
		return bytes.Join(append(records, keEOM()), nil)
	}
	var body []byte
	switch w.d.pick(8) {
	case 0, 1, 2:
		body = honest(s, 8)
	case 3:
		body = honest(s, 1+w.d.pick(12))
	case 4:
		body = w.mutated(honest(s, 8))
	case 5:
		body = w.garbage()
	case 6:
		// Another operator's cookies: they do not go with these keys.
		body = honest(w.servers[w.d.pick(len(w.servers))], 8)
	default:
		return 0, nil, nil, 0, errors.New("nts-ke: connection refused")
	}
	// What the response names is where the core must dial, if it takes
	// the response at all.
	// A key exchange the core ran with cookies in hand (after a streak of
	// lost queries) leaves the earlier address in force if it fails.
	delete(w.named, peer)
	if r, err := ParseKEResponse(body); err == nil {
		host, port := srv.Host, "123"
		if r.Server != "" {
			host = r.Server
		}
		if r.Port != 0 {
			port = fmt.Sprint(r.Port)
		}
		w.named[peer] = net.JoinHostPort(host, port)
	}
	n := copy(resp, body)
	c2s, s2c := append([]byte(nil), s.c2s...), append([]byte(nil), s.s2c...)
	switch w.keBad {
	case 1:
		c2s = c2s[:31]
	case 2:
		s2c = append(s2c, 0)
	case 3:
		n = len(resp) + 1
	}
	return n, c2s, s2c, time.Duration(w.d.pick(900)) * time.Millisecond, nil
}

type hostileConn struct {
	w    *hostileWorld
	peer int
	// The answers queued for this exchange, in order; nil means nothing
	// more comes.
	queue [][]byte
	tags  []string
}

func (w *hostileWorld) UDPOpen(peer int, addr string, timeout time.Duration) (UDPConn, error) {
	w.openTimeout = timeout
	if w.onOpen != nil {
		w.onOpen()
	}
	if w.rawCode[2] != 0 {
		return nil, rawHostCode(w.rawCode[2])
	}
	if w.silent {
		return silentConn{w}, nil
	}
	if w.plain {
		s := w.server(peer)
		host := s.host
		if host == "" {
			host = fmt.Sprintf("nts-%s.test", s.op)
		}
		if want := net.JoinHostPort(host, "123"); (s.ntpAddr == "" && addr != want) || (s.ntpAddr != "" && addr != s.ntpAddr) {
			w.fail("peer %d: plain NTP dialed %q, want the server's NTP address %q, or without one %q", peer, addr, s.ntpAddr, want)
		}
	} else if want, ok := w.named[peer]; ok && addr == want {
		w.dialed[peer] = addr
	} else if was, ok := w.dialed[peer]; !ok || addr != was {
		w.fail("peer %d: dialed %q, the key exchange named %q (and an earlier one %q)", peer, addr, want, was)
	}
	if err := w.cancelled(2); err != nil {
		return nil, err
	}
	if w.d.pick(10) == 9 {
		return nil, errors.New("ntp: no route")
	}
	w.opens++
	return &hostileConn{w: w, peer: peer}, nil
}

// Send reads the request as a server would, checks it, and queues the
// answers the fuzzer wants delivered.
func (c *hostileConn) Send(p []byte) error {
	w := c.w
	s := w.server(c.peer)
	if w.plain {
		return c.sendPlain(p)
	}
	req := serverReadRequest(s.c2s, p)
	if req == nil {
		w.fail("peer %d: a request that does not verify under the C2S key: %x", c.peer, p)
		return nil
	}
	by := w.issued[hex.EncodeToString(req.cookie)]
	var uid [UniqueIDLen]byte
	copy(uid[:], req.uniqueID)
	if w.uids[uid] {
		w.fail("peer %d: a Unique Identifier used twice", c.peer)
	}
	w.uids[uid] = true
	if ck := hex.EncodeToString(req.cookie); w.sent[ck] {
		w.fail("peer %d: a cookie sent twice", c.peer)
	} else {
		w.sent[ck] = true
	}
	if req.placeholders > MaxPlaceholders || len(p) > NTPMaxRequestLen {
		w.fail("peer %d: %d placeholders, %d octets", c.peer, req.placeholders, len(p))
	}
	w.live[c.peer] = req
	w.honest[c.peer] = false
	// The honest answer: the server's clock is true time plus its error;
	// the request takes a while to arrive and the server holds it a bit.
	w.advance()
	recv := w.trueNow() + s.offset
	hold := int64(w.d.pick(5)) * int64(time.Millisecond)
	w.now += hold
	r := goodReply()
	r.stratum, r.precision = uint8(1+w.d.pick(15)), int8(-20+w.d.pick(12))
	r.rootDelay, r.rootDispersion = uint32(w.d.pick(600)), uint32(w.d.pick(600))
	if w.rootDispersion != 0 {
		r.rootDispersion = w.rootDispersion
	}
	r.reference = uint64(NTPFromUnixNanos(recv - 16*int64(time.Second)))
	r.receive, r.transmit = uint64(NTPFromUnixNanos(recv)), uint64(NTPFromUnixNanos(recv+hold))
	r.nonce = w.rng.bytes(1 + w.d.pick(24))
	r.cookies = nil
	for i := 0; i <= req.placeholders; i++ {
		r.cookies = append(r.cookies, w.cookie(s))
	}
	kod := func(code string, authentic bool) []byte {
		k := goodReply()
		k.leap, k.stratum = 3, 0
		copy(k.referenceID[:], code)
		k.noAuthenticator = !authentic
		return serverResponse(s.s2c, req, &k)
	}
	if w.sendFail {
		return errors.New("ntp: write: the host says it failed")
	}
	if err := w.cancelled(3); err != nil {
		return err
	}
	if w.rawCode[3] != 0 {
		return rawHostCode(w.rawCode[3])
	}
	var answer []byte
	if by == s {
		answer = serverResponse(s.s2c, req, &r)
		s.last = answer
		w.answers = append(w.answers, answer)
	} else {
		// A cookie this server did not issue (another server's, handed
		// over by a key exchange, or a changed one): the server does not
		// know it and says so, never authenticated (RFC 8915 section 5.7).
		answer = kod("NTSN", false)
		s.last = nil
	}
	// What the wire delivers, in order.
	queue := func(tag string, p ...[]byte) {
		for _, x := range p {
			c.queue = append(c.queue, x)
			c.tags = append(c.tags, tag)
		}
	}
	switch {
	case w.drop > 0:
		w.drop--
		queue("nothing", nil)
		return nil
	case w.kiss != "":
		queue("kod-authentic", kod(w.kiss, true))
		return nil
	case w.plainKiss != "":
		queue("kod-plain", kod(w.plainKiss, false))
		return nil
	case w.kissThenAnswer != "":
		queue("kod-authentic", kod(w.kissThenAnswer, true))
		queue("answer", answer)
		return nil
	}
	for n := 1 + w.d.pick(4); n > 0; n-- {
		switch w.d.pick(14) {
		case 0, 1, 2:
			queue("answer", answer)
		case 3:
			queue("answer+trailing", append(append([]byte(nil), answer...), w.rng.bytes(1+w.d.pick(40))...))
		case 4:
			queue("mutated", w.mutated(answer))
		case 5:
			queue("garbage", w.garbage())
		case 6:
			if len(w.answers) > 0 {
				queue("replay", w.answers[w.d.pick(len(w.answers))])
			}
		case 7:
			queue("kod-plain", kod([]string{"RATE", "DENY", "RSTR", "NTSN", "STEP"}[w.d.pick(5)], false))
		case 8:
			queue("kod-authentic", kod([]string{"RATE", "DENY", "RSTR"}[w.d.pick(3)], true))
		case 9:
			// A forged answer first, then the real one.
			f := append([]byte(nil), answer...)
			f[len(f)-1] ^= 1
			queue("forged-then-real", f, answer)
		case 10:
			// The answer of another server to this request's twin: wrong keys.
			o := w.servers[w.d.pick(len(w.servers))]
			if o == s {
				o = &hostileServer{s2c: w.rng.bytes(32)}
			}
			queue("other-keys", serverResponse(o.s2c, req, &r))
		case 11:
			queue("nothing", nil)
		default:
			queue("answer", answer)
		}
	}
	return nil
}

// sendPlain is Send under plain NTP: the request must be the bare header
// with a transmit timestamp never used before. The honest answer is the
// server's header to it; the tests of client_test.go get that (or what
// their knobs say), the fuzzer also forges: the world sees the transmit
// timestamp, so it can answer with any time, any kiss, anything.
func (c *hostileConn) sendPlain(p []byte) error {
	w := c.w
	s := w.server(c.peer)
	if len(p) != PlainRequestLen || p[0] != 0x23 || !allZero(p[1:40]) {
		w.fail("peer %d: a plain request that is not the bare header: %x", c.peer, p)
		return nil
	}
	var transmit [8]byte
	copy(transmit[:], p[40:])
	if w.transmits[transmit] {
		w.fail("peer %d: a transmit timestamp used twice", c.peer)
	}
	if w.transmits == nil {
		w.transmits = map[[8]byte]bool{}
	}
	w.transmits[transmit] = true
	w.advance()
	recv := w.trueNow() + s.offset
	hold := int64(w.d.pick(5)) * int64(time.Millisecond)
	w.now += hold
	reply := func(at int64) []byte {
		r := goodReply()
		r.stratum, r.precision = uint8(1+w.d.pick(15)), int8(-20+w.d.pick(12))
		r.rootDelay, r.rootDispersion = uint32(w.d.pick(600)), uint32(w.d.pick(600))
		if w.rootDispersion != 0 {
			r.rootDispersion = w.rootDispersion
		}
		r.reference = uint64(NTPFromUnixNanos(at - 16*int64(time.Second)))
		r.receive, r.transmit = uint64(NTPFromUnixNanos(at)), uint64(NTPFromUnixNanos(at+hold))
		return replyHeader(&r, transmit)
	}
	kod := func(code string) []byte {
		k := goodReply()
		k.leap, k.stratum = 3, 0
		copy(k.referenceID[:], code)
		return replyHeader(&k, transmit)
	}
	if w.sendFail {
		return errors.New("ntp: write: the host says it failed")
	}
	if err := w.cancelled(3); err != nil {
		return err
	}
	if w.rawCode[3] != 0 {
		return rawHostCode(w.rawCode[3])
	}
	answer := reply(recv)
	queue := func(tag string, p ...[]byte) {
		for _, x := range p {
			c.queue = append(c.queue, x)
			c.tags = append(c.tags, tag)
		}
	}
	switch {
	case w.drop > 0:
		w.drop--
		queue("nothing", nil)
		return nil
	case w.kiss != "":
		queue("kod-plain", kod(w.kiss))
		return nil
	case w.kissThenAnswer != "":
		queue("kod-plain", kod(w.kissThenAnswer))
		queue("answer", answer)
		return nil
	case !w.forge:
		queue("answer", answer)
		return nil
	}
	for n := 1 + w.d.pick(4); n > 0; n-- {
		switch w.d.pick(12) {
		case 0, 1, 2:
			queue("answer", answer)
		case 3:
			queue("answer+trailing", append(append([]byte(nil), answer...), w.rng.bytes(1+w.d.pick(40))...))
		case 4:
			queue("mutated", w.mutated(answer))
		case 5:
			queue("garbage", w.garbage())
		case 6:
			// A forged time near the truth: seconds off.
			queue("forged-near", reply(recv+(int64(w.d.next())-128)*int64(time.Second)))
		case 7:
			// A forged time anywhere: days to decades off, either way.
			queue("forged-far", reply(recv+(int64(w.d.next())-128)*int64(24*time.Hour)*int64(1+w.d.pick(200))))
		case 8:
			// A forged time that names the coarse reading the world gave,
			// an NTP era off when that is.
			queue("forged-coarse", reply(w.coarse+(w.now-w.coarseLocal)))
		case 9:
			queue("kod-plain", kod([]string{"RATE", "DENY", "RSTR", "NTSN", "NTS\x00", "STEP"}[w.d.pick(6)]))
		case 10:
			queue("nothing", nil)
		default:
			queue("answer", answer)
		}
	}
	return nil
}

func (c *hostileConn) Recv(buf []byte, wait time.Duration) (int, error) {
	w := c.w
	if err := w.cancelled(4); err != nil {
		return 0, err
	}
	if w.rawCode[4] != 0 {
		return 0, rawHostCode(w.rawCode[4])
	}
	// The answer takes a while; sometimes longer than the core will wait.
	w.now += int64(time.Millisecond) * int64(1+w.d.pick(40))
	if w.d.pick(12) == 11 {
		w.now += int64(wait) + 1
	}
	if len(c.queue) == 0 || c.queue[0] == nil {
		w.now += int64(wait)
		return 0, &net.OpError{Op: "read", Err: timeoutError{}}
	}
	p, tag := c.queue[0], c.tags[0]
	c.queue, c.tags = c.queue[1:], c.tags[1:]
	if w.d.pick(20) == 19 {
		return 0, errors.New("ntp: connection reset")
	}
	w.got = append(w.got, fmt.Sprintf("%s(%d)", tag, len(p)))
	if last := w.server(c.peer).last; w.live[c.peer] != nil && last != nil && len(p) >= len(last) && bytes.Equal(p[:len(last)], last) {
		w.honest[c.peer] = true
	}
	return copy(buf, p), nil
}

func (c *hostileConn) Close() {
	if c.w.onClose != nil {
		c.w.onClose()
	}
}

// silentConn is the socket of a world whose servers answer nothing.
type silentConn struct{ w *hostileWorld }

func (c silentConn) Send([]byte) error { return nil }

func (c silentConn) Recv(_ []byte, wait time.Duration) (int, error) {
	c.w.now += int64(wait)
	return 0, &net.OpError{Op: "read", Err: timeoutError{}}
}

func (c silentConn) Close() {
	if c.w.onClose != nil {
		c.w.onClose()
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// The limits of the hostile runs. The sample age limit is under 4
// intervals of the clock, as before the core's own cap of 4 intervals
// went away.
const (
	hostileInterval   = 2 * time.Second
	hostileMaxAge     = 5 * time.Second
	hostileCoarseDiff = 30 * time.Second
	hostileCoarseRes  = time.Second
	// What the run does beyond the hostile untrusted operations, from the
	// first decision octet; zero is none of it.
	hostilePlain  = 1 << 0 // the core starts on plain NTP
	hostileCancel = 1 << 1 // host operations report a cancel by the caller at random
	hostileEra    = 1 << 2 // coarse readings 2^32 s off at random
	hostileConfig = 1 << 3 // SetServers and SetPolicy between rounds
)

var hostileFloor = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

// hostileRun is one run: the world, the core, and what the oracles track.
type hostileRun struct {
	t        testing.TB
	w        *hostileWorld
	core     *Core
	d        *decisions
	flags    int
	liars    map[*hostileServer]bool
	capacity int
	maxBound time.Duration
	coffs    []int64 // every coarse reading given to a combine or a configuration call, as Unix ns minus monotonic ns
	highest  int64
}

func (r *hostileRun) servers() []Server {
	var out []Server
	for _, s := range r.w.list {
		out = append(out, Server{Operator: s.op, Host: s.host, NTPAddr: s.ntpAddr, Roots: []byte("-----BEGIN CERTIFICATE-----\n")})
	}
	return out
}

// sameClient says what differs between two snapshots of the client, ""
// for nothing: what an illegal configuration call must leave. The fields
// that follow the clock are left out.
func sameClient(a, b Status) string {
	switch {
	case a.HaveResult != b.HaveResult || a.Offset != b.Offset || a.At != b.At || a.Bound != b.Bound || a.Sampled != b.Sampled:
		return "the result"
	case fmt.Sprint(a.Members) != fmt.Sprint(b.Members) || a.Protocol != b.Protocol || a.Cold != b.Cold || a.EraPivot != b.EraPivot || len(a.Peers) != len(b.Peers):
		return "the members, the protocol, the start state, the pivot or the list"
	case a.HaveDrift != b.HaveDrift || a.DriftDT != b.DriftDT || a.Violations != b.Violations:
		return "the drift history"
	}
	for i := range a.Peers {
		x, y := a.Peers[i], b.Peers[i]
		if x.Cookies != y.Cookies || x.NextPoll != y.NextPoll || x.NextKE != y.NextKE || (x.Sample == nil) != (y.Sample == nil) || x.Poll != y.Poll ||
			x.Disabled != y.Disabled || x.LostInRow != y.LostInRow || x.NTPAddr != y.NTPAddr || x.Stats.KEOK != y.Stats.KEOK {
			return fmt.Sprintf("peer %d", i)
		}
	}
	return ""
}

func indexOfServer(l []*hostileServer, s *hostileServer) int {
	for i, x := range l {
		if x == s {
			return i
		}
	}
	return -1
}

// setServers is one SetServers by the trusted configuration side: a
// sublist or a permutation of the servers, some under a new host name
// (then a new peer to the core), or an illegal list.
func (r *hostileRun) setServers(round int, coarse time.Time, coarseLocal int64) {
	t, w, d := r.t, r.w, r.d
	before := r.core.Status()
	if before.Busy {
		t.Fatalf("round %d: busy between polls", round)
	}
	old := append([]*hostileServer(nil), w.list...)
	// The new list: each server of the world in or out, then rotated.
	var list []*hostileServer
	for _, s := range w.servers {
		if d.pick(4) != 3 {
			list = append(list, s)
		}
	}
	if k := d.pick(4); k < len(list) {
		list = append(list[k:], list[:k]...)
	}
	hosts := map[*hostileServer]string{}
	for _, s := range list {
		hosts[s] = s.host
		if d.pick(8) == 7 {
			hosts[s] = fmt.Sprintf("nts-%s-%d.test", s.op, d.pick(3))
		}
	}
	var servers []Server
	for _, s := range list {
		servers = append(servers, Server{Operator: s.op, Host: hosts[s], NTPAddr: s.ntpAddr, Roots: []byte("-----BEGIN CERTIFICATE-----\n")})
	}
	illegal := ""
	switch d.pick(12) {
	case 8:
		if len(servers) > 0 {
			illegal = "an operator named twice"
			servers = append(servers, Server{Operator: servers[0].Operator, Host: "other.test"})
		}
	case 9:
		if len(servers) > 0 {
			illegal = "a host named twice"
			servers = append(servers, Server{Operator: "twin", Host: servers[0].Host})
		}
	case 10:
		illegal = "more servers than the capacity"
		for i := 0; len(servers) <= r.capacity; i++ {
			servers = append(servers, Server{Operator: fmt.Sprintf("extra%d", i), Host: fmt.Sprintf("extra%d.test", i)})
		}
	case 11:
		if len(servers) > 1 {
			illegal = "an NTP address named twice"
			servers[0].NTPAddr, servers[1].NTPAddr = "192.0.2.9:123", "192.0.2.9:123"
		}
	}
	r.coffs = append(r.coffs, coarse.UnixNano()-coarseLocal)
	err := r.core.SetServers(servers, coarse, coarseLocal)
	after := r.core.Status()
	if illegal != "" {
		if !errors.Is(err, ErrBadConfig) {
			t.Fatalf("round %d: SetServers with %s: %v", round, illegal, err)
		}
		if what := sameClient(before, after); what != "" {
			t.Fatalf("round %d: SetServers with %s was refused and changed %s", round, illegal, what)
		}
		return
	}
	if err != nil {
		t.Fatalf("round %d: SetServers(%d servers): %v", round, len(servers), err)
	}
	// A server that is as before keeps its peer; the others are new peers,
	// to the world as well: what their key exchanges named is forgotten.
	kept := map[*hostileServer]bool{}
	named, dialed := map[int]string{}, map[int]string{}
	for i, s := range list {
		if j := indexOfServer(old, s); j >= 0 && s.host == hosts[s] {
			kept[s] = true
			if a, ok := w.named[j]; ok {
				named[i] = a
			}
			if a, ok := w.dialed[j]; ok {
				dialed[i] = a
			}
		}
	}
	for _, s := range list {
		s.host = hosts[s]
	}
	w.list, w.named, w.dialed = list, named, dialed
	w.live, w.honest = map[int]*clientRequest{}, map[int]bool{}
	if len(after.Peers) != len(list) {
		t.Fatalf("round %d: %d peers after SetServers(%d servers)", round, len(after.Peers), len(list))
	}
	// A quorum in force after the call has no member that left, and if a
	// member of the earlier one left it is a new quorum, formed in the call.
	left := false
	for _, m := range before.Members {
		if !kept[old[m]] {
			left = true
		}
	}
	for i, s := range list {
		ps := after.Peers[i]
		if !kept[s] && (ps.Sample != nil || ps.Cookies != 0 || ps.Stats.Queries != 0) {
			t.Fatalf("round %d: the new peer %d (%s) has state: %+v", round, i, s.op, ps)
		}
		if j := indexOfServer(old, s); kept[s] && (ps.Cookies != before.Peers[j].Cookies || (ps.Sample == nil) != (before.Peers[j].Sample == nil) || ps.Stats.Queries != before.Peers[j].Stats.Queries) {
			t.Fatalf("round %d: the kept peer %d (%s) lost state: %+v, was %+v", round, i, s.op, ps, before.Peers[j])
		}
	}
	switch {
	case after.HaveResult:
		for _, m := range after.Members {
			// (A member may have lost its sample since the quorum formed, to
			// a DENY say; it is a kept peer all the same.)
			if !kept[list[m]] {
				t.Fatalf("round %d: member %d (%s) of the quorum after SetServers is a new peer", round, m, list[m].op)
			}
		}
		if left && (!before.HaveResult || after.At <= before.At) {
			t.Fatalf("round %d: a member left and the quorum of %d is still in force (now formed at %d)", round, before.At, after.At)
		}
		if !left && (!before.HaveResult || after.At != before.At || after.Offset != before.Offset) {
			t.Fatalf("round %d: no member left and the quorum changed", round)
		}
	case before.HaveResult && !left:
		t.Fatalf("round %d: no member left and the quorum is gone", round)
	}
}

// setPolicy is one SetPolicy by the trusted configuration side, with
// legal and illegal values.
func (r *hostileRun) setPolicy(round int, coarse time.Time, coarseLocal int64) {
	t, w, d := r.t, r.w, r.d
	before := r.core.Status()
	proto := []Protocol{ProtocolNTS, ProtocolNTS, ProtocolNTP, Protocol(2), Protocol(-1)}[d.pick(5)]
	if d.pick(2) == 1 {
		proto = before.Protocol
	}
	maxBound := []time.Duration{100 * time.Millisecond, 50 * time.Millisecond, 20 * time.Millisecond, 0, -1}[d.pick(5)]
	sampleBound := []time.Duration{100 * time.Millisecond, 100 * time.Millisecond, 60 * time.Millisecond, 80 * time.Millisecond, 2 * time.Second, 10 * time.Millisecond}[d.pick(6)]
	legal := (proto == ProtocolNTS || (proto == ProtocolNTP && PlainSupported())) && maxBound > 0 && sampleBound >= maxBound && sampleBound <= MaxSampleBound
	r.coffs = append(r.coffs, coarse.UnixNano()-coarseLocal)
	err := r.core.SetPolicy(proto, maxBound, sampleBound, coarse, coarseLocal)
	after := r.core.Status()
	if !legal {
		if !errors.Is(err, ErrBadConfig) {
			t.Fatalf("round %d: SetPolicy(%v, %v, %v): %v", round, proto, maxBound, sampleBound, err)
		}
		if what := sameClient(before, after); what != "" {
			t.Fatalf("round %d: SetPolicy(%v, %v, %v) was refused and changed %s", round, proto, maxBound, sampleBound, what)
		}
		return
	}
	if err != nil {
		t.Fatalf("round %d: SetPolicy(%v, %v, %v): %v", round, proto, maxBound, sampleBound, err)
	}
	r.maxBound = maxBound
	w.plain = proto == ProtocolNTP
	if after.Protocol != proto {
		t.Fatalf("round %d: protocol %v after SetPolicy(%v)", round, after.Protocol, proto)
	}
	if proto != before.Protocol {
		// The core starts over: nothing of the other protocol is left.
		if after.HaveResult || after.HaveDrift {
			t.Fatalf("round %d: a quorum or a drift reading across the change of protocol: %+v", round, after)
		}
		for i, ps := range after.Peers {
			if ps.Sample != nil || ps.Cookies != 0 {
				t.Fatalf("round %d: peer %d keeps a sample or cookies across the change of protocol: %+v", round, i, ps)
			}
		}
		w.named, w.dialed = map[int]string{}, map[int]string{}
		w.live, w.honest = map[int]*clientRequest{}, map[int]bool{}
	}
}

// runHostile is one run of the harness on a decision stream.
func runHostile(t testing.TB, data []byte) (served int) {
	t.Helper()
	d := &decisions{data: data}
	w := &hostileWorld{t: t, d: d, rng: testRng(0x484f5354 + uint64(len(data))), live: map[int]*clientRequest{}, honest: map[int]bool{},
		uids: map[[UniqueIDLen]byte]bool{}, issued: map[string]*hostileServer{}, named: map[int]string{}, dialed: map[int]string{}, sent: map[string]bool{},
		forge: true}
	r := &hostileRun{t: t, w: w, d: d, maxBound: 100 * time.Millisecond, liars: map[*hostileServer]bool{}}
	r.flags = int(d.next())
	if !PlainSupported() {
		r.flags &^= hostilePlain
	}
	w.plain, w.cancelFuzz = r.flags&hostilePlain != 0, r.flags&hostileCancel != 0
	// True time: late 2026 and up to two years on; the virtual clock starts
	// anywhere.
	w.now = int64(d.pick(200)) * int64(time.Hour)
	w.trueOffset = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC).UnixNano() + int64(d.pick(730))*int64(24*time.Hour) - w.now
	// Up to QuorumWrong of the servers lie, each with its own lie or all
	// with one (colluding); their answers are authentic.
	n := 3 + d.pick(4)
	nliars := d.pick(QuorumWrong(n) + 1)
	collude := d.pick(2) == 1
	var lie int64
	for i := 0; i < n; i++ {
		s := &hostileServer{op: string(rune('a' + i)), c2s: w.rng.bytes(32), s2c: w.rng.bytes(32)}
		s.host = fmt.Sprintf("nts-%s.test", s.op)
		if i%2 == 1 {
			s.ntpAddr = fmt.Sprintf("ntp-%s.test:1123", s.op)
		}
		if i < nliars {
			if i == 0 || !collude {
				lie = (int64(d.next()) - 128) * int64(time.Second) * int64(1+d.pick(1000))
				if d.pick(4) == 3 {
					lie = (int64(d.next()) - 128) * int64(time.Millisecond) // a lie within the bounds' reach
				}
			}
			s.offset = lie
			r.liars[s] = s.offset != 0
		}
		w.servers = append(w.servers, s)
	}
	w.list = append([]*hostileServer(nil), w.servers...)
	r.capacity = n
	cfg := Config{
		Servers: r.servers(), Interval: hostileInterval, MinPoll: time.Second, MaxPoll: 64 * time.Second, MaxBound: r.maxBound, MaxAge: hostileMaxAge,
		MaxCoarseDiff: hostileCoarseDiff, CoarseResolution: hostileCoarseRes, ExchangeTimeout: time.Second, KissGrace: 100 * time.Millisecond,
		DriftBaselinePolls: 4, FloorUnix: hostileFloor, StartWait: 10 * time.Second,
	}
	if w.plain {
		cfg.Protocol = ProtocolNTP
	}
	core, err := New(cfg, w)
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	w.core, r.core = core, core
	for round := 0; round < 40 && !d.done(); round++ {
		w.advance()
		// The host's coarse time: true time, a little off, sometimes a lot,
		// and sometimes a whole NTP era (2^32 s) off.
		coarseErr := int64(d.pick(25))*int64(time.Second) - 12*int64(time.Second)
		if d.pick(8) == 7 {
			coarseErr = (int64(d.next()) - 128) * int64(time.Hour)
		}
		if r.flags&hostileEra != 0 && d.pick(4) == 3 {
			coarseErr += (int64(d.pick(2))*2 - 1) << 32 * int64(time.Second)
		}
		coarseLocal := w.now
		coarse := time.Unix(0, w.trueNow()+coarseErr)
		w.coarse, w.coarseLocal = coarse.UnixNano(), coarseLocal
		if r.flags&hostileConfig != 0 {
			switch d.pick(8) {
			case 6:
				r.setServers(round, coarse, coarseLocal)
			case 7:
				r.setPolicy(round, coarse, coarseLocal)
			}
			if w.failed != nil {
				t.Fatalf("round %d: %v", round, w.failed)
			}
		}
		for _, i := range core.Due(w.now) {
			s := w.server(i)
			w.live[i], w.honest[i], w.got = nil, false, nil
			was := core.Peer(i)
			kes := w.kes
			ps, err := core.Poll(i, coarse, coarseLocal)
			if w.failed != nil {
				t.Fatalf("round %d peer %d: %v", round, i, w.failed)
			}
			if ps.Cookies > MaxCookies || ps.Cookies < 0 || (w.plain && (ps.Cookies != 0 || w.kes != kes)) {
				t.Fatalf("round %d peer %d: %d cookies, %d key exchanges", round, i, ps.Cookies, w.kes-kes)
			}
			if errors.Is(err, ErrHostCancelled) {
				// A cancel by the caller is no loss: no error counted, no
				// streak, no backoff (a key exchange that failed before the
				// cancelled query has its own), and the peer stays due.
				if !w.cancelFuzz {
					t.Fatalf("round %d peer %d: cancelled, and the host cancelled nothing", round, i)
				}
				if ps.Stats.Errors != was.Stats.Errors || ps.LostInRow != was.LostInRow || ps.NextPoll != was.NextPoll || ps.Stats.Samples != was.Stats.Samples ||
					(ps.Stats.Queries == was.Stats.Queries && (ps.Stats.KEFail != was.Stats.KEFail || ps.NextKE != was.NextKE)) {
					t.Fatalf("round %d peer %d: a cancelled exchange cost something: %+v, was %+v", round, i, ps, was)
				}
				continue
			}
			if err == nil {
				if ps.Sample == nil {
					t.Fatalf("round %d peer %d: no error and no sample", round, i)
				}
				if ps.Sample.Bound > 100*time.Millisecond {
					t.Fatalf("round %d peer %d: a sample with bound %v", round, i, ps.Sample.Bound)
				}
				if w.plain {
					continue
				}
				if !w.honest[i] {
					t.Fatalf("round %d peer %d: a sample without the honest answer delivered: %+v; given %v", round, i, ps.Sample, w.got)
				}
				// The sample measures the server's clock: true time plus the
				// server's error, within the bound.
				want := w.trueOffset + s.offset
				if diff := ps.Sample.Offset - want; diff > int64(ps.Sample.Bound) || -diff > int64(ps.Sample.Bound) {
					t.Fatalf("round %d peer %d: offset %d, the server's %d, bound %v", round, i, ps.Sample.Offset, want, ps.Sample.Bound)
				}
				continue
			}
			var e *Error
			if !errors.As(err, &e) {
				t.Fatalf("round %d peer %d: not a core error: %v", round, i, err)
			}
		}
		r.coffs = append(r.coffs, coarse.UnixNano()-coarseLocal)
		cerr := core.Combine(coarse, coarseLocal)
		st := core.Status()
		if cerr == nil && (len(st.Members) < MinServers || st.MaxWrong != QuorumWrong(st.LastFresh) || len(st.Members) != st.LastFresh) {
			t.Fatalf("round %d: a quorum of %d, %d allowed wrong, of %d fresh samples", round, len(st.Members), st.MaxWrong, st.LastFresh)
		}
		w.advance()
		tm, bound, berr := core.Bounded()
		if berr != nil {
			continue
		}
		served++
		if tm.UnixNano() < r.highest {
			t.Fatalf("round %d: the time went back from %d to %d", round, r.highest, tm.UnixNano())
		}
		was := r.highest
		r.highest = tm.UnixNano()
		if bound < 0 || bound > r.maxBound {
			t.Fatalf("round %d: served with bound %v", round, bound)
		}
		// The quorum's oldest sample is within the age limit. The snapshot
		// reads the virtual clock again, which moves a nanosecond a read.
		st = core.Status()
		if st.Refusal != nil || st.SampleAge < 0 || st.SampleAge > hostileMaxAge || st.BoundNow < bound || st.BoundNow > bound+time.Microsecond {
			t.Fatalf("round %d: served, but the snapshot says refusal %v, sample age %v, bound %v (served %v)", round, st.Refusal, st.SampleAge, st.BoundNow, bound)
		}
		if (st.Protocol == ProtocolNTP) != w.plain {
			t.Fatalf("round %d: the status says %v, the world runs plain NTP: %v", round, st.Protocol, w.plain)
		}
		// The time served is the quorum's (raw), or the highest served
		// before if that is later: it never goes back.
		raw := st.Now + st.Offset
		if got := tm.UnixNano(); got != was && (got > raw || got < raw-int64(time.Millisecond)) {
			t.Fatalf("round %d: served %d, the quorum reads %d and the highest before was %d", round, got, raw, was)
		}
		// Nothing before the floor, and nothing of another NTP era: within
		// 2^31 s of the true time, whatever the coarse readings said.
		if tm.Before(hostileFloor) || raw < hostileFloor.UnixNano() {
			t.Fatalf("round %d: served %v, before the floor", round, tm)
		}
		if diff := raw - w.trueNow(); diff > int64(1)<<31*int64(time.Second) || -diff > int64(1)<<31*int64(time.Second) {
			t.Fatalf("round %d: served %v, true %v: another era", round, time.Unix(0, raw), time.Unix(0, w.trueNow()))
		}
		// The quorum passed the coarse check against a coarse reading the
		// world gave: under plain NTP that is all that holds.
		near := false
		for _, coff := range r.coffs {
			if diff := st.Offset - coff; diff >= -int64(hostileCoarseDiff) && diff < int64(hostileCoarseDiff+hostileCoarseRes) {
				near = true
			}
		}
		if !near {
			t.Fatalf("round %d: served offset %d, not within the coarse check of any coarse reading given", round, st.Offset)
		}
		if w.plain {
			continue
		}
		// Under NTS: while no more members lie than the quorum allowed
		// wrong, the true time is within the bound. With more (a liar among
		// three, or honest samples missing), at least three members cover
		// every point of the result and one of them is honest, so the result
		// is within that sample's bound of the truth: never further than the
		// bound and a sample's cap.
		lying := 0
		for _, m := range st.Members {
			if r.liars[w.list[m]] {
				lying++
			}
		}
		slack := int64(0)
		if lying > st.MaxWrong {
			slack = int64(100 * time.Millisecond)
		}
		if diff := raw - w.trueNow(); diff > int64(bound)+slack || -diff > int64(bound)+slack {
			t.Fatalf("round %d: served %v, true %v, bound %v (%d of %d members lie, %d allowed wrong)", round, time.Unix(0, raw), time.Unix(0, w.trueNow()), bound, lying, len(st.Members), st.MaxWrong)
		}
	}
	if testing.Verbose() && served > 0 {
		t.Logf("flags %#x: %d servers (%d lie), %d rounds served a time", r.flags, n, nliars, served)
	}
	return served
}

func TestHostileHostRounds(t *testing.T) {
	rounds := 300
	if testing.Short() {
		rounds = 40
	}
	rng := testRng(0x686f7374696c65)
	served := map[int]int{}
	for i := 0; i < rounds; i++ {
		data := rng.bytes(rng.below(2000))
		if len(data) > 0 {
			// Every mix of what a run does beyond the untrusted operations.
			data[0] = byte(i % 16)
		}
		t.Run(fmt.Sprintf("seed-%d", i), func(t *testing.T) {
			n := runHostile(t, data)
			if len(data) > 0 {
				served[int(data[0])] += n
			}
		})
	}
	t.Logf("rounds that served a time, by what the run did: %v", served)
	// All honest: the quorum forms and a time is served, with and without
	// the other things a run does (their decisions exhausted, they are
	// honest too).
	for flags := 0; flags < 16; flags++ {
		if flags&hostilePlain != 0 && !PlainSupported() {
			continue
		}
		if runHostile(t, []byte{byte(flags)}) == 0 {
			t.Fatalf("flags %#x: no time served with every operation honest", flags)
		}
	}
	if runHostile(t, nil) == 0 {
		t.Fatal("no time served with every operation honest")
	}
}

func FuzzHostileHost(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	rng := testRng(0x66757a7a)
	for i := 0; i < 8; i++ {
		f.Add(rng.bytes(200 + i*100))
	}
	// Plain NTP worlds, cancels by the caller, coarse readings an era off,
	// the configuration calls, and all of it at once.
	for _, flags := range []byte{hostilePlain, hostileCancel, hostileEra, hostileConfig, hostilePlain | hostileConfig, 15} {
		for i := 0; i < 3; i++ {
			seed := rng.bytes(300 + i*300)
			seed[0] = flags
			f.Add(seed)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzcheck.Watch(t)
		runHostile(t, data)
	})
}
