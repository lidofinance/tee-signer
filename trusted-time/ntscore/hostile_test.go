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
//     cookie the key exchange or an authentic answer issued, and a Unique
//     Identifier never used before;
//   - the jar never holds more than MaxCookies cookies;
//   - a time is served only from a quorum of at least MinServers operators
//     with fresh samples, and with at most one server lying it is within
//     its bound of the true time; it never goes back; its bound ages;
//   - the key exchange request is the one the RFC asks for, and the NTP
//     address is the one the key exchange named;
//   - nothing crashes (the sanitizer run of scripts/test-modules.sh).
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
	op     string
	c2s    []byte
	s2c    []byte
	offset int64  // the server's clock minus true time
	last   []byte // the last answer, for replays
}

// cookie is a fresh cookie of s, remembered as its.
func (w *hostileWorld) cookie(s *hostileServer) []byte {
	c := w.rng.bytes(100)
	w.issued[hex.EncodeToString(c)] = s
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
	got         []string                  // what the poll under way was given, for the failure message
	coarse      int64                     // the coarse time the host gave, at the monotonic time coarseLocal
	coarseLocal int64
	failed      error
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
	copy(buf, w.rng.bytes(len(buf)))
	return nil
}

func (w *hostileWorld) Monotonic() int64 {
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
	s := w.servers[peer]
	if !bytes.Equal(req, KERequest()) {
		w.fail("peer %d: NTS-KE request %x", peer, req)
	}
	if srv.Operator != s.op {
		w.fail("peer %d: the core named operator %q", peer, srv.Operator)
	}
	// The certificate is dated by the coarse time the host gave, moved
	// forward, before the first quorum; by the core's own time after it.
	fromCoarse := validity.UnixNano() - (w.coarse + (w.now - w.coarseLocal))
	fromTrue := validity.UnixNano() - w.trueNow()
	if (fromCoarse > int64(time.Second) || -fromCoarse > int64(time.Second)) && (fromTrue > int64(time.Second) || -fromTrue > int64(time.Second)) {
		w.fail("peer %d: certificate validity %v, true time %v, coarse %v", peer, validity, time.Unix(0, w.trueNow()), time.Unix(0, w.coarse))
	}
	w.advance()
	honest := func(from *hostileServer, n int) []byte {
		var cookies [][]byte
		for i := 0; i < n; i++ {
			cookies = append(cookies, w.cookie(from))
		}
		records := goodKERecords(cookies)
		records = append(records, keRec(true, RecServer, []byte(fmt.Sprintf("ntp-%s.test", s.op))), keRec(false, RecPort, []byte{0x04, 0xd2}))
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
	return n, append([]byte(nil), s.c2s...), append([]byte(nil), s.s2c...), time.Duration(w.d.pick(900)) * time.Millisecond, nil
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
	if want, ok := w.named[peer]; !ok || addr != want {
		w.fail("peer %d: dialed %q, the key exchange named %q", peer, addr, want)
	}
	if w.d.pick(10) == 9 {
		return nil, errors.New("ntp: no route")
	}
	return &hostileConn{w: w, peer: peer}, nil
}

// Send reads the request as a server would, checks it, and queues the
// answers the fuzzer wants delivered.
func (c *hostileConn) Send(p []byte) error {
	w := c.w
	s := w.servers[c.peer]
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
			o := w.servers[(c.peer+1+w.d.pick(len(w.servers)-1))%len(w.servers)]
			queue("other-keys", serverResponse(o.s2c, req, &r))
		case 11:
			queue("nothing", nil)
		default:
			queue("answer", answer)
		}
	}
	return nil
}

func (c *hostileConn) Recv(buf []byte, wait time.Duration) (int, error) {
	w := c.w
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
	if last := w.servers[c.peer].last; w.live[c.peer] != nil && last != nil && len(p) >= len(last) && bytes.Equal(p[:len(last)], last) {
		w.honest[c.peer] = true
	}
	return copy(buf, p), nil
}

func (c *hostileConn) Close() {}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// runHostile is one run of the harness on a decision stream.
func runHostile(t testing.TB, data []byte) (served int) {
	t.Helper()
	d := &decisions{data: data}
	w := &hostileWorld{t: t, d: d, rng: testRng(0x484f5354 + uint64(len(data))), live: map[int]*clientRequest{}, honest: map[int]bool{},
		uids: map[[UniqueIDLen]byte]bool{}, issued: map[string]*hostileServer{}, named: map[int]string{}}
	// True time: late 2026 and up to two years on; the virtual clock starts
	// anywhere.
	w.now = int64(d.pick(200)) * int64(time.Hour)
	w.trueOffset = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC).UnixNano() + int64(d.pick(730))*int64(24*time.Hour) - w.now
	n := 3 + d.pick(3)
	liar := d.pick(n + 1) // n: no liar
	var servers []Server
	for i := 0; i < n; i++ {
		s := &hostileServer{op: string(rune('a' + i)), c2s: w.rng.bytes(32), s2c: w.rng.bytes(32)}
		if i == liar {
			s.offset = (int64(d.next()) - 128) * int64(time.Second) * int64(1+d.pick(1000))
		}
		w.servers = append(w.servers, s)
		servers = append(servers, Server{Operator: s.op, Host: fmt.Sprintf("nts-%s.test", s.op), Roots: []byte("-----BEGIN CERTIFICATE-----\n")})
	}
	const interval = 2 * time.Second
	core, err := New(Config{
		Servers: servers, Interval: interval, MinPoll: time.Second, MaxPoll: 64 * time.Second, MaxBound: 100 * time.Millisecond,
		MaxCoarseDiff: 30 * time.Second, CoarseResolution: time.Second, ExchangeTimeout: time.Second, KissGrace: 100 * time.Millisecond,
		DriftBaselinePolls: 4, FloorUnix: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
	}, w)
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	var highest int64
	for round := 0; round < 40 && !d.done(); round++ {
		w.advance()
		// The host's coarse time: true time, a little off, sometimes a lot.
		coarseErr := int64(d.pick(25))*int64(time.Second) - 12*int64(time.Second)
		if d.pick(8) == 7 {
			coarseErr = (int64(d.next()) - 128) * int64(time.Hour)
		}
		coarseLocal := w.now
		coarse := time.Unix(0, w.trueNow()+coarseErr)
		w.coarse, w.coarseLocal = coarse.UnixNano(), coarseLocal
		for _, i := range core.Due(w.now) {
			s := w.servers[i]
			w.live[i], w.honest[i], w.got = nil, false, nil
			ps, err := core.Poll(i, coarse, coarseLocal)
			if w.failed != nil {
				t.Fatalf("round %d peer %d: %v", round, i, w.failed)
			}
			if ps.Cookies > MaxCookies || ps.Cookies < 0 {
				t.Fatalf("round %d peer %d: %d cookies", round, i, ps.Cookies)
			}
			if err == nil {
				if ps.Sample == nil {
					t.Fatalf("round %d peer %d: no error and no sample", round, i)
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
		cerr := core.Combine(coarse, coarseLocal)
		st := core.Summary()
		if cerr == nil && len(st.Members) < MinServers {
			t.Fatalf("round %d: a quorum of %d", round, len(st.Members))
		}
		w.advance()
		tm, bound, berr := core.Bounded()
		if berr != nil {
			continue
		}
		served++
		if tm.UnixNano() < highest {
			t.Fatalf("round %d: the time went back from %d to %d", round, highest, tm.UnixNano())
		}
		highest = tm.UnixNano()
		if bound < 0 || bound > 100*time.Millisecond {
			t.Fatalf("round %d: served with bound %v", round, bound)
		}
		// With at most one liar the true time is within the bound. The time
		// never goes back, so a reading may sit at the highest earlier one,
		// which was within its own bound (at most MaxBound) of its true
		// time: ahead of true time by at most that, never behind by more
		// than the bound.
		if diff := tm.UnixNano() - w.trueNow(); diff > int64(max(bound, 100*time.Millisecond)) || -diff > int64(bound) {
			t.Fatalf("round %d: served %v, true %v, bound %v (liar %d of %d: %v)", round, tm, time.Unix(0, w.trueNow()), bound, liar, n, time.Duration(w.servers[min(liar, n-1)].offset))
		}
	}
	if testing.Verbose() && served > 0 {
		t.Logf("%d servers (liar %d), %d rounds served a time", n, liar, served)
	}
	return served
}

func TestHostileHostRounds(t *testing.T) {
	rounds := 300
	if testing.Short() {
		rounds = 40
	}
	rng := testRng(0x686f7374696c65)
	for i := 0; i < rounds; i++ {
		data := rng.bytes(rng.below(2000))
		t.Run(fmt.Sprintf("seed-%d", i), func(t *testing.T) { runHostile(t, data) })
	}
	// All honest: the quorum forms and a time is served.
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
	f.Fuzz(func(t *testing.T, data []byte) { runHostile(t, data) })
}
