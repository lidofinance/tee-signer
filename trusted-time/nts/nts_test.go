//go:build nts

package nts

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"github.com/lidofinance/tee-signer/devkit/fuzzcheck"
	"github.com/lidofinance/tee-signer/trusted-time/nts/ntstest"
	ntscore "github.com/lidofinance/tee-signer/trusted-time/ntscore/go"
)

func TestVersion(t *testing.T) {
	v := Version()
	if !strings.HasPrefix(v, "signer-nts c") {
		t.Fatalf("Version() = %q, want a string that starts with %q", v, "signer-nts c")
	}
	t.Log(v)
}

func TestAESSIVSelfTest(t *testing.T) {
	if err := AESSIVSelfTest(); err != nil {
		t.Fatal(err)
	}
}

// RUNNER_NTS_BIN is a runner built with -tags nts. RUNNER_WRAPPER, if set, is
// a program that runs it (qemu-aarch64 for an arm64 binary on an x86_64 host).
func TestRunnerBuiltWithTheTag(t *testing.T) {
	bin := os.Getenv("RUNNER_NTS_BIN")
	if bin == "" {
		t.Skip("RUNNER_NTS_BIN is not set")
	}
	args := []string{bin, "-nts-selftest"}
	if w := os.Getenv("RUNNER_WRAPPER"); w != "" {
		args = append([]string{w}, args...)
	}
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
	want := Version() + ": AES-SIV self-test ok"
	if got := strings.TrimSpace(string(out)); got != want {
		t.Fatalf("%v printed %q, want %q", args, got, want)
	}
}

func TestPinnedRoots(t *testing.T) {
	for _, s := range PublicServers {
		pem, err := RootsPEM(s.Roots)
		if err != nil || len(pem) == 0 || len(pem) > ntscore.MaxRootsLen {
			t.Fatalf("%s: %d octets, %v", s.Host, len(pem), err)
		}
	}
	if _, err := RootsPEM([]string{"other.pem"}); err == nil {
		t.Fatal("unpinned root accepted")
	}
}

// fixture is one loopback NTS-KE and NTP server pair, and the Server that
// names them.
type fixture struct {
	store *ntstest.Store
	ke    *ntstest.KEServer
	ntp   *ntstest.NTPServer
	srv   Server
}

// newFixture starts a KE server that names the NTP server's port.
func newFixture(t *testing.T, keOpts ntstest.KEOptions, ntpOpts ntstest.NTPOptions) *fixture {
	t.Helper()
	cert, ca, err := ntstest.CertificatePEM("nts.test", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{store: ntstest.NewStore()}
	if f.ntp, err = ntstest.StartNTP(f.store, ntpOpts); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.ntp.Close)
	keOpts.NTPServer, keOpts.NTPPort = "127.0.0.1", f.ntp.Port
	if f.ke, err = ntstest.StartKE(cert, f.store, keOpts); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.ke.Close)
	f.srv = Server{Operator: "a", Host: "nts.test", KEAddr: f.ke.Addr, Roots: ca}
	return f
}

// newClient is a client of the given servers. A query gets half the
// interval: 2 s here.
func newClient(t *testing.T, cfg Config, servers ...Server) *Client {
	t.Helper()
	cfg.Servers = servers
	if cfg.Interval == 0 {
		cfg.Interval = 4 * time.Second
	}
	cfg.MinPoll, cfg.MaxPoll, cfg.MaxBound = cmpOr(cfg.MinPoll, time.Second), cmpOr(cfg.MaxPoll, 1024*time.Second), cmpOr(cfg.MaxBound, 100*time.Millisecond)
	cfg.MaxAge = cmpOr(cfg.MaxAge, time.Minute)
	cfg.MaxCoarseDiff, cfg.CoarseResolution = cmpOr(cfg.MaxCoarseDiff, 30*time.Second), cmpOr(cfg.CoarseResolution, time.Second)
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func ctx(t *testing.T, d time.Duration) context.Context {
	c, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return c
}

// poll polls server 0 with the host clock as the coarse time.
func poll(t *testing.T, c *Client) (ntscore.PeerStatus, error) {
	t.Helper()
	return c.Poll(ctx(t, 10*time.Second), 0, time.Now(), c.Local())
}

// mustSample polls and fails unless a sample came back.
func mustSample(t *testing.T, c *Client) Sample {
	t.Helper()
	ps, err := poll(t, c)
	if err != nil || ps.Sample == nil {
		t.Fatalf("poll: %+v, %v", ps, err)
	}
	return *ps.Sample
}

func TestKeyExchangeAndQuery(t *testing.T) {
	f := newFixture(t, ntstest.KEOptions{}, ntstest.NTPOptions{RootDelay: 2 * time.Millisecond, RootDisp: time.Millisecond})
	c := newClient(t, Config{}, f.srv)
	for i := 0; i < 12; i++ {
		ps, err := poll(t, c)
		if err != nil || ps.Sample == nil {
			t.Fatalf("poll %d: %v", i, err)
		}
		if ps.NTPAddr != f.ntp.Addr || ps.Cookies != 8 || ps.Stats.KEOK != 1 {
			t.Fatalf("NTP addr %s (want %s), cookies %d, stats %+v", ps.NTPAddr, f.ntp.Addr, ps.Cookies, ps.Stats)
		}
		s := ps.Sample
		// The server's clock is this host's; the measured real time must be
		// within the bound of it.
		now := time.Now().UnixNano()
		est := s.Offset + Monotonic()
		if diff := time.Duration(est - now); diff.Abs() > s.Bound+5*time.Millisecond {
			t.Fatalf("estimate off by %v, bound %v", diff, s.Bound)
		}
		if s.Bound < s.RootDelay/2+s.RootDispersion || s.CookiesHeld != 8 || s.Stratum != 1 {
			t.Fatalf("sample %+v", s)
		}
		if i == 0 {
			t.Logf("sample %+v", s)
		}
	}
	if n := f.ke.Sessions.Load(); n != 1 {
		t.Fatalf("NTS-KE sessions after 12 queries: %d", n)
	}
}

func TestServerOffsetIsMeasured(t *testing.T) {
	f := newFixture(t, ntstest.KEOptions{}, ntstest.NTPOptions{Offset: 3 * time.Second, Hold: 2 * time.Millisecond})
	c := newClient(t, Config{}, f.srv)
	s := mustSample(t, c)
	est := time.Duration(s.Offset + Monotonic() - time.Now().UnixNano())
	if (est - 3*time.Second).Abs() > s.Bound+5*time.Millisecond {
		t.Fatalf("server 3 s ahead, measured %v (bound %v)", est, s.Bound)
	}
	if s.Delay < 0 || s.Delay > 50*time.Millisecond {
		t.Fatalf("delay %v: the 2 ms hold must not count", s.Delay)
	}
}

// Before the first quorum the certificate is dated by the coarse time the
// host gives; after it, by the core's own time (the clock tests).
func TestCertificateValidityUsesTheGivenClock(t *testing.T) {
	future := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	cert, ca, err := ntstest.CertificatePEM("nts.test", future, future.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	store := ntstest.NewStore()
	ntp, err := ntstest.StartNTP(store, ntstest.NTPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer ntp.Close()
	ke, err := ntstest.StartKE(cert, store, ntstest.KEOptions{NTPServer: "127.0.0.1", NTPPort: ntp.Port})
	if err != nil {
		t.Fatal(err)
	}
	defer ke.Close()
	c := newClient(t, Config{}, Server{Operator: "a", Host: "nts.test", KEAddr: ke.Addr, Roots: ca})
	if _, err := c.Poll(ctx(t, 5*time.Second), 0, time.Now(), c.Local()); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("certificate from 2031 accepted with today's clock: %v", err)
	}
	// The failed key exchange backs off: a new client for the second try.
	c = newClient(t, Config{}, Server{Operator: "a", Host: "nts.test", KEAddr: ke.Addr, Roots: ca})
	if ps, err := c.Poll(ctx(t, 5*time.Second), 0, future.Add(time.Minute), c.Local()); err != nil || ps.Sample == nil {
		t.Fatalf("with the given clock in 2031: %v", err)
	}
}

// No certificate is checked without a trusted time. The coarse time dates
// the certificate before the first quorum; a zero time (no reading), one
// before the epoch, or one not after FloorTime (a host clock reset to 2000)
// is no time: the core refuses the key exchange before the host dials,
// whatever the certificate. crypto/x509 would read a zero time as the
// host's clock, and the certificate here is valid around the host's clock,
// so a handshake that succeeded would have used it. The host operation
// refuses a time at or before the epoch on its own as well.
func TestKeyExchangeWithoutTrustedTimeIsNotTheSystemClock(t *testing.T) {
	f := newFixture(t, ntstest.KEOptions{}, ntstest.NTPOptions{})
	for _, coarse := range []time.Time{{}, time.Unix(0, 0), time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), FloorTime.Add(-time.Second)} {
		c := newClient(t, Config{}, f.srv)
		ps, err := c.Poll(ctx(t, 5*time.Second), 0, coarse, c.Local())
		if err == nil || !errors.Is(err, ntscore.ErrNoTrustedTime) || !strings.Contains(err.Error(), "no trusted time") {
			t.Fatalf("coarse time %v: %v", coarse, err)
		}
		if ps.Stats.KEFail != 1 || ps.Cookies != 0 || f.ke.Sessions.Load() != 0 {
			t.Fatalf("coarse time %v: stats %+v, cookies %d, sessions %d", coarse, ps.Stats, ps.Cookies, f.ke.Sessions.Load())
		}
	}
	h := newHooks(func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("the host operation dialed without a trusted time")
		return nil, nil
	}, nil)
	for _, v := range []time.Time{{}, time.Unix(0, 0), time.Unix(-1, 0)} {
		if _, _, _, _, err := h.KeyExchange(0, &f.srv, v, time.Second, nil, make([]byte, 16)); err == nil || !strings.Contains(err.Error(), "no trusted time") {
			t.Fatalf("validity %v: %v", v, err)
		}
	}
	// A coarse time in 2000 fails the certificate, not just the floor: a
	// core with an older floor hands it over, and the handshake refuses it.
	// With the host's clock it succeeds.
	if _, err := poll(t, newClient(t, Config{}, f.srv)); err != nil {
		t.Fatalf("with today's coarse time: %v", err)
	}
}

func TestKERefusals(t *testing.T) {
	cases := []struct {
		name string
		opts ntstest.KEOptions
		want string
	}{
		{"TLS 1.2 only", ntstest.KEOptions{TLS12: true}, "protocol version"},
		{"no ALPN", ntstest.KEOptions{NoALPN: true}, "ALPN"},
		{"error record", ntstest.KEOptions{ErrorCode: 2}, "server error 1"},
		{"octets after End of Message", ntstest.KEOptions{Trailing: true}, "after End of Message"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, c.opts, ntstest.NTPOptions{})
			cl := newClient(t, Config{}, f.srv)
			ps, err := poll(t, cl)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error with %q", err, c.want)
			}
			if ps.Stats.KEFail != 1 || ps.Stats.KEOK != 0 || ps.Cookies != 0 {
				t.Fatalf("stats %+v, cookies %d", ps.Stats, ps.Cookies)
			}
			t.Log(err)
		})
	}
	t.Run("roots of another CA", func(t *testing.T) {
		f := newFixture(t, ntstest.KEOptions{}, ntstest.NTPOptions{})
		_, other, _ := ntstest.CertificatePEM("nts.test", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
		srv := f.srv
		srv.Roots = other
		if _, err := poll(t, newClient(t, Config{}, srv)); err == nil || !strings.Contains(err.Error(), "certificate") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("wrong host name", func(t *testing.T) {
		f := newFixture(t, ntstest.KEOptions{}, ntstest.NTPOptions{})
		srv := f.srv
		srv.Host = "other.test"
		if _, err := poll(t, newClient(t, Config{}, srv)); err == nil || !strings.Contains(err.Error(), "certificate") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("no roots", func(t *testing.T) {
		f := newFixture(t, ntstest.KEOptions{}, ntstest.NTPOptions{})
		srv := f.srv
		srv.Roots = nil
		if _, err := poll(t, newClient(t, Config{}, srv)); err == nil || !strings.Contains(err.Error(), "pinned roots") {
			t.Fatalf("got %v", err)
		}
	})
}

func TestKissForgeryAndNTSN(t *testing.T) {
	f := newFixture(t, ntstest.KEOptions{}, ntstest.NTPOptions{Kiss: "RATE"})
	// A query gets half the interval: 500 ms.
	c := newClient(t, Config{Interval: time.Second}, f.srv)
	var k *KissError
	if _, err := poll(t, c); !errors.As(err, &k) || k.Code != "RATE" || !k.Authentic {
		t.Fatalf("RATE: %v", err)
	}
	// A response whose authenticator does not verify is dropped and the
	// query waits for the real one; nothing else comes, so it times out
	// and says why.
	f.ntp.Set(ntstest.NTPOptions{BadAuth: true})
	_, err := poll(t, c)
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() || !strings.Contains(err.Error(), "authenticator does not verify") {
		t.Fatalf("forged: %v", err)
	}
	// The server forgets its cookies: NTSN (RFC 8915 section 5.7), never
	// authenticated, so the keys and the cookies in hand stay.
	f.ntp.Set(ntstest.NTPOptions{})
	f.store.Forget()
	ps, err := poll(t, c)
	if !errors.As(err, &k) || k.Code != "NTSN" || k.Authentic || ps.Cookies != 5 || ps.Stats.Kisses["NTSN"] != 1 {
		t.Fatalf("NTSN: %v, %+v", err, ps)
	}
	// A zero reference timestamp is refused by the RFC 5905 checks; the
	// cookies of that answer are kept, since it was authentic.
	g := newFixture(t, ntstest.KEOptions{}, ntstest.NTPOptions{ZeroRefTim: true})
	c2 := newClient(t, Config{}, g.srv)
	var e *Error
	if ps, err := poll(t, c2); !errors.As(err, &e) || e.Code != CodeSample || ps.Cookies != 8 || ps.Sample != nil {
		t.Fatalf("zero reference: %v, %+v", err, ps)
	}
}

// Eight lost requests use up the cookies; the next poll runs NTS-KE
// again before it asks (RFC 8915 section 5.7).
func TestCookiesRunOut(t *testing.T) {
	f := newFixture(t, ntstest.KEOptions{}, ntstest.NTPOptions{Drop: true})
	c := newClient(t, Config{Interval: 100 * time.Millisecond, ExchangeTimeout: 50 * time.Millisecond}, f.srv)
	for i := 0; i < 8; i++ {
		ps, err := poll(t, c)
		if err == nil || ps.Cookies != 7-i {
			t.Fatalf("poll %d: %v, %d cookies", i, err, ps.Cookies)
		}
	}
	if n := f.ke.Sessions.Load(); n != 1 {
		t.Fatalf("%d NTS-KE sessions with cookies in hand", n)
	}
	ps, err := poll(t, c)
	if err == nil || ps.Stats.KEOK != 2 || ps.Cookies != 7 || f.ke.Sessions.Load() != 2 {
		t.Fatalf("after 8 lost requests: %v, %+v", err, ps)
	}
}

// The KE server may name another NTP host; the address follows it.
func TestNTPAddressFromKE(t *testing.T) {
	f := newFixture(t, ntstest.KEOptions{}, ntstest.NTPOptions{})
	ps, err := poll(t, newClient(t, Config{}, f.srv))
	if err != nil {
		t.Fatal(err)
	}
	host, port, _ := net.SplitHostPort(ps.NTPAddr)
	if host != "127.0.0.1" || port != strconv.Itoa(int(f.ntp.Port)) {
		t.Fatalf("NTP address %s", ps.NTPAddr)
	}
}

// A spoofer on the path sends a forged answer before the real one: the
// forgery is dropped and the real answer is taken, so one fake packet
// cannot knock a server out of the quorum.
func TestDecoyBeforeTheAnswer(t *testing.T) {
	f := newFixture(t, ntstest.KEOptions{}, ntstest.NTPOptions{Decoy: true})
	c := newClient(t, Config{}, f.srv)
	for i := 0; i < 4; i++ {
		s := mustSample(t, c)
		if s.CookiesHeld != 8 || s.CookiesReceived != 1 {
			t.Fatalf("sample %+v", s)
		}
	}
	if n := f.ntp.Requests.Load(); n != 4 {
		t.Fatalf("%d requests for 4 queries", n)
	}
}

// Every precision value a server can state is taken: -128 (which crashed
// the NTP library this client replaced) measures with a 1 ns term, and
// 127 (2^127 s) is refused by the bound, not by a crash.
func TestPrecisionExtremes(t *testing.T) {
	f := newFixture(t, ntstest.KEOptions{}, ntstest.NTPOptions{Precision: -128})
	c := newClient(t, Config{}, f.srv)
	s := mustSample(t, c)
	if s.Precision != -128 || s.Bound > 50*time.Millisecond {
		t.Fatalf("precision -128: %+v", s)
	}
	f.ntp.Set(ntstest.NTPOptions{Precision: 127})
	ps, err := poll(t, c)
	if !errors.Is(err, &Error{Code: CodeSample}) || !strings.Contains(err.Error(), "MAXDIST") {
		t.Fatalf("precision 127: %v", err)
	}
	// The cookies of that answer were kept: it was authentic.
	if ps.Cookies != 8 {
		t.Fatalf("%d cookies after a refused measurement", ps.Cookies)
	}
}

// A forged Kiss-o'-Death does not end the query: the real answer that
// follows it is taken. One sent by itself is reported after the grace,
// without the authentic mark, so the clock does not obey it; the same code
// from the server, authenticated, carries the mark.
func TestForgedKissOfDeath(t *testing.T) {
	f := newFixture(t, ntstest.KEOptions{}, ntstest.NTPOptions{KissDecoy: "DENY"})
	c := newClient(t, Config{}, f.srv)
	if s := mustSample(t, c); s.CookiesHeld != 8 {
		t.Fatalf("a forged DENY before the answer: %+v", s)
	}
	f.ntp.Set(ntstest.NTPOptions{Kiss: "DENY", KissPlain: true})
	start := time.Now()
	var k *KissError
	ps, err := poll(t, c)
	if !errors.As(err, &k) || k.Code != "DENY" || k.Authentic || ps.Disabled != "" || ps.Cookies != 7 {
		t.Fatalf("a forged DENY alone: %v, %+v", err, ps)
	}
	if took := time.Since(start); took < KissGrace || took > 3*time.Second {
		t.Fatalf("the query took %v, want about the grace of %v", took, KissGrace)
	}
	f.ntp.Set(ntstest.NTPOptions{Kiss: "DENY"})
	ps, err = poll(t, c)
	if !errors.As(err, &k) || k.Code != "DENY" || !k.Authentic || ps.Disabled != "DENY" || ps.Cookies != 0 {
		t.Fatalf("the server's own DENY: %v, %+v", err, ps)
	}
}

// A dial that never returns costs one query and its timeout, never the
// clock: UDPOpen bounds the dial, the send and the reads by the core's
// exchange timeout on its own, whatever context the caller gave. A host
// that accepts and never moves (a relay that stops reading) could
// otherwise hold a poll, and with it the refresh, until restart.
func TestHungDialEndsWithTheTimeout(t *testing.T) {
	f := newFixture(t, ntstest.KEOptions{}, ntstest.NTPOptions{})
	hang := false
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if hang && network == "udp" {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	c := newClient(t, Config{Interval: 4 * time.Second, ExchangeTimeout: 200 * time.Millisecond, Dial: dial}, f.srv)
	mustSample(t, c)
	hang = true
	start := time.Now()
	ps, err := c.Poll(context.Background(), 0, time.Now(), c.Local())
	took := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), context.DeadlineExceeded.Error()) || took > 2*time.Second || ps.Cookies != 8 || ps.Stats.Errors != 1 {
		t.Fatalf("hung dial: %v after %v, %+v", err, took, ps)
	}
}

// A connection that fails before the request leaves costs no cookie.
func TestFailedDialReturnsTheCookie(t *testing.T) {
	f := newFixture(t, ntstest.KEOptions{}, ntstest.NTPOptions{})
	fail := false
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if fail && network == "udp" {
			return nil, errors.New("no route")
		}
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	c := newClient(t, Config{Dial: dial}, f.srv)
	mustSample(t, c)
	fail = true
	ps, err := poll(t, c)
	if err == nil || !strings.Contains(err.Error(), "no route") || ps.Cookies != 8 || ps.Stats.Errors != 1 {
		t.Fatalf("failed dial: %v, %+v", err, ps)
	}
}

// keRecords is a well-formed NTS-KE response: Next Protocol, AEAD, two
// cookies and End of Message.
func keRecords(cookies ...[]byte) []byte {
	rec := func(typ uint16, body []byte) []byte {
		return append([]byte{byte(0x80 | typ>>8), byte(typ), byte(len(body) >> 8), byte(len(body))}, body...)
	}
	out := append(rec(1, []byte{0, 0}), rec(4, []byte{0, 15})...)
	for _, c := range cookies {
		out = append(out, rec(5, c)...)
	}
	return append(out, rec(0, nil)...)
}

// readKEResponse reads until End of Message however the bytes arrive:
// one at a time, in odd chunks, with the end of the stream right after.
// It hands over everything read, so octets after End of Message in the
// same read reach the core, which refuses them (the server has nothing
// to say after it). A stream that ends before End of Message, a response
// over the buffer and a reader that makes no progress are errors.
func TestReadKEResponse(t *testing.T) {
	good := keRecords(bytes.Repeat([]byte{0xaa}, 100), bytes.Repeat([]byte{0xbb}, 1024))
	for name, r := range map[string]io.Reader{
		"whole":        bytes.NewReader(good),
		"one byte":     iotest.OneByteReader(bytes.NewReader(good)),
		"half":         iotest.HalfReader(bytes.NewReader(good)),
		"data and EOF": iotest.DataErrReader(bytes.NewReader(good)),
	} {
		buf := make([]byte, ntscore.KEMaxResponseLen)
		n, err := readKEResponse(r, buf)
		if err != nil || n != len(good) || !bytes.Equal(buf[:n], good) {
			t.Fatalf("%s: %d octets, %v", name, n, err)
		}
	}
	trailing := append(append([]byte(nil), good...), 1, 2, 3)
	buf := make([]byte, ntscore.KEMaxResponseLen)
	n, err := readKEResponse(bytes.NewReader(trailing), buf)
	if err != nil || n != len(trailing) {
		t.Fatalf("trailing octets in the same read: %d octets, %v", n, err)
	}
	if _, err := ntscore.ParseKEResponse(buf[:n]); !errors.Is(err, ntscore.ErrKETrailingData) {
		t.Fatalf("the core takes a response with octets after End of Message: %v", err)
	}
	if _, err := readKEResponse(bytes.NewReader(good[:len(good)-1]), make([]byte, ntscore.KEMaxResponseLen)); err == nil || !strings.Contains(err.Error(), "before End of Message") {
		t.Fatalf("a stream that ends before End of Message: %v", err)
	}
	if _, err := readKEResponse(bytes.NewReader(good), make([]byte, len(good)-1)); err == nil || !strings.Contains(err.Error(), "over") {
		t.Fatalf("a response over the buffer: %v", err)
	}
	if _, err := readKEResponse(noProgress{}, make([]byte, 64)); !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("a reader that makes no progress: %v", err)
	}
	if _, err := readKEResponse(iotest.ErrReader(errors.New("reset")), make([]byte, 64)); err == nil || err.Error() != "reset" {
		t.Fatalf("a reader that fails: %v", err)
	}
}

type noProgress struct{}

func (noProgress) Read([]byte) (int, error) { return 0, nil }

// FuzzReadKEResponse: however a response is chunked, the reader gives
// what the core's framing walk says: the complete response (and whatever
// came in the same read after it, which the core refuses), an error for a
// refused framing, and an error for a stream that ends first.
func FuzzReadKEResponse(f *testing.F) {
	f.Add(keRecords([]byte("cookie")), uint8(1))
	f.Add(keRecords([]byte("cookie"))[:9], uint8(3))
	f.Add([]byte{0x80, 0, 0xff, 0xff}, uint8(0))
	f.Fuzz(func(t *testing.T, data []byte, chunk uint8) {
		fuzzcheck.Watch(t)
		r := &chunkReader{data: data, size: 1 + int(chunk)}
		buf := make([]byte, ntscore.KEMaxResponseLen)
		n, err := readKEResponse(r, buf)
		wantN, done, werr := ntscore.KEComplete(data)
		switch {
		case werr != nil:
			if err == nil {
				t.Fatalf("read %d octets of a response the framing refuses: %v", n, werr)
			}
		case done:
			if err != nil || n < wantN || n >= wantN+r.size || !bytes.Equal(buf[:n], data[:n]) {
				t.Fatalf("complete at %d, chunks of %d: read %d, %v", wantN, r.size, n, err)
			}
		default:
			if err == nil {
				t.Fatalf("read %d octets of an incomplete response", n)
			}
		}
	})
}

type chunkReader struct {
	data []byte
	size int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p[:min(len(p), c.size)], c.data)
	c.data = c.data[n:]
	return n, nil
}

// An NTS-KE server that accepts the connection and never speaks costs
// the exchange timeout, one failed key exchange and no cookie.
func TestKEServerThatNeverSpeaks(t *testing.T) {
	f := newFixture(t, ntstest.KEOptions{}, ntstest.NTPOptions{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { conn.Close() })
		}
	}()
	srv := f.srv
	srv.KEAddr = ln.Addr().String()
	c := newClient(t, Config{ExchangeTimeout: 200 * time.Millisecond}, srv)
	start := time.Now()
	ps, err := poll(t, c)
	if took := time.Since(start); err == nil || took > 2*time.Second || ps.Stats.KEFail != 1 || ps.Cookies != 0 || f.ke.Sessions.Load() != 0 {
		t.Fatalf("a silent KE server: %v after %v, %+v", err, took, ps)
	}
}

// The caller's context ends a poll at once, key exchange or query: a
// cancelled context is not a timeout the core waits out.
func TestCancelledContextEndsThePoll(t *testing.T) {
	f := newFixture(t, ntstest.KEOptions{}, ntstest.NTPOptions{Drop: true})
	c := newClient(t, Config{Interval: 20 * time.Second, ExchangeTimeout: 5 * time.Second}, f.srv)
	start := time.Now()
	_, err := c.Poll(ctx(t, 100*time.Millisecond), 0, time.Now(), c.Local())
	if took := time.Since(start); err == nil || !strings.Contains(err.Error(), context.DeadlineExceeded.Error()) || took > time.Second {
		t.Fatalf("a context of 100 ms: %v after %v", err, took)
	}
}

// Close waits for the poll under way and refuses every call after it.
func TestCloseWaitsForThePoll(t *testing.T) {
	f := newFixture(t, ntstest.KEOptions{}, ntstest.NTPOptions{Drop: true})
	c := newClient(t, Config{Interval: time.Second, ExchangeTimeout: 300 * time.Millisecond}, f.srv)
	var pollEnd time.Time
	done := make(chan error, 1)
	go func() {
		_, err := c.Poll(context.Background(), 0, time.Now(), c.Local())
		pollEnd = time.Now()
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	c.Close()
	closeEnd := time.Now()
	if err := <-done; err == nil || pollEnd.After(closeEnd) {
		t.Fatalf("Close returned %v before the poll (%v), poll error %v", closeEnd.Sub(pollEnd), pollEnd, err)
	}
	if _, err := c.Poll(context.Background(), 0, time.Now(), c.Local()); !errors.Is(err, ntscore.ErrClosed) {
		t.Fatalf("a poll after Close: %v", err)
	}
	if _, _, err := c.Bounded(); !errors.Is(err, ntscore.ErrClosed) {
		t.Fatalf("the time after Close: %v", err)
	}
}

// Polls of the three servers of one core run at the same time, on their
// own goroutines, while the time and the summary are read: the core's
// concurrency contract (nts_core.h) under the race detector and the
// sanitizers, then a quorum of the three.
func TestConcurrentPollsOfOneCore(t *testing.T) {
	var servers []Server
	for _, op := range []string{"a", "b", "c"} {
		f := newFixture(t, ntstest.KEOptions{}, ntstest.NTPOptions{})
		s := f.srv
		s.Operator = op
		servers = append(servers, s)
	}
	c := newClient(t, Config{Interval: 200 * time.Millisecond, MinPoll: 10 * time.Millisecond}, servers...)
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	stop := make(chan struct{})
	for i := range servers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for r := 0; r < 6; r++ {
				if ps, err := c.Poll(ctx(t, 10*time.Second), i, time.Now(), c.Local()); err != nil || ps.Sample == nil {
					errs <- err
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
		}(i)
	}
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			select {
			case <-stop:
				return
			default:
				c.Bounded()
				c.Summary()
				c.Peer(0)
			}
		}
	}()
	wg.Wait()
	close(stop)
	<-readerDone
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if err := c.Combine(time.Now(), c.Local()); err != nil {
		t.Fatal(err)
	}
	if st := c.Status(); len(st.Members) != 3 {
		t.Fatalf("quorum of %v", st.Members)
	}
}
