//go:build nts

package nts

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/trusted-time/nts/ntstest"
	"github.com/lidofinance/tee-signer/trusted-time/ntscore"
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
