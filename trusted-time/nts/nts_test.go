//go:build nts

package nts

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/lidofinance/tee-signer/devkit/fuzzcheck"
	"github.com/lidofinance/tee-signer/trusted-time/nts/ntstest"
	"github.com/lidofinance/tee-signer/trusted-time/ntscatalog"
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
	// No root named is refused here, not only at the key exchange.
	for _, none := range [][]string{nil, {}} {
		if pem, err := RootsPEM(none); err == nil || pem != nil {
			t.Fatalf("no root named: %d octets, %v", len(pem), err)
		}
	}
	if _, err := RootPool([]string{"other.pem"}); err == nil {
		t.Fatal("unpinned root accepted into a pool")
	}
	// Every root the catalog names, for its entries and their alt hosts,
	// is pinned and loads, and every pinned file is used.
	used := map[string]bool{}
	for _, e := range ntscatalog.Builtin.NTS {
		sets := [][]string{e.Roots}
		for _, a := range e.Alt {
			if len(a.Roots) > 0 {
				sets = append(sets, a.Roots)
			}
		}
		for _, roots := range sets {
			if _, err := RootPool(roots); err != nil {
				t.Errorf("%s: %v", e.ID, err)
			}
			if pem, err := RootsPEM(roots); err != nil || len(pem) > ntscore.MaxRootsLen {
				t.Errorf("%s: %d octets of PEM, %v", e.ID, len(pem), err)
			}
			for _, r := range roots {
				used[r] = true
			}
		}
	}
	for f := range rootSHA256 {
		if !used[f] {
			t.Errorf("pinned root %s is named by no catalog entry", f)
		}
	}
}

// fixture is one loopback NTS-KE and NTP server pair, and the Server that
// names them.
type fixture struct {
	store *ntstest.Store
	ke    *ntstest.KEServer
	ntp   *ntstest.NTPServer
	srv   Server
	cert  tls.Certificate
}

// newFixture starts a KE server that names the NTP server's port.
func newFixture(t *testing.T, keOpts ntstest.KEOptions, ntpOpts ntstest.NTPOptions) *fixture {
	t.Helper()
	return newFixtureFor(t, "a", "nts.test", keOpts, ntpOpts)
}

// newFixtureFor is newFixture for another operator and TLS name.
func newFixtureFor(t *testing.T, operator, host string, keOpts ntstest.KEOptions, ntpOpts ntstest.NTPOptions) *fixture {
	t.Helper()
	cert, ca, err := ntstest.CertificatePEM(host, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{store: ntstest.NewStore(), cert: cert}
	if f.ntp, err = ntstest.StartNTP(f.store, ntpOpts); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.ntp.Close)
	keOpts.NTPServer, keOpts.NTPPort = "127.0.0.1", f.ntp.Port
	if f.ke, err = ntstest.StartKE(cert, f.store, keOpts); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.ke.Close)
	f.srv = Server{Operator: operator, Host: host, KEAddr: f.ke.Addr, Roots: ca}
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

// Lost requests use up the cookies, one each (RFC 8915 section 5.7). After
// ntscore.KEAfterLost in a row the core runs NTS-KE again, once for the
// streak (the server may have rotated its keys and dropped the cookies
// silently); the requests lost after it use up the new cookies, and only
// an empty jar runs NTS-KE a third time.
func TestCookiesRunOut(t *testing.T) {
	f := newFixture(t, ntstest.KEOptions{}, ntstest.NTPOptions{Drop: true})
	c := newClient(t, Config{Interval: 100 * time.Millisecond, ExchangeTimeout: 50 * time.Millisecond}, f.srv)
	for i := 0; i < ntscore.KEAfterLost; i++ {
		ps, err := poll(t, c)
		if err == nil || ps.Cookies != 7-i || ps.Stats.KEOK != 1 {
			t.Fatalf("poll %d: %v, %d cookies, %d NTS-KE", i, err, ps.Cookies, ps.Stats.KEOK)
		}
	}
	if n := f.ke.Sessions.Load(); n != 1 {
		t.Fatalf("%d NTS-KE sessions with cookies in hand", n)
	}
	for i := 0; i < ntscore.MaxCookies; i++ {
		ps, err := poll(t, c)
		if err == nil || ps.Cookies != 7-i || ps.Stats.KEOK != 2 {
			t.Fatalf("poll %d of the streak: %v, %d cookies, %d NTS-KE", i, err, ps.Cookies, ps.Stats.KEOK)
		}
	}
	ps, err := poll(t, c)
	if err == nil || ps.Stats.KEOK != 3 || ps.Cookies != 7 || f.ke.Sessions.Load() != 3 {
		t.Fatalf("after the jar ran out: %v, %+v", err, ps)
	}
}

// Two of five servers wrong in different directions: F = 1 gives no time,
// the majority rule (F = 2) gives the interval the other three share.
func TestQuorumBindingMajority(t *testing.T) {
	const ms = int64(time.Millisecond)
	in := []Interval{
		{Operator: "a", Offset: 100 * ms, Bound: 5 * time.Millisecond},
		{Operator: "b", Offset: 101 * ms, Bound: 5 * time.Millisecond},
		{Operator: "c", Offset: 99 * ms, Bound: 5 * time.Millisecond},
		{Operator: "d", Offset: -900 * ms, Bound: time.Millisecond},
		{Operator: "e", Offset: 900 * ms, Bound: time.Millisecond},
	}
	for n, want := range map[int]int{0: 0, 1: 0, 3: 1, 4: 1, 5: 2, 6: 2, 7: 3, 12: 5} {
		if got := MajorityWrong(n); got != want {
			t.Fatalf("MajorityWrong(%d) = %d, want %d", n, got, want)
		}
	}
	for n, want := range map[int]int{0: 0, 2: 0, 3: 0, 4: 1, 5: 2, 6: 2, 7: 3, 12: 5} {
		if got := QuorumWrong(n); got != want {
			t.Fatalf("QuorumWrong(%d) = %d, want %d", n, got, want)
		}
	}
	// Two agree, one does not: the majority rule takes it, the clock's does not.
	two := []Interval{in[0], in[1], in[3]}
	if _, err := Quorum(two, 0, MajorityWrong(3)); err != nil {
		t.Fatalf("2 of 3: %v", err)
	}
	if _, err := Quorum(two, 0, QuorumWrong(3)); err == nil {
		t.Fatal("QuorumWrong took 2 of 3")
	}
	if _, err := Quorum(in, 0, 1); err == nil || !strings.Contains(err.Error(), "disagree") {
		t.Fatalf("F = 1: %v", err)
	}
	q, err := Quorum(in, 0, MajorityWrong(len(in)))
	if err != nil || q.Lo != 96*ms || q.Hi != 104*ms {
		t.Fatalf("majority: %+v %v", q, err)
	}
	if _, err := Quorum(in[:4], 0, 2); err == nil {
		t.Fatal("F = 2 with 4 servers accepted")
	}
	if _, err := Quorum(in, 0, -1); err == nil {
		t.Fatal("negative max wrong accepted")
	}
}

// The catalog keeps copies of the quorum's limits (it builds without cgo);
// they must be the core's.
func TestCatalogLimitsMatchTheCore(t *testing.T) {
	if ntscatalog.MaxLabel != MaxOperatorLen || ntscatalog.MaxServers != MaxServers {
		t.Fatalf("catalog MaxLabel %d MaxServers %d, core %d and %d", ntscatalog.MaxLabel, ntscatalog.MaxServers, MaxOperatorLen, MaxServers)
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
	ps, err := c.Poll(ctx(t, 100*time.Millisecond), 0, time.Now(), c.Local())
	if took := time.Since(start); err == nil || !strings.Contains(err.Error(), context.DeadlineExceeded.Error()) || took > time.Second {
		t.Fatalf("a context of 100 ms: %v after %v", err, took)
	}
	// The caller cut the query, not the server or the query's own timeout:
	// the core is told so (ntscore.ErrHostCancelled) and counts no error
	// and no loss; the server stays due, and the cookie that went out is
	// spent.
	if !errors.Is(err, ntscore.ErrHostCancelled) || ps.Stats.Errors != 0 || ps.LostInRow != 0 || ps.Stats.Queries != 1 || ps.Cookies != 7 ||
		len(c.Due()) != 1 {
		t.Fatalf("a query the caller cut: %v, %+v", err, ps)
	}
	// The query's own timeout is a loss: the context is alive.
	c2 := newClient(t, Config{Interval: 200 * time.Millisecond, ExchangeTimeout: 5 * time.Second}, f.srv)
	if ps, err := poll(t, c2); err == nil || errors.Is(err, ntscore.ErrHostCancelled) || ps.Stats.Errors != 1 || ps.LostInRow != 1 {
		t.Fatalf("a query that timed out: %v, %+v", err, ps)
	}
}

// SetServers and SetPolicy reach the core through the client: a server
// that stays keeps its keys and cookies, a refused list changes nothing,
// and a new protocol starts over.
func TestClientSetServersAndPolicy(t *testing.T) {
	a := newFixture(t, ntstest.KEOptions{}, ntstest.NTPOptions{})
	b := newFixtureFor(t, "b", "b.test", ntstest.KEOptions{}, ntstest.NTPOptions{})
	c := newClient(t, Config{Capacity: 3, StartWait: time.Minute}, a.srv)
	mustSample(t, c)
	if err := c.SetServers([]Server{a.srv, a.srv}, time.Now(), c.Local()); !errors.Is(err, ntscore.ErrBadConfig) {
		t.Fatalf("an operator named twice: %v", err)
	}
	// One host under two labels would have two votes: refused as well.
	twin := a.srv
	twin.Operator = "twin"
	if err := c.SetServers([]Server{a.srv, twin}, time.Now(), c.Local()); !errors.Is(err, ntscore.ErrBadConfig) {
		t.Fatalf("a host named twice: %v", err)
	}
	if ps := c.Peer(0); ps.Sample == nil || ps.Cookies != 8 || len(c.Status().Peers) != 1 {
		t.Fatalf("a refused list changed the client: %+v", ps)
	}
	if err := c.SetServers([]Server{b.srv, a.srv}, time.Now(), c.Local()); err != nil {
		t.Fatal(err)
	}
	// a is server 1 now, with its state; b is new.
	if pa, pb := c.Peer(1), c.Peer(0); pa.Sample == nil || pa.Cookies != 8 || pa.Stats.KEOK != 1 || pb.Sample != nil || pb.Stats.KEOK != 0 {
		t.Fatalf("after the swap: a %+v, b %+v", pa, pb)
	}
	if ps, err := c.Poll(ctx(t, 10*time.Second), 0, time.Now(), c.Local()); err != nil || ps.Stats.KEOK != 1 {
		t.Fatalf("the new server: %v, %+v", err, ps)
	}
	if err := c.SetPolicy(ProtocolNTS, 0, time.Second, time.Now(), c.Local()); !errors.Is(err, ntscore.ErrBadConfig) {
		t.Fatalf("a max bound of 0: %v", err)
	}
	if !ntscore.PlainSupported() {
		return
	}
	if err := c.SetPolicy(ProtocolNTP, 100*time.Millisecond, 100*time.Millisecond, time.Now(), c.Local()); err != nil {
		t.Fatal(err)
	}
	if st := c.Status(); st.Protocol != ProtocolNTP || st.Peers[1].Sample != nil || st.Peers[1].Cookies != 0 || !st.Cold {
		t.Fatalf("after the protocol change: %+v", st)
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

// ---- Plain NTP (RFC 5905, no NTS) through the client ----

func startPlain(t *testing.T, opts ntstest.NTPOptions) *ntstest.NTPServer {
	t.Helper()
	s, err := ntstest.StartPlainNTP(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// plainClient is a client that asks addr with plain NTP.
func plainClient(t *testing.T, cfg Config, addr string) *Client {
	t.Helper()
	if !ntscore.PlainSupported() {
		t.Skip("the core was built without plain NTP")
	}
	cfg.Protocol = ProtocolNTP
	return newClient(t, cfg, Server{Operator: "a", Host: "ntp.test", NTPAddr: addr})
}

func TestQueryPlain(t *testing.T) {
	s := startPlain(t, ntstest.NTPOptions{Offset: 2 * time.Second, RootDelay: 2 * time.Millisecond, RootDisp: time.Millisecond})
	c := plainClient(t, Config{Interval: time.Second, MinPoll: time.Millisecond}, s.Addr)
	for i := 0; i < 5; i++ {
		ps, err := poll(t, c)
		if err != nil || ps.Sample == nil {
			t.Fatalf("poll %d: %v", i, err)
		}
		got := *ps.Sample
		est := time.Duration(got.Offset + Monotonic() - time.Now().UnixNano())
		if (est - 2*time.Second).Abs() > got.Bound+5*time.Millisecond {
			t.Fatalf("server 2 s ahead, measured %v (bound %v)", est, got.Bound)
		}
		if got.Bound < got.RootDelay/2+got.RootDispersion || got.Stratum != 1 || got.CookiesHeld != 0 || got.CookiesReceived != 0 {
			t.Fatalf("sample %+v", got)
		}
		// No key exchange, no cookies, and the address the server list named.
		if ps.Stats.KEOK+ps.Stats.KEFail != 0 || ps.Cookies != 0 || ps.NeedKE || ps.NTPAddr != s.Addr {
			t.Fatalf("peer %+v", ps)
		}
	}
}

func TestQueryPlainKissAndChecks(t *testing.T) {
	s := startPlain(t, ntstest.NTPOptions{Kiss: "RATE"})
	c := plainClient(t, Config{Interval: 600 * time.Millisecond, MinPoll: time.Millisecond}, s.Addr)
	ps, err := poll(t, c)
	var kiss *KissError
	// A plain kiss cannot be authenticated; RATE is obeyed all the same.
	if !errors.As(err, &kiss) || kiss.Code != "RATE" || kiss.Authentic || ps.Poll != 1200*time.Millisecond {
		t.Fatalf("got %v, poll %v", err, ps.Poll)
	}
	s.Set(ntstest.NTPOptions{ZeroRefTim: true})
	var e *Error
	if _, err := poll(t, c); !errors.As(err, &e) || e.Code != CodeSample || !errors.Is(err, ntscore.ErrNeverSynchronized) {
		t.Fatalf("zero reference timestamp: %v", err)
	}
	// A refused answer may be a forgery, so the query waits on for the real
	// one until its deadline (half the interval here).
	s.Set(ntstest.NTPOptions{Stratum: 16})
	if _, err := poll(t, c); err == nil || !strings.Contains(err.Error(), "stratum above 15") {
		t.Fatalf("stratum 16: %v", err)
	}
}

// A forged answer that does not echo the transmit timestamp is skipped; the
// real one that follows is taken.
func TestQueryPlainSkipsForgery(t *testing.T) {
	srv := startPlain(t, ntstest.NTPOptions{Hold: 20 * time.Millisecond})
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { relay.Close() })
	go func() {
		buf := make([]byte, 64)
		n, from, err := relay.ReadFromUDP(buf)
		if err != nil || n != 48 {
			return
		}
		// First a forgery: mode 4, stratum 1, but a wrong origin.
		forged := make([]byte, 48)
		forged[0], forged[1] = 4<<3|4, 1
		copy(forged[24:], buf[40:48])
		forged[31] ^= 1
		_, _ = relay.WriteToUDP(forged, from)
		up, err := net.Dial("udp", srv.Addr)
		if err != nil {
			return
		}
		defer up.Close()
		_, _ = up.Write(buf[:n])
		_ = up.SetDeadline(time.Now().Add(2 * time.Second))
		if n, err = up.Read(buf); err == nil {
			_, _ = relay.WriteToUDP(buf[:n], from)
		}
	}()
	ps, err := poll(t, plainClient(t, Config{Interval: 6 * time.Second}, relay.LocalAddr().String()))
	if err != nil || ps.Sample == nil {
		t.Fatal(err)
	}
	got := *ps.Sample
	if est := time.Duration(got.Offset + Monotonic() - time.Now().UnixNano()); est.Abs() > got.Bound+5*time.Millisecond {
		t.Fatalf("estimate off by %v, bound %v", est, got.Bound)
	}
}

// An NTS server of ntstest answers plain requests too; a plain-only one
// drops NTS requests.
func TestNTSServerAnswersPlain(t *testing.T) {
	f := newFixture(t, ntstest.KEOptions{}, ntstest.NTPOptions{})
	if ps, err := poll(t, plainClient(t, Config{}, f.ntp.Addr)); err != nil || ps.Sample == nil {
		t.Fatal(err)
	}
	// The NTS-KE server names a plain-only NTP server: NTS-KE works, and
	// the NTS query gets no answer.
	s := startPlain(t, ntstest.NTPOptions{})
	f2 := newFixture(t, ntstest.KEOptions{}, ntstest.NTPOptions{})
	ke, err := ntstest.StartKE(f2.cert, f2.store, ntstest.KEOptions{NTPServer: "127.0.0.1", NTPPort: s.Port})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ke.Close)
	srv := f2.srv
	srv.KEAddr = ke.Addr
	ps, err := poll(t, newClient(t, Config{Interval: 600 * time.Millisecond}, srv))
	if err == nil || ps.Stats.KEOK != 1 || ps.Sample != nil || s.Requests.Load() != 1 {
		t.Fatalf("a plain-only server answered NTS: %v, %+v", err, ps)
	}
}

// The NTP host is looked up once and kept until the peer's next key
// exchange or ForgetAddr; an address that is an IP, or a name that does not
// resolve, stays as it is (each dial then looks it up).
func TestResolveNTPAddress(t *testing.T) {
	var warned atomic.Int32
	h := newHooks(nil, nil)
	h.resolve, h.warn = true, func(string, ...any) { warned.Add(1) }
	bg := context.Background()
	if got := h.resolved(bg, 0, "127.0.0.1:123"); got != "127.0.0.1:123" {
		t.Fatal(got)
	}
	if got := h.resolved(bg, 1, "no-such-host.invalid:123"); got != "no-such-host.invalid:123" || warned.Load() != 1 {
		t.Fatalf("%q, %d warnings", got, warned.Load())
	}
	// Kept: no second lookup, so no second warning.
	if got := h.resolved(bg, 1, "no-such-host.invalid:123"); got != "no-such-host.invalid:123" || warned.Load() != 1 {
		t.Fatalf("kept: %q, %d warnings", got, warned.Load())
	}
	h.forget(1)
	if h.resolved(bg, 1, "no-such-host.invalid:123"); warned.Load() != 2 {
		t.Fatalf("after forget: %d warnings, want a second lookup", warned.Load())
	}
	got := h.resolved(bg, 2, "localhost:123")
	host, port, err := net.SplitHostPort(got)
	if ip := net.ParseIP(host); err != nil || ip == nil || ip.To4() == nil || port != "123" {
		t.Fatalf("localhost:123 resolved to %q, want an IPv4 address", got)
	}
	// What was kept is for the address the core named then: another one
	// (a new key exchange named another host) is looked up.
	if got := h.resolved(bg, 2, "127.0.0.2:123"); got != "127.0.0.2:123" {
		t.Fatal(got)
	}
	// A lookup the caller's context cut is not kept.
	done, cancel := context.WithCancel(bg)
	cancel()
	if got := h.resolved(done, 3, "localhost:123"); got != "localhost:123" {
		t.Fatal(got)
	}
	h.mu.Lock()
	_, kept := h.addrs[3]
	h.mu.Unlock()
	if kept {
		t.Fatal("a cut lookup was kept")
	}
}
