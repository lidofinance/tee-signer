//go:build nts

package nts

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/trusted-time/nts/ntstest"
)

func TestVersion(t *testing.T) {
	v := Version()
	if !strings.HasPrefix(v, "beevik/nts") {
		t.Fatalf("Version() = %q, want a string that starts with %q", v, "beevik/nts")
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

// The test server's AES-SIV against RFC 5297 appendix A.1, so the cross
// check below means something, and the library's AES-SIV against the test
// server's on the self-test's input.
func TestTestServerSIVMatchesRFC5297(t *testing.T) {
	h := func(s string) []byte { b, _ := hex.DecodeString(s); return b }
	key := h("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	ad := h("101112131415161718191a1b1c1d1e1f2021222324252627")
	pt := h("112233445566778899aabbccddee")
	want := h("85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c")
	if got := ntstest.SealVector(key, [][]byte{ad}, pt); !bytes.Equal(got, want) {
		t.Fatalf("A.1: got %x, want %x", got, want)
	}
	ct := ntstest.Seal(key, ad, []byte("nonce"), pt)
	if p, ok := ntstest.Open(key, ad, []byte("nonce"), ct); !ok || !bytes.Equal(p, pt) {
		t.Fatal("open after seal failed")
	}
	ct[3] ^= 1
	if _, ok := ntstest.Open(key, ad, []byte("nonce"), ct); ok {
		t.Fatal("tampered ciphertext opened")
	}
	// The same input through both: the known answer of AESSIVSelfTest.
	key2 := h("7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f")
	ad2 := h("00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100")
	nonce2 := h("09f911029d74e35bd84156c5635688c0")
	pt2 := h("7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553")
	want2 := h("85825e22e90cf2ddda2c548dc7c1b6310dcdaca0cebf9dc6cb90583f5bf1506e02cd48832b00e4e598b2b22a53e6199d4df0c1666a35a0433b250dc134d776")
	if got := ntstest.Seal(key2, ad2, nonce2, pt2); !bytes.Equal(got, want2) {
		t.Fatalf("test server on the self-test input: %x", got)
	}
}

type fixture struct {
	store *ntstest.Store
	ke    *ntstest.KEServer
	ntp   *ntstest.NTPServer
	cfg   KEConfig
}

// newFixture starts a KE server that names the NTP server's port.
func newFixture(t *testing.T, keOpts ntstest.KEOptions, ntpOpts ntstest.NTPOptions) *fixture {
	t.Helper()
	cert, pool, err := ntstest.Certificate("nts.test", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
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
	f.cfg = KEConfig{Host: "nts.test", Addr: f.ke.Addr, Roots: pool, Time: time.Now}
	return f
}

func ctx(t *testing.T, d time.Duration) context.Context {
	c, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return c
}

func TestKeyExchangeAndQuery(t *testing.T) {
	f := newFixture(t, ntstest.KEOptions{}, ntstest.NTPOptions{RootDelay: 2 * time.Millisecond, RootDisp: time.Millisecond})
	ke, err := KeyExchange(ctx(t, 5*time.Second), f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ke.Assoc.Close()
	if ke.NTPAddr != f.ntp.Addr {
		t.Fatalf("NTP addr %s (want %s)", ke.NTPAddr, f.ntp.Addr)
	}
	for i := 0; i < 12; i++ {
		s, err := ke.Assoc.Query(ctx(t, 2*time.Second), ke.NTPAddr, time.Now(), nil)
		if err != nil {
			t.Fatal(err)
		}
		// The server's clock is this host's; the measured real time must be
		// within the bound of it.
		now := time.Now().UnixNano()
		est := s.Offset + Monotonic()
		if diff := time.Duration(est - now); diff.Abs() > s.Bound+5*time.Millisecond {
			t.Fatalf("estimate off by %v, bound %v", diff, s.Bound)
		}
		if s.Bound < s.RootDelay/2+s.RootDispersion || s.Stratum != 1 {
			t.Fatalf("sample %+v", s)
		}
		if i == 0 {
			t.Logf("sample %+v", s)
		}
	}
	// Twelve queries used twelve cookies and got twelve back: one key
	// exchange served them all.
	if n := f.ke.Sessions.Load(); n != 1 {
		t.Fatalf("%d key exchanges for 12 queries, want 1", n)
	}
}

func TestServerOffsetIsMeasured(t *testing.T) {
	f := newFixture(t, ntstest.KEOptions{}, ntstest.NTPOptions{Offset: 3 * time.Second, Hold: 2 * time.Millisecond})
	ke, err := KeyExchange(ctx(t, 5*time.Second), f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ke.Assoc.Close()
	s, err := ke.Assoc.Query(ctx(t, 2*time.Second), ke.NTPAddr, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	est := time.Duration(s.Offset + Monotonic() - time.Now().UnixNano())
	if (est - 3*time.Second).Abs() > s.Bound+5*time.Millisecond {
		t.Fatalf("server 3 s ahead, measured %v (bound %v)", est, s.Bound)
	}
	if s.Delay < 0 || s.Delay > 50*time.Millisecond {
		t.Fatalf("delay %v: the 2 ms hold must not count", s.Delay)
	}
}

func TestCertificateValidityUsesTheGivenClock(t *testing.T) {
	future := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	cert, pool, err := ntstest.Certificate("nts.test", future, future.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	store := ntstest.NewStore()
	ke, err := ntstest.StartKE(cert, store, ntstest.KEOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer ke.Close()
	cfg := KEConfig{Host: "nts.test", Addr: ke.Addr, Roots: pool, Time: time.Now}
	if _, err := KeyExchange(ctx(t, 5*time.Second), cfg); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("certificate from 2031 accepted with today's clock: %v", err)
	}
	cfg.Time = func() time.Time { return future.Add(time.Minute) }
	r, err := KeyExchange(ctx(t, 5*time.Second), cfg)
	if err != nil {
		t.Fatalf("with the given clock in 2031: %v", err)
	}
	r.Assoc.Close()
}

func TestKERefusals(t *testing.T) {
	cases := []struct {
		name string
		opts ntstest.KEOptions
		want string
	}{
		{"TLS 1.2 only", ntstest.KEOptions{TLS12: true}, "protocol version"},
		{"no ALPN", ntstest.KEOptions{NoALPN: true}, "not negotiated"},
		{"error record", ntstest.KEOptions{ErrorCode: 2}, "bad request"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, c.opts, ntstest.NTPOptions{})
			_, err := KeyExchange(ctx(t, 5*time.Second), f.cfg)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error with %q", err, c.want)
			}
			t.Log(err)
		})
	}
	t.Run("roots of another CA", func(t *testing.T) {
		f := newFixture(t, ntstest.KEOptions{}, ntstest.NTPOptions{})
		_, other, _ := ntstest.Certificate("nts.test", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
		f.cfg.Roots = other
		if _, err := KeyExchange(ctx(t, 5*time.Second), f.cfg); err == nil || !strings.Contains(err.Error(), "certificate") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("wrong host name", func(t *testing.T) {
		f := newFixture(t, ntstest.KEOptions{}, ntstest.NTPOptions{})
		f.cfg.Host = "other.test"
		if _, err := KeyExchange(ctx(t, 5*time.Second), f.cfg); err == nil || !strings.Contains(err.Error(), "certificate") {
			t.Fatalf("got %v", err)
		}
	})
}

func TestKissForgeryAndNTSN(t *testing.T) {
	f := newFixture(t, ntstest.KEOptions{}, ntstest.NTPOptions{Kiss: "RATE"})
	ke, err := KeyExchange(ctx(t, 5*time.Second), f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ke.Assoc.Close()
	var k *KissError
	if _, err := ke.Assoc.Query(ctx(t, 2*time.Second), ke.NTPAddr, time.Now(), nil); !errors.As(err, &k) || k.Code != "RATE" {
		t.Fatalf("RATE: %v", err)
	}
	// A response whose authenticator does not verify is refused: the
	// library takes the first answer, so this query fails and says why.
	f.ntp.Set(ntstest.NTPOptions{BadAuth: true})
	_, err = ke.Assoc.Query(ctx(t, 500*time.Millisecond), ke.NTPAddr, time.Now(), nil)
	if !errors.Is(err, &Error{Code: CodeNTP}) || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("forged: %v", err)
	}
	// The server forgets its cookies: NTSN (RFC 8915 section 5.7).
	f.ntp.Set(ntstest.NTPOptions{})
	f.store.Forget()
	if _, err := ke.Assoc.Query(ctx(t, 2*time.Second), ke.NTPAddr, time.Now(), nil); !errors.As(err, &k) || k.Code != "NTSN" {
		t.Fatalf("NTSN: %v", err)
	}
	// A zero reference timestamp is refused by the RFC 5905 checks.
	g := newFixture(t, ntstest.KEOptions{}, ntstest.NTPOptions{ZeroRefTim: true})
	ke2, err := KeyExchange(ctx(t, 5*time.Second), g.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ke2.Assoc.Close()
	var e *Error
	if _, err := ke2.Assoc.Query(ctx(t, 2*time.Second), ke2.NTPAddr, time.Now(), nil); !errors.As(err, &e) || e.Code != CodeSample {
		t.Fatalf("zero reference: %v", err)
	}
}

// When the eight cookies of a key exchange are gone (eight requests without
// an answer), the next query runs NTS-KE again by itself.
func TestCookiesRunOutRunsKeyExchangeAgain(t *testing.T) {
	f := newFixture(t, ntstest.KEOptions{}, ntstest.NTPOptions{Drop: true})
	ke, err := KeyExchange(ctx(t, 5*time.Second), f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ke.Assoc.Close()
	for i := 0; i < 8; i++ {
		if _, err := ke.Assoc.Query(ctx(t, 50*time.Millisecond), ke.NTPAddr, time.Now(), nil); err == nil {
			t.Fatal("dropped request answered")
		}
	}
	if n := f.ke.Sessions.Load(); n != 1 {
		t.Fatalf("%d key exchanges after 8 lost requests, want 1", n)
	}
	f.ntp.Set(ntstest.NTPOptions{})
	if _, err := ke.Assoc.Query(ctx(t, 2*time.Second), ke.NTPAddr, time.Now(), nil); err != nil {
		t.Fatalf("ninth query: %v", err)
	}
	if n := f.ke.Sessions.Load(); n != 2 {
		t.Fatalf("%d key exchanges after the cookies ran out, want 2", n)
	}
}

func TestQuorumBinding(t *testing.T) {
	const ms = int64(time.Millisecond)
	in := []Interval{
		{Operator: "cloudflare", Offset: 100 * ms, Bound: 10 * time.Millisecond},
		{Operator: "netnod", Offset: 110 * ms, Bound: 15 * time.Millisecond},
		{Operator: "ptb", Offset: 102 * ms, Bound: 2 * time.Millisecond},
	}
	q, err := Quorum(in, 0)
	if err != nil || q.Lo != 95*ms || q.Hi != 110*ms || q.Offset != 102_500_000 || q.Bound != 7_500_000 {
		t.Fatalf("%+v %v", q, err)
	}
	in[2].Operator = "netnod"
	if _, err := Quorum(in, 0); err == nil || !strings.Contains(err.Error(), "two servers of one operator") {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := Quorum(in[:2], 0); err == nil {
		t.Fatal("two servers accepted")
	}
	if d := Drift(32 * time.Second); d != 16*time.Millisecond {
		t.Fatalf("Drift(32 s) = %v", d)
	}
}

func TestPinnedRoots(t *testing.T) {
	for _, s := range PublicServers {
		if _, err := RootPool(s.Roots); err != nil {
			t.Fatalf("%s: %v", s.Host, err)
		}
	}
	if _, err := RootPool([]string{"other.pem"}); err == nil {
		t.Fatal("unpinned root accepted")
	}
}

// The KE server may name another NTP host; the address follows it.
func TestNTPAddressFromKE(t *testing.T) {
	f := newFixture(t, ntstest.KEOptions{}, ntstest.NTPOptions{})
	ke, err := KeyExchange(ctx(t, 5*time.Second), f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ke.Assoc.Close()
	host, port, _ := net.SplitHostPort(ke.NTPAddr)
	if host != "127.0.0.1" || port != strconv.Itoa(int(f.ntp.Port)) {
		t.Fatalf("NTP address %s", ke.NTPAddr)
	}
}
