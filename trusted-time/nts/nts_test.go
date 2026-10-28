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
	"sync"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/trusted-time/nts/ntstest"
)

func TestVersion(t *testing.T) {
	v := Version()
	if !strings.HasPrefix(v, "signer-nts ") {
		t.Fatalf("Version() = %q, want a string that starts with %q", v, "signer-nts ")
	}
	t.Log(v)
}

func TestAESSIVSelfTest(t *testing.T) {
	if err := AESSIVSelfTest(); err != nil {
		t.Fatal(err)
	}
}

// Go calls C from whatever thread runs the goroutine. The library must not
// care which one.
func TestCallsFromManyGoroutines(t *testing.T) {
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if err := AESSIVSelfTest(); err != nil {
					errs <- err
					return
				}
				_ = Version()
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
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

// cgo's view of the structs must match the sizes the header states (the
// Rust test checks the Rust side against the same numbers).
func TestStructSizesMatchTheHeader(t *testing.T) {
	if cSizes != headerSizes {
		t.Fatalf("C struct sizes %v, header says %v", cSizes, headerSizes)
	}
}

func TestKEValues(t *testing.T) {
	if ALPN() != "ntske/1" || ExporterLabel() != "EXPORTER-network-time-security" {
		t.Fatalf("ALPN %q, label %q", ALPN(), ExporterLabel())
	}
	if c := ExporterContext(false); !bytes.Equal(c, []byte{0, 0, 0, 15, 0}) {
		t.Fatalf("C2S context %x", c)
	}
	if c := ExporterContext(true); !bytes.Equal(c, []byte{0, 0, 0, 15, 1}) {
		t.Fatalf("S2C context %x", c)
	}
	if r := hex.EncodeToString(KERequest()); r != "80010002000080040002000f80000000" {
		t.Fatalf("KE request %s", r)
	}
	if _, done, err := KEResponseLength([]byte{0x80, 0x01}); done || err != nil {
		t.Fatalf("2 octets: done %v err %v", done, err)
	}
	_, _, err := KEResponseLength([]byte{0x00, 0x05, 0x04, 0x01})
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeKE || e.Kind() != 4 {
		t.Fatalf("over-long record: %v", err)
	}
	t.Log(err)
}

// The test server's AES-SIV against RFC 5297 appendix A.1, so the cross
// check below means something.
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
	if ke.NTPAddr != f.ntp.Addr || ke.Assoc.Cookies() != 8 {
		t.Fatalf("NTP addr %s (want %s), cookies %d", ke.NTPAddr, f.ntp.Addr, ke.Assoc.Cookies())
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
		if s.Bound < s.RootDelay/2+s.RootDispersion || s.CookiesHeld != 8 || s.Stratum != 1 {
			t.Fatalf("sample %+v", s)
		}
		if i == 0 {
			t.Logf("sample %+v", s)
		}
	}
	if n := ke.Assoc.Cookies(); n != 8 {
		t.Fatalf("cookies after 12 queries: %d", n)
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
		{"no ALPN", ntstest.KEOptions{NoALPN: true}, "ALPN"},
		{"error record", ntstest.KEOptions{ErrorCode: 2}, "server error (value: error code, RFC 8915 4.1.3): 1"},
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
	// A response whose authenticator does not verify is skipped; nothing
	// else comes, so the query times out and says why.
	f.ntp.Set(ntstest.NTPOptions{BadAuth: true})
	_, err = ke.Assoc.Query(ctx(t, 500*time.Millisecond), ke.NTPAddr, time.Now(), nil)
	if err == nil || !strings.Contains(err.Error(), "authenticator does not verify") {
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

func TestCookiesRunOut(t *testing.T) {
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
	_, err = ke.Assoc.Query(ctx(t, 50*time.Millisecond), ke.NTPAddr, time.Now(), nil)
	if !errors.Is(err, &Error{Code: CodeNoCookie}) {
		t.Fatalf("after 8 lost requests: %v", err)
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
