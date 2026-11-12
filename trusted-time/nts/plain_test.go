//go:build nts

package nts

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/trusted-time/nts/ntstest"
)

func startPlain(t *testing.T, opts ntstest.NTPOptions) *ntstest.NTPServer {
	t.Helper()
	s, err := ntstest.StartPlainNTP(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestPlainRequestBytes(t *testing.T) {
	random := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	p, r, err := NewPlainRequest(random)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if len(p) != PlainRequestLen || p[0] != 0x23 || string(p[40:]) != string(random) {
		t.Fatalf("request %x", p)
	}
	for _, b := range p[1:40] {
		if b != 0 {
			t.Fatalf("request %x: octets 1 to 39 not zero", p)
		}
	}
	var e *Error
	if _, _, err := NewPlainRequest(random[:7]); !errors.As(err, &e) || e.Code != CodeArg {
		t.Fatalf("7 random octets: %v", err)
	}
	// Our own request is mode 3: refused, and r stays open.
	if _, err := r.Verify(p, 0, 1, time.Now()); !errors.As(err, &e) || e.Code != CodeNTP || e.Kind() != 8 {
		t.Fatalf("mode 3 answer: %v", err)
	}
	r.Close()
	if _, err := r.Verify(p, 0, 1, time.Now()); err == nil {
		t.Fatal("verify after close")
	}
}

func TestQueryPlain(t *testing.T) {
	s := startPlain(t, ntstest.NTPOptions{Offset: 2 * time.Second, RootDelay: 2 * time.Millisecond, RootDisp: time.Millisecond})
	for i := 0; i < 5; i++ {
		got, err := QueryPlain(ctx(t, 2*time.Second), s.Addr, time.Now(), nil)
		if err != nil {
			t.Fatal(err)
		}
		est := time.Duration(got.Offset + Monotonic() - time.Now().UnixNano())
		if (est - 2*time.Second).Abs() > got.Bound+5*time.Millisecond {
			t.Fatalf("server 2 s ahead, measured %v (bound %v)", est, got.Bound)
		}
		if got.Bound < got.RootDelay/2+got.RootDispersion || got.Stratum != 1 || got.CookiesHeld != 0 || got.CookiesReceived != 0 {
			t.Fatalf("sample %+v", got)
		}
	}
}

func TestQueryPlainKissAndChecks(t *testing.T) {
	s := startPlain(t, ntstest.NTPOptions{Kiss: "RATE"})
	_, err := QueryPlain(ctx(t, 2*time.Second), s.Addr, time.Now(), nil)
	var kiss *KissError
	if !errors.As(err, &kiss) || kiss.Code != "RATE" {
		t.Fatalf("got %v", err)
	}
	s.Set(ntstest.NTPOptions{ZeroRefTim: true})
	var e *Error
	if _, err := QueryPlain(ctx(t, 2*time.Second), s.Addr, time.Now(), nil); !errors.As(err, &e) || e.Code != CodeSample || e.Kind() != 5 {
		t.Fatalf("zero reference timestamp: %v", err)
	}
	// A refused answer may be a forgery, so the query waits on for the real
	// one until its deadline.
	s.Set(ntstest.NTPOptions{Stratum: 16})
	if _, err := QueryPlain(ctx(t, 300*time.Millisecond), s.Addr, time.Now(), nil); err == nil || !strings.Contains(err.Error(), "stratum above 15") {
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
	got, err := QueryPlain(ctx(t, 3*time.Second), relay.LocalAddr().String(), time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if est := time.Duration(got.Offset + Monotonic() - time.Now().UnixNano()); est.Abs() > got.Bound+5*time.Millisecond {
		t.Fatalf("estimate off by %v, bound %v", est, got.Bound)
	}
}

// An NTS server of ntstest answers plain requests too; a plain-only one
// drops NTS requests.
func TestNTSServerAnswersPlain(t *testing.T) {
	f := newFixture(t, ntstest.KEOptions{}, ntstest.NTPOptions{})
	if _, err := QueryPlain(ctx(t, 2*time.Second), f.ntp.Addr, time.Now(), nil); err != nil {
		t.Fatal(err)
	}
	s := startPlain(t, ntstest.NTPOptions{})
	ke, err := KeyExchange(ctx(t, 5*time.Second), f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ke.Assoc.Close()
	if _, err := ke.Assoc.Query(ctx(t, 300*time.Millisecond), s.Addr, time.Now(), nil); err == nil {
		t.Fatal("a plain-only server answered NTS")
	}
}
