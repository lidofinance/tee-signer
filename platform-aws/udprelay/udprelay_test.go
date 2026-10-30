package udprelay

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/platform-aws/udprelay/relayclient"
	"github.com/lidofinance/tee-signer/signer-protocol/transport"
)

// fakeDNS answers from a table and counts lookups.
type fakeDNS struct {
	table map[string][]netip.Addr
	calls atomic.Int64
}

func (f *fakeDNS) lookup(_ context.Context, h string) ([]netip.Addr, error) {
	f.calls.Add(1)
	if a, ok := f.table[h]; ok {
		return append([]netip.Addr(nil), a...), nil
	}
	return nil, errors.New("no such host")
}

func addrs(s ...string) []netip.Addr {
	var out []netip.Addr
	for _, v := range s {
		out = append(out, netip.MustParseAddr(v))
	}
	return out
}

func TestAllowlist(t *testing.T) {
	dns := &fakeDNS{table: map[string][]netip.Addr{
		"time.cloudflare.com": addrs("2606:4700:f1::1", "162.159.200.1"),
		"nts.netnod.se":       addrs("194.58.204.203", "192.71.80.206"),
		"ptbtime1.ptb.de":     addrs("::ffff:192.53.103.108"),
		"evil.example":        addrs("203.0.113.9"),
	}}
	a := Default()
	a.Lookup = dns.lookup
	ok := map[string]string{
		"time.cloudflare.com:123":      "162.159.200.1:123", // IPv4 first
		"Time.Cloudflare.COM.:123":     "162.159.200.1:123",
		"ptbtime1.ptb.de:123":          "192.53.103.108:123",  // mapped address unmapped
		"194.58.205.197:4123":          "194.58.205.197:4123", // Netnod's block
		"192.71.80.206:123":            "192.71.80.206:123",   // an address of an allowed name
		"[2606:4700:f1::1]:123":        "[2606:4700:f1::1]:123",
		"[::ffff:194.58.203.196]:4123": "194.58.203.196:4123",
	}
	for dest, want := range ok {
		ap, err := a.Check(context.Background(), dest)
		if err != nil || ap.String() != want {
			t.Errorf("%s: got %v, %v; want %s", dest, ap, err, want)
		}
	}
	refused := map[string]string{
		"time.cloudflare.com:53":            "port 53 not allowed",
		"time.cloudflare.com:4460":          "port 4460 not allowed",
		"evil.example:123":                  "name evil.example not in the allowlist",
		"ntppool1.time.nl.evil.example:123": "not in the allowlist",
		"203.0.113.9:123":                   "not in the allowlist", // what evil.example resolves to
		"194.58.208.1:4123":                 "not in the allowlist", // just outside the block
		"127.0.0.1:123":                     "not in the allowlist",
		"0.0.0.0:123":                       "not allowed",
		"224.0.1.1:123":                     "not allowed", // NTP multicast
		"[fe80::1%eth0]:123":                "not allowed",
		"ntppool1.time.nl:123":              "cannot resolve",
		"time.cloudflare.com":               "not host:port",
		"time.cloudflare.com:x":             "port x not allowed",
		"time.cloudflare.com:-1":            "not allowed",
		"time.cloudflare.com:65659":         "not allowed",
	}
	before := dns.calls.Load()
	for dest, want := range refused {
		if _, err := a.Check(context.Background(), dest); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want %q", dest, err, want)
		}
	}
	// No name outside the list was looked up. The allowed names are
	// cached from above, except ntppool1.time.nl, whose lookup fails.
	if got := dns.calls.Load() - before; got > 1 {
		t.Errorf("%d lookups for the refusals, want at most 1 (ntppool1.time.nl, then its failure is cached)", got)
	}
	for _, f := range []string{"evil.example", "ntppool1.time.nl.evil.example"} {
		if _, ok := a.cache[f]; ok {
			t.Errorf("%s was looked up", f)
		}
	}
}

func TestAllowlistCacheTTL(t *testing.T) {
	dns := &fakeDNS{table: map[string][]netip.Addr{"a.example": addrs("192.0.2.1")}}
	a := &Allowlist{Names: []string{"a.example"}, Ports: []uint16{123}, Lookup: dns.lookup, TTL: 50 * time.Millisecond}
	for range 3 {
		if _, err := a.Check(context.Background(), "a.example:123"); err != nil {
			t.Fatal(err)
		}
	}
	if dns.calls.Load() != 1 {
		t.Fatalf("%d lookups within the TTL", dns.calls.Load())
	}
	dns.table["a.example"] = addrs("192.0.2.2")
	time.Sleep(60 * time.Millisecond)
	if _, err := a.Check(context.Background(), "192.0.2.1:123"); err == nil {
		t.Fatal("the old address passed after the TTL")
	}
	if ap, err := a.Check(context.Background(), "192.0.2.2:123"); err != nil || ap.Addr().String() != "192.0.2.2" {
		t.Fatalf("new address: %v %v", ap, err)
	}
}

func TestParse(t *testing.T) {
	p, err := ParsePorts(" 123, 4123,")
	if err != nil || len(p) != 2 || p[1] != 4123 {
		t.Fatalf("%v %v", p, err)
	}
	for _, bad := range []string{"0", "65536", "x"} {
		if _, err := ParsePorts(bad); err == nil {
			t.Errorf("port %q accepted", bad)
		}
	}
	n, err := ParseNets("194.58.205.197/21")
	if err != nil || n[0].String() != "194.58.200.0/21" {
		t.Fatalf("%v %v", n, err)
	}
	if _, err := ParseNets("194.58.205.0"); err == nil {
		t.Error("an address without length accepted")
	}
	if got := ParseNames(" A.example., ,b.example"); len(got) != 2 || got[0] != "a.example" {
		t.Fatalf("%v", got)
	}
}

// udpServer answers each datagram with reply(p), counting the datagrams.
type udpServer struct {
	conn *net.UDPConn
	got  atomic.Int64
}

func startUDP(t *testing.T, reply func([]byte) []byte) *udpServer {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	s := &udpServer{conn: c}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			s.got.Add(1)
			if r := reply(buf[:n]); r != nil {
				_, _ = c.WriteToUDP(r, from)
			}
		}
	}()
	return s
}

func (s *udpServer) port() uint16 { return uint16(s.conn.LocalAddr().(*net.UDPAddr).Port) }

func echo(p []byte) []byte { return append([]byte("re:"), p...) }

// startRelay runs srv on a loopback TCP port (the vsock of the tests).
func startRelay(t *testing.T, srv *Server) transport.Addr {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, l) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	a, err := transport.Parse("tcp:" + l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func loopAllow(ports ...uint16) *Allowlist {
	return &Allowlist{Nets: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Ports: ports}
}

func dest(port uint16) string { return "127.0.0.1:" + strconv.Itoa(int(port)) }

func TestRelayRoundTrip(t *testing.T) {
	u := startUDP(t, echo)
	srv := &Server{Allow: loopAllow(u.port())}
	relay := startRelay(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := relayclient.Dial(ctx, relay, dest(u.port()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	for i, msg := range []string{"one", strings.Repeat("x", 1280)} {
		if _, err := c.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, relayclient.MaxDatagram+1)
		n, err := c.Read(buf)
		if err != nil || string(buf[:n]) != "re:"+msg {
			t.Fatalf("datagram %d: %q %v", i, buf[:min(n, 20)], err)
		}
	}
	// A short buffer gets the first octets, as UDP gives.
	_, _ = c.Write([]byte("abcdef"))
	small := make([]byte, 4)
	if n, err := c.Read(small); err != nil || n != 4 || string(small) != "re:a" {
		t.Fatalf("short read %q %v", small[:n], err)
	}
	if _, err := c.Write(make([]byte, relayclient.MaxDatagram+1)); err == nil {
		t.Fatal("datagram over the cap written")
	}
	if _, err := c.Write(nil); err == nil {
		t.Fatal("empty datagram written")
	}
	c.Close()
	waitFor(t, func() bool { return srv.Counter.sessionsNow.Load() == 0 })
	if srv.Counter.Out.Load() != 3 || srv.Counter.In.Load() != 3 {
		t.Fatalf("counters %v", srv.Counter.Snapshot())
	}
}

func waitFor(t *testing.T, f func() bool) {
	t.Helper()
	for i := 0; i < 200 && !f(); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if !f() {
		t.Fatal("condition not reached")
	}
}

// A refused destination gets the reason and no datagram leaves.
func TestRelayRefusesDestinations(t *testing.T) {
	u := startUDP(t, echo)
	srv := &Server{Allow: loopAllow(123)}
	relay := startRelay(t, srv)
	ctx := context.Background()
	for _, d := range []string{dest(u.port()), "localhost:123", "8.8.8.8:123", "not a destination", strings.Repeat("a", relayclient.MaxDest) + ":123"} {
		c, err := relayclient.Dial(ctx, relay, d)
		if err == nil {
			c.Close()
			t.Fatalf("%s accepted", d)
		}
		t.Logf("%.40s: %v", d, err)
	}
	if got := srv.Counter.Refused.Load(); got != 4 {
		t.Errorf("refused %d, want 4 (the long one is refused by relayclient.Dial itself)", got)
	}
	// A destination that is not printable ASCII.
	raw := rawConn(t, relay)
	_ = relayclient.WriteFrame(raw, []byte("127.0.0.1:123\x00"))
	st, err := relayclient.ReadFrame(raw, make([]byte, 300), 300)
	if err != nil || st[0] != 1 {
		t.Fatalf("NUL in the destination: %q %v", st, err)
	}
	if u.got.Load() != 0 {
		t.Fatalf("%d datagrams reached the server", u.got.Load())
	}
}

func rawConn(t *testing.T, a transport.Addr) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", a.Address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	return c
}

// closed: the relay closes c without sending more.
func closed(t *testing.T, c net.Conn) {
	t.Helper()
	b := make([]byte, 64)
	for {
		n, err := c.Read(b)
		if err != nil {
			if errors.Is(err, io.EOF) || strings.Contains(err.Error(), "reset") {
				return
			}
			t.Fatalf("read: %v", err)
		}
		_ = n
	}
}

func TestRelayGarbage(t *testing.T) {
	u := startUDP(t, echo)
	srv := &Server{Allow: loopAllow(u.port())}
	relay := startRelay(t, srv)

	// A zero length destination frame.
	c := rawConn(t, relay)
	_, _ = c.Write([]byte{0, 0})
	closed(t, c)
	// A destination frame over relayclient.MaxDest.
	c = rawConn(t, relay)
	_, _ = c.Write(binary.BigEndian.AppendUint16(nil, relayclient.MaxDest+1))
	closed(t, c)
	// Accepted, then a datagram frame over the cap: the session ends.
	c = rawConn(t, relay)
	_ = relayclient.WriteFrame(c, []byte(dest(u.port())))
	if st, err := relayclient.ReadFrame(c, make([]byte, 300), 300); err != nil || st[0] != 0 {
		t.Fatalf("status %q %v", st, err)
	}
	_, _ = c.Write(binary.BigEndian.AppendUint16(nil, relayclient.MaxDatagram+1))
	_, _ = c.Write(bytes.Repeat([]byte{0xff}, 100))
	closed(t, c)
	// Accepted, then a zero length frame.
	c = rawConn(t, relay)
	_ = relayclient.WriteFrame(c, []byte(dest(u.port())))
	_, _ = relayclient.ReadFrame(c, make([]byte, 300), 300)
	_, _ = c.Write([]byte{0, 0})
	closed(t, c)
	// Something else on the port ("GET /" reads as a length of 18245).
	c = rawConn(t, relay)
	_, _ = c.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	closed(t, c)
	waitFor(t, func() bool { return srv.Counter.BadFrames.Load() == 5 })
	if u.got.Load() != 0 {
		t.Fatalf("%d datagrams reached the server", u.got.Load())
	}
	// The relay still works.
	cl, err := relayclient.Dial(context.Background(), relay, dest(u.port()))
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	_, _ = cl.Write([]byte("still"))
	_ = cl.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 100)
	if n, err := cl.Read(buf); err != nil || string(buf[:n]) != "re:still" {
		t.Fatalf("after garbage: %q %v", buf[:n], err)
	}
}

// An answer over relayclient.MaxDatagram is dropped, the next one passes.
func TestRelayDropsLargeAnswers(t *testing.T) {
	u := startUDP(t, func(p []byte) []byte {
		if string(p) == "big" {
			return make([]byte, relayclient.MaxDatagram+1)
		}
		return echo(p)
	})
	srv := &Server{Allow: loopAllow(u.port())}
	c, err := relayclient.Dial(context.Background(), startRelay(t, srv), dest(u.port()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = c.Write([]byte("big"))
	_, _ = c.Write([]byte("small"))
	buf := make([]byte, relayclient.MaxDatagram+1)
	n, err := c.Read(buf)
	if err != nil || string(buf[:n]) != "re:small" {
		t.Fatalf("%q %v", buf[:min(n, 10)], err)
	}
	if srv.Counter.DroppedLarge.Load() != 1 {
		t.Fatalf("counters %v", srv.Counter.Snapshot())
	}
}

func sendN(t *testing.T, c *relayclient.Conn, n int) {
	t.Helper()
	for i := range n {
		if _, err := c.Write([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRelayRateLimits(t *testing.T) {
	t.Run("per destination", func(t *testing.T) {
		u := startUDP(t, func([]byte) []byte { return nil })
		srv := &Server{Allow: loopAllow(u.port()), DestRate: 0.001, DestBurst: 2}
		c, err := relayclient.Dial(context.Background(), startRelay(t, srv), dest(u.port()))
		if err != nil {
			t.Fatal(err)
		}
		sendN(t, c, 5)
		c.Close()
		waitFor(t, func() bool { return srv.Counter.sessionsNow.Load() == 0 })
		if u.got.Load() != 2 || srv.Counter.DroppedRate.Load() != 3 {
			t.Fatalf("server got %d, counters %v", u.got.Load(), srv.Counter.Snapshot())
		}
	})
	t.Run("all destinations", func(t *testing.T) {
		u1 := startUDP(t, func([]byte) []byte { return nil })
		u2 := startUDP(t, func([]byte) []byte { return nil })
		srv := &Server{Allow: loopAllow(u1.port(), u2.port()), Rate: 0.001, Burst: 3}
		relay := startRelay(t, srv)
		for _, u := range []*udpServer{u1, u2} {
			c, err := relayclient.Dial(context.Background(), relay, dest(u.port()))
			if err != nil {
				t.Fatal(err)
			}
			sendN(t, c, 2)
			c.Close()
			waitFor(t, func() bool { return srv.Counter.sessionsNow.Load() == 0 })
		}
		if u1.got.Load()+u2.got.Load() != 3 || srv.Counter.DroppedRate.Load() != 1 {
			t.Fatalf("servers got %d+%d, counters %v", u1.got.Load(), u2.got.Load(), srv.Counter.Snapshot())
		}
	})
	t.Run("per session", func(t *testing.T) {
		u := startUDP(t, func([]byte) []byte { return nil })
		srv := &Server{Allow: loopAllow(u.port()), PerSession: 3}
		c, err := relayclient.Dial(context.Background(), startRelay(t, srv), dest(u.port()))
		if err != nil {
			t.Fatal(err)
		}
		sendN(t, c, 6)
		c.Close()
		waitFor(t, func() bool { return srv.Counter.sessionsNow.Load() == 0 })
		if u.got.Load() != 3 || srv.Counter.DroppedSession.Load() != 3 {
			t.Fatalf("server got %d, counters %v", u.got.Load(), srv.Counter.Snapshot())
		}
	})
	t.Run("sessions at once", func(t *testing.T) {
		u := startUDP(t, echo)
		srv := &Server{Allow: loopAllow(u.port()), MaxSessions: 1}
		relay := startRelay(t, srv)
		c, err := relayclient.Dial(context.Background(), relay, dest(u.port()))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if c2, err := relayclient.Dial(context.Background(), relay, dest(u.port())); err == nil || !strings.Contains(err.Error(), "busy") {
			if c2 != nil {
				c2.Close()
			}
			t.Fatalf("second session: %v", err)
		}
		c.Close()
		waitFor(t, func() bool { return srv.Counter.sessionsNow.Load() == 0 })
		c3, err := relayclient.Dial(context.Background(), relay, dest(u.port()))
		if err != nil {
			t.Fatalf("after the first ended: %v", err)
		}
		c3.Close()
	})
}

// A session ends after Idle without traffic, and after MaxLife.
func TestRelaySessionTimeouts(t *testing.T) {
	u := startUDP(t, echo)
	srv := &Server{Allow: loopAllow(u.port()), Idle: 100 * time.Millisecond, MaxLife: 400 * time.Millisecond,
		PerSession: 100, DestBurst: 100, Burst: 100}
	relay := startRelay(t, srv)
	c, err := relayclient.Dial(context.Background(), relay, dest(u.port()))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 10)); err == nil {
		t.Fatal("read on an idle session")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("idle session closed after %v", d)
	}
	c, err = relayclient.Dial(context.Background(), relay, dest(u.port()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start = time.Now()
	go func() {
		for range 20 {
			if _, err := c.Write([]byte("k")); err != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	buf := make([]byte, 10)
	for {
		if _, err := c.Read(buf); err != nil {
			break
		}
	}
	if d := time.Since(start); d < 300*time.Millisecond || d > 2*time.Second {
		t.Fatalf("busy session closed after %v, want about 400 ms", d)
	}
}
