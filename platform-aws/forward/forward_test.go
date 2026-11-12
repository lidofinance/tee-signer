package forward

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/tee-signer/attls"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// recorder keeps every byte that passes through a connection.
type recorder struct {
	net.Conn
	mu  *sync.Mutex
	buf *bytes.Buffer
}

func (r recorder) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	r.mu.Lock()
	r.buf.Write(p[:n])
	r.mu.Unlock()
	return n, err
}

func (r recorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	r.buf.Write(p)
	r.mu.Unlock()
	return r.Conn.Write(p)
}

// CloseWrite passes the half-close on to the connection underneath.
func (r recorder) CloseWrite() error { return r.Conn.(closeWriter).CloseWrite() }

// startForwarder forwards 127.0.0.1:0 to target and returns its address.
// wrap, if set, wraps the connection to the target (a recorder).
func startForwarder(t *testing.T, target string, mod func(*Forwarder), wrap func(net.Conn) net.Conn) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &Forwarder{
		Dial: func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			c, err := d.DialContext(ctx, "tcp", target)
			if err == nil && wrap != nil {
				c = wrap(c)
			}
			return c, err
		},
		Log: quiet,
	}
	if mod != nil {
		mod(f)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.Serve(ctx, l); close(done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Serve did not return after its context ended")
		}
	})
	return l.Addr().String()
}

func listen(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

// A client with a certificate from the pinned CA does mutual TLS 1.3 with
// the target through the forwarder. The forwarder has no certificate, key
// or CA, and the bytes it copies do not contain the payload.
func TestMutualTLSRunsEndToEndThroughTheForwarder(t *testing.T) {
	now := time.Now()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	cliKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cliTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "client"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	cliDER, err := x509.CreateCertificate(rand.Reader, cliTmpl, caCert, &cliKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	// The target is the runner's TLS configuration, as in the enclave.
	cfg, keyHash, err := attls.ServerConfig(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), nil)
	if err != nil {
		t.Fatal(err)
	}
	tl := tls.NewListener(listen(t), cfg)
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 64)
				n, err := c.Read(buf)
				if err == nil {
					c.Write(buf[:n])
				}
			}()
		}
	}()

	var mu sync.Mutex
	seen := &bytes.Buffer{}
	addr := startForwarder(t, tl.Addr().String(), nil, func(c net.Conn) net.Conn { return recorder{c, &mu, seen} })

	conn, err := tls.Dial("tcp", addr, &tls.Config{
		MinVersion: tls.VersionTLS13, InsecureSkipVerify: true,
		Certificates: []tls.Certificate{{Certificate: [][]byte{cliDER}, PrivateKey: cliKey}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := []byte("a request the forwarder must not be able to read")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("echo through the forwarder: %q, %v", got, err)
	}
	// The key the client sees through the forwarder is the target's.
	h := sha256.Sum256(conn.ConnectionState().PeerCertificates[0].RawSubjectPublicKeyInfo)
	if !bytes.Equal(h[:], keyHash) {
		t.Fatalf("the client saw TLS key %x, the target's is %x", h, keyHash)
	}
	mu.Lock()
	defer mu.Unlock()
	if seen.Len() == 0 {
		t.Fatal("the recorder saw no bytes")
	}
	if bytes.Contains(seen.Bytes(), payload) {
		t.Fatal("the forwarder carried the payload in the clear")
	}
}

// A client that connects without TLS to a TLS target gets what the target
// gives it. The forwarder does not answer for the target.
func TestForwarderAddsNothing(t *testing.T) {
	l := listen(t)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.WriteString(c, "from the target\n")
		io.Copy(io.Discard, c)
	}()
	addr := startForwarder(t, l.Addr().String(), nil, nil)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b := make([]byte, 16)
	n, err := io.ReadFull(c, b)
	if err != nil || string(b[:n]) != "from the target\n" {
		t.Fatalf("got %q, %v", b[:n], err)
	}
}

// Large transfers arrive intact in both directions.
func TestCopiesBothWaysIntact(t *testing.T) {
	l := listen(t)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// Echo: read everything, send it back.
		io.Copy(c, c)
	}()
	addr := startForwarder(t, l.Addr().String(), nil, nil)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	data := make([]byte, 6<<20)
	rand.Read(data)
	go func() {
		c.Write(data)
		c.(*net.TCPConn).CloseWrite()
	}()
	_ = c.SetReadDeadline(time.Now().Add(20 * time.Second))
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(got) != sha256.Sum256(data) {
		t.Fatalf("echoed %d bytes, sent %d, content differs", len(got), len(data))
	}
}

// A half-close of the client reaches the target, which can still answer.
// Only this direction passes a half-close on.
func TestHalfClosePassesThrough(t *testing.T) {
	l := listen(t)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		b, _ := io.ReadAll(c) // returns at the client's half-close
		io.WriteString(c, "got "+string(b))
	}()
	addr := startForwarder(t, l.Addr().String(), nil, nil)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "request")
	c.(*net.TCPConn).CloseWrite()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "got request" {
		t.Fatalf("got %q, %v", got, err)
	}
}

// When the target closes, the forwarder closes the client and frees the
// slot, even if the client stays idle and never closes. The target sends one
// byte, so a connection that got a slot reads it and a refused one does not.
func TestTargetCloseFreesTheSlot(t *testing.T) {
	l := listen(t)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			io.WriteString(c, "x")
			c.Close()
		}
	}()
	addr := startForwarder(t, l.Addr().String(), func(f *Forwarder) { f.MaxConns = 1 }, nil)
	deadline := time.Now().Add(5 * time.Second)
	for served := 0; served < 3; {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close() // idle until the test ends
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		got, err := io.ReadAll(c)
		if err != nil {
			t.Fatalf("the client was not closed: %v", err)
		}
		if string(got) == "x" {
			served++
			continue
		}
		if time.Now().After(deadline) {
			t.Fatalf("served %d connections, then the slot stayed held", served)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// With the enclave down, the client is closed and the forwarder lives on.
func TestDialFailureClosesTheClient(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := l.Addr().String()
	l.Close() // nothing listens there any more
	var f *Forwarder
	addr := startForwarder(t, dead, func(x *Forwarder) { f = x }, nil)
	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Read(make([]byte, 1)); err == nil || errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("attempt %d: the client was not closed: %v", i, err)
		}
		c.Close()
	}
	if s := f.Stats(); s.Accepted != 3 || s.DialFailures != 3 || s.RefusedMaxConns != 0 || s.RefusedPerSource != 0 {
		t.Fatalf("stats %+v, want 3 accepted, 3 dial failures", s)
	}
}

func TestMaxConns(t *testing.T) {
	l := listen(t)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(io.Discard, c) }()
		}
	}()
	var f *Forwarder
	addr := startForwarder(t, l.Addr().String(), func(x *Forwarder) { x.MaxConns = 1; f = x }, nil)
	first, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	// Make sure the forwarder holds the first connection before the second
	// arrives: it forwards one byte.
	io.WriteString(first, "x")
	time.Sleep(200 * time.Millisecond)
	second, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_ = second.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := second.Read(make([]byte, 1)); err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("the second connection was not closed: %v", err)
	}
	if s := f.Stats(); s.Accepted != 2 || s.Open != 1 || s.RefusedMaxConns != 1 || s.DialFailures != 0 {
		t.Fatalf("stats %+v, want 2 accepted, 1 open, 1 refused", s)
	}
	// The first one still works, and a slot frees when it closes.
	first.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			_, err = c.Read(make([]byte, 1))
			c.Close()
			if ne, ok := err.(net.Error); ok && ne.Timeout() { // held open: it got a slot
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("no slot came free after the first connection closed")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// One source IP address holds at most MaxConnsPerSource connections
// within their handshake window (the default window here, 15 s, outlasts
// the test): its next one is closed at once, a connection from another
// address still gets a slot, and the count gives back when a connection
// closes. The enclave sees every connection come from the parent's vsock
// address, so this is the only cap per peer on Nitro.
func TestMaxConnsPerSource(t *testing.T) {
	l := listen(t)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(io.Discard, c) }()
		}
	}()
	var f *Forwarder
	addr := startForwarder(t, l.Addr().String(), func(x *Forwarder) { x.MaxConnsPerSource = 2; f = x }, nil)
	// held reports whether a connection got a slot: a read runs into its
	// deadline instead of the close.
	held := func(c net.Conn) bool {
		_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		_, err := c.Read(make([]byte, 1))
		ne, ok := err.(net.Error)
		return ok && ne.Timeout()
	}
	var first []net.Conn
	for i := range 2 {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		io.WriteString(c, "x")
		if !held(c) {
			t.Fatalf("connection %d from one address within the cap of 2 was closed", i+1)
		}
		first = append(first, c)
	}
	third, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	if held(third) {
		t.Fatal("connection 3 from one address stays open over the cap of 2")
	}
	if s := f.Stats(); s.RefusedPerSource != 1 || s.RefusedMaxConns != 0 || s.Open != 2 {
		t.Fatalf("stats %+v, want 1 refused per source, 2 open", s)
	}
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2)}}
	other, err := d.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	io.WriteString(other, "x")
	if !held(other) {
		t.Fatal("a connection from another address was closed")
	}
	first[0].Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		ok := held(c)
		c.Close()
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the count per source did not give back after a connection closed")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestServeClosesConnectionsWhenTheContextEnds(t *testing.T) {
	l := listen(t)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(io.Discard, c) }()
		}
	}()
	fl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &Forwarder{Dial: func(ctx context.Context) (net.Conn, error) { return net.Dial("tcp", l.Addr().String()) }, Log: quiet}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.Serve(ctx, fl) }()
	c, err := net.Dial("tcp", fl.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "x")
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("the connection stayed open")
	}
}

// A signing client pool of 16 from one address that handshaked and
// works, then more connections from the same address: a second pool
// behind the same NAT, a tool on the same host, a rolling restart. The cap
// per source counts a connection only through its handshake window, as
// the runner's cap per address counts handshakes in progress, so the pool
// stays open and the later connections are served too.
func TestEstablishedConnectionsLeaveTheCapPerSource(t *testing.T) {
	l := listen(t)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }() // echo
		}
	}()
	// Defaults, 16 per source, with a short window: the runner's deadline
	// does not apply to the echo target.
	const window = 200 * time.Millisecond
	addr := startForwarder(t, l.Addr().String(), func(f *Forwarder) { f.HandshakeWindow = window }, nil)
	// exchange sends a byte and waits for its echo: the connection got a
	// slot and the target answers on it.
	exchange := func(c net.Conn) error {
		if _, err := io.WriteString(c, "x"); err != nil {
			return err
		}
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		b := make([]byte, 1)
		if _, err := io.ReadFull(c, b); err != nil {
			return err
		}
		if b[0] != 'x' {
			return errors.New("echoed " + string(b))
		}
		return nil
	}
	var pool []net.Conn
	for i := range 16 {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if err := exchange(c); err != nil {
			t.Fatalf("pool connection %d: %v", i+1, err)
		}
		pool = append(pool, c)
	}
	time.Sleep(2 * window) // the handshake window of every pool connection has passed
	for i := range 4 {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if err := exchange(c); err != nil {
			t.Fatalf("connection %d from one address, after 16 established ones: %v", 16+i+1, err)
		}
	}
	for i, c := range pool {
		if err := exchange(c); err != nil {
			t.Fatalf("pool connection %d after the later ones: %v", i+1, err)
		}
	}
}

// Peers from one address that connect and send nothing still hold at most
// MaxConnsPerSource slots: the next one from that address is closed at
// once. This is what the cap is for: on vsock the enclave cannot tell
// outside peers apart.
func TestSilentPeersStayCappedPerSource(t *testing.T) {
	l := listen(t)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(io.Discard, c) }()
		}
	}()
	addr := startForwarder(t, l.Addr().String(), nil, nil) // defaults: 16 per source
	held := func(c net.Conn) bool {
		_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		_, err := c.Read(make([]byte, 1))
		ne, ok := err.(net.Error)
		return ok && ne.Timeout()
	}
	for i := range 16 {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if !held(c) {
			t.Fatalf("silent connection %d from one address within the cap of 16 was closed", i+1)
		}
	}
	extra, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	if held(extra) {
		t.Fatal("silent connection 17 from one address stays open over the cap of 16")
	}
}

// lockedBuffer is a log sink the forwarder's goroutines can share.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) count(s string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.Count(b.buf.String(), s)
}

// A flood of refused connections or failed dials writes one log line per
// kind, not one per connection: one outside peer must not fill the
// parent's log. The counts stay exact in Stats.
func TestRefusalsAndDialFailuresLogOncePerFlood(t *testing.T) {
	const n = 20
	// flood dials addr n times; the forwarder closes each connection.
	flood := func(t *testing.T, addr string) {
		for range n {
			c, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := c.Read(make([]byte, 1)); err == nil {
				t.Fatal("a connection over the bound got data")
			}
			c.Close()
		}
	}
	// holdOne opens a connection that takes a slot and keeps it.
	holdOne := func(t *testing.T, addr string) {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		// The forwarded byte shows the forwarder holds the connection
		// before the flood starts.
		if _, err := io.WriteString(c, "x"); err != nil {
			t.Fatal(err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	alive := func(t *testing.T) string {
		l := listen(t)
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go func() { defer c.Close(); io.Copy(io.Discard, c) }()
			}
		}()
		return l.Addr().String()
	}
	for _, tc := range []struct {
		name   string
		mod    func(*Forwarder)
		hold   bool
		target func(*testing.T) string
		line   string
		count  func(Stats) uint64
	}{
		{"dial failure", nil, false, func(t *testing.T) string {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			l.Close() // nothing listens there any more
			return l.Addr().String()
		}, "dial failed", func(s Stats) uint64 { return s.DialFailures }},
		{"max conns", func(f *Forwarder) { f.MaxConns = 1 }, true, alive,
			"too many connections, closing", func(s Stats) uint64 { return s.RefusedMaxConns }},
		{"max conns per source", func(f *Forwarder) { f.MaxConnsPerSource = 1 }, true, alive,
			"too many connections in their handshake window", func(s Stats) uint64 { return s.RefusedPerSource }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := &lockedBuffer{}
			var f *Forwarder
			addr := startForwarder(t, tc.target(t), func(x *Forwarder) {
				x.Log = slog.New(slog.NewTextHandler(logs, nil))
				if tc.mod != nil {
					tc.mod(x)
				}
				f = x
			}, nil)
			if tc.hold {
				holdOne(t, addr)
			}
			flood(t, addr)
			if got := tc.count(f.Stats()); got != n {
				t.Fatalf("stats %+v, want %d", f.Stats(), n)
			}
			if got := logs.count(tc.line); got != 1 {
				t.Fatalf("%d log lines for %d, want 1", got, n)
			}
		})
	}
}
