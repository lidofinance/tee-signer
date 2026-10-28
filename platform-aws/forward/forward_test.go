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
	cliTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "dirk"},
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

// With the enclave down, the client is closed and the forwarder lives on.
func TestDialFailureClosesTheClient(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := l.Addr().String()
	l.Close() // nothing listens there any more
	addr := startForwarder(t, dead, nil, nil)
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
	addr := startForwarder(t, l.Addr().String(), func(f *Forwarder) { f.MaxConns = 1 }, nil)
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
