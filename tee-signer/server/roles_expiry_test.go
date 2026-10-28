package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	"github.com/lidofinance/tee-signer/tee-signer/attls"
)

// movingClock is a trusted clock the test sets or breaks.
type movingClock struct {
	mu  sync.Mutex
	t   time.Time
	err error
}

func (c *movingClock) Now() (time.Time, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t, c.err
}
func (c *movingClock) Source() string { return "test" }
func (c *movingClock) Trusted() bool  { return true }
func (c *movingClock) set(t time.Time) {
	c.mu.Lock()
	c.t, c.err = t, nil
	c.mu.Unlock()
}
func (c *movingClock) fail(err error) {
	c.mu.Lock()
	c.err = err
	c.mu.Unlock()
}

// dialClock is dial with the server's TLS configuration on clk, as the
// runner has it (attls.ServerConfig on the platform clock).
func dialClock(t *testing.T, s *Server, rootPEM []byte, cert tls.Certificate, clk *movingClock) *conn {
	t.Helper()
	c, err := dialClockErr(t, s, rootPEM, cert, clk)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// dialClockErr is dialClock that returns a failed client handshake.
func dialClockErr(t *testing.T, s *Server, rootPEM []byte, cert tls.Certificate, clk *movingClock) (*conn, error) {
	t.Helper()
	cfg, _, err := attls.ServerConfig(rootPEM, clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	s.ClientCAs = cfg.ClientCAs
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		if c, err := l.Accept(); err == nil {
			s.handleConn(context.Background(), tls.Server(c, cfg))
		}
	}()
	peer, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	c := tls.Client(peer, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil }})
	if err := c.Handshake(); err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	return &conn{t: t, c: c}, nil
}

// ATTEST-ROLES-01: a connection made while the client certificate was
// valid loses its role once the trusted clock passes the certificate's
// NotAfter. The next request is refused and the connection closes; a
// SIGN gets no partial.
func TestExpiredCertificateLosesItsOpenConnection(t *testing.T) {
	root := newTestCA(t, nil, nil, nil)
	s := roleServer(t)
	clk := &movingClock{t: time.Now()}
	s.Platform.Clock = clk
	cert := root.leaf(t, clientAuth, nil) // NotAfter: now + 1 h
	c := dialClock(t, s, root.pem(), cert, clk)
	if _, err := c.call(wire.TypeHealth, nil); err != nil {
		t.Fatalf("HEALTH while the certificate is valid: %v", err)
	}

	clk.set(time.Now().Add(2 * time.Hour))
	sign := append(bytes.Repeat([]byte{0xb0}, 48), make([]byte, 1+32+64)...)
	if _, err := c.call(wire.TypeSign, sign); refusedWith(err) != backend.StatusForbidden || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("SIGN on a connection whose certificate expired: %v, want FORBIDDEN for the expiry", err)
	}
	if _, err := c.call(wire.TypeHealth, nil); err == nil {
		t.Fatal("the connection stays open after its certificate expired")
	}
}

// The same when trusted time fails on an open connection: no request but
// HEALTH is served without a reading to check the certificate against.
// HEALTH shows the clock state: no reading (clock_unix 0), not ready.
func TestOpenConnectionNeedsTrustedTime(t *testing.T) {
	root := newTestCA(t, nil, nil, nil)
	s := roleServer(t)
	clk := &movingClock{t: time.Now()}
	s.Platform.Clock = clk
	c := dialClock(t, s, root.pem(), root.leaf(t, clientAuth, nil), clk)
	if _, err := c.call(wire.TypeHealth, nil); err != nil {
		t.Fatalf("HEALTH: %v", err)
	}
	clk.fail(errors.New("test clock: no quorum"))
	b, err := c.call(wire.TypeHealth, nil)
	if err != nil {
		t.Fatalf("HEALTH on an open connection without trusted time: %v", err)
	}
	wantNoClock(t, b)
	sign := append(bytes.Repeat([]byte{0xb0}, 48), make([]byte, 1+32+64)...)
	if _, err := c.call(wire.TypeSign, sign); refusedWith(err) != backend.StatusForbidden || !strings.Contains(err.Error(), "no trusted time") {
		t.Fatalf("SIGN without trusted time: %v, want FORBIDDEN for the clock", err)
	}
	if _, err := c.call(wire.TypeHealth, nil); err == nil {
		t.Fatal("the connection stays open after a refused SIGN without trusted time")
	}
}
