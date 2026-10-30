//go:build nts

package nts

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/lidofinance/tee-signer/trusted-time/ntscore"
)

// The host operations of the core, in Go: the CSPRNG, the monotonic
// clock, the TLS 1.3 session of NTS-KE with the exporter, and the sockets.
// On the cloud runners the whole process is inside the TEE, so all of them
// are the TEE's; in an OP-TEE trusted application the first three would be
// the application's and only the sockets would stay out here.

type hooks struct {
	dial  DialFunc
	local func() int64
	mu    sync.Mutex
	ctx   context.Context // of the refresh under way
	pools map[[32]byte]*x509.CertPool
}

func newHooks(dial DialFunc, local func() int64) *hooks {
	return &hooks{dial: dial, local: local, ctx: context.Background(), pools: map[[32]byte]*x509.CertPool{}}
}

func (h *hooks) setContext(ctx context.Context) {
	h.mu.Lock()
	h.ctx = ctx
	h.mu.Unlock()
}

func (h *hooks) context() context.Context {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.ctx
}

func (h *hooks) Random(buf []byte) error {
	_, err := rand.Read(buf)
	return err
}

func (h *hooks) Monotonic() int64 {
	if h.local != nil {
		return h.local()
	}
	return Monotonic()
}

// pool is the certificate pool of the roots the core handed over, parsed
// once per distinct set.
func (h *hooks) pool(roots []byte) (*x509.CertPool, error) {
	key := sha256.Sum256(roots)
	h.mu.Lock()
	defer h.mu.Unlock()
	if p, ok := h.pools[key]; ok {
		return p, nil
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(roots) {
		return nil, errors.New("no certificate in the pinned roots")
	}
	h.pools[key] = p
	return p, nil
}

func dialWith(dial DialFunc, ctx context.Context, network, addr string) (net.Conn, error) {
	if dial != nil {
		return dial(ctx, network, addr)
	}
	var d net.Dialer
	// For UDP a connected socket: the kernel drops datagrams from other
	// addresses.
	return d.DialContext(ctx, network, addr)
}

// KeyExchange runs NTS-KE: TLS 1.3 with ALPN ntske/1 over the dialer, the
// request, the response, the keys from the exporter. The certificate is
// checked against validity, the core's time, never the host's clock.
func (h *hooks) KeyExchange(peer int, srv *ntscore.Server, validity time.Time, timeout time.Duration, req, resp []byte) (int, []byte, []byte, time.Duration, error) {
	ctx, cancel := context.WithTimeout(h.context(), timeout)
	defer cancel()
	addr := srv.KEAddr
	if addr == "" {
		addr = net.JoinHostPort(srv.Host, strconv.Itoa(KEPort))
	}
	fail := func(format string, args ...any) (int, []byte, []byte, time.Duration, error) {
		return 0, nil, nil, 0, fmt.Errorf("nts-ke %s: "+format, append([]any{srv.Host}, args...)...)
	}
	pool, err := h.pool(srv.Roots)
	if err != nil {
		return fail("%w", err)
	}
	start := time.Now()
	raw, err := dialWith(h.dial, ctx, "tcp", addr)
	if err != nil {
		return fail("%w", err)
	}
	defer raw.Close()
	// The context's deadline bounds the whole exchange; a cancelled
	// context ends it at once.
	_ = raw.SetDeadline(time.Now().Add(timeoutOf(ctx, timeout)))
	defer context.AfterFunc(ctx, func() { _ = raw.SetDeadline(time.Unix(1, 0)) })()
	conn := tls.Client(raw, &tls.Config{
		ServerName: srv.Host,
		RootCAs:    pool,
		// RFC 8915 section 3: NTS-KE MUST NOT use a TLS version below 1.3.
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		NextProtos: []string{ntscore.ALPN},
		Time:       func() time.Time { return validity },
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		return fail("TLS: %w", err)
	}
	st := conn.ConnectionState()
	// RFC 8915 section 4: the connection is NTS-KE only if the server chose
	// our ALPN ID. Go accepts a server that chose none, so check here.
	if st.NegotiatedProtocol != ntscore.ALPN {
		return fail("server chose ALPN %q, not %q", st.NegotiatedProtocol, ntscore.ALPN)
	}
	if _, err := conn.Write(req); err != nil {
		return fail("write: %w", err)
	}
	n, err := readKEResponse(conn, resp)
	if err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return fail("%w", err)
	}
	c2s, err := st.ExportKeyingMaterial(ntscore.ExporterLabel, ntscore.ExporterContext(false), ntscore.KeyLen)
	if err != nil {
		return fail("export C2S: %w", err)
	}
	s2c, err := st.ExportKeyingMaterial(ntscore.ExporterLabel, ntscore.ExporterContext(true), ntscore.KeyLen)
	if err != nil {
		clear(c2s)
		return fail("export S2C: %w", err)
	}
	return n, c2s, s2c, time.Since(start), nil
}

// readKEResponse reads into buf until End of Message, the cap or the end
// of the stream. The core checks the records; this only knows when they
// are complete.
func readKEResponse(r io.Reader, buf []byte) (int, error) {
	n := 0
	for {
		m, err := r.Read(buf[n:])
		n += m
		if _, done, cerr := ntscore.KEComplete(buf[:n]); cerr != nil {
			return 0, cerr
		} else if done {
			return n, nil
		}
		if n == len(buf) {
			return 0, fmt.Errorf("response over %d octets", len(buf))
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return 0, fmt.Errorf("response ends after %d octets, before End of Message", n)
			}
			return 0, err
		}
	}
}

// UDPOpen is a connected UDP socket to the NTP server.
func (h *hooks) UDPOpen(peer int, addr string, timeout time.Duration) (ntscore.UDPConn, error) {
	ctx := h.context()
	conn, err := dialWith(h.dial, ctx, "udp", addr)
	if err != nil {
		return nil, fmt.Errorf("ntp %s: %w", addr, err)
	}
	u := &udpConn{conn: conn, addr: addr, ctx: ctx}
	// A cancelled context ends a read at once, through the deadline.
	u.stop = context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	return u, nil
}

type udpConn struct {
	conn net.Conn
	addr string
	ctx  context.Context
	stop func() bool
}

func (u *udpConn) Send(p []byte) error {
	if _, err := u.conn.Write(p); err != nil {
		return fmt.Errorf("ntp %s: write: %w", u.addr, err)
	}
	return nil
}

func (u *udpConn) Recv(buf []byte, wait time.Duration) (int, error) {
	if u.ctx.Err() == nil {
		_ = u.conn.SetReadDeadline(time.Now().Add(wait))
	}
	n, err := u.conn.Read(buf)
	if err != nil {
		// A cancelled context ended the read through the deadline; the
		// caller gets the context's error, not an I/O timeout.
		if u.ctx.Err() != nil {
			err = u.ctx.Err()
		}
		return 0, fmt.Errorf("ntp %s: %w", u.addr, err)
	}
	return n, nil
}

func (u *udpConn) Close() {
	u.stop()
	u.conn.Close()
}
