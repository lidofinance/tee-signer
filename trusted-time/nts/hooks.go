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

	ntscore "github.com/lidofinance/tee-signer/trusted-time/ntscore/go"
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
	ctxs  map[int]context.Context // of each peer's poll under way
	pools map[[32]byte]*x509.CertPool
	// resolve: look the NTP host up once per key exchange and dial the
	// address (Config.ResolveNTP). addrs holds, per peer, the address the
	// core named and what is dialed for it.
	resolve bool
	addrs   map[int][2]string
	warn    func(msg string, args ...any)
}

func newHooks(dial DialFunc, local func() int64) *hooks {
	return &hooks{dial: dial, local: local, ctxs: map[int]context.Context{}, pools: map[[32]byte]*x509.CertPool{}, addrs: map[int][2]string{}}
}

// SetContext binds peer's operations to ctx for the poll under way; a nil
// ctx unbinds. Polls of different peers run under their own contexts.
func (h *hooks) SetContext(peer int, ctx context.Context) {
	h.mu.Lock()
	if ctx == nil {
		delete(h.ctxs, peer)
	} else {
		h.ctxs[peer] = ctx
	}
	h.mu.Unlock()
}

func (h *hooks) context(peer int) context.Context {
	h.mu.Lock()
	defer h.mu.Unlock()
	if ctx, ok := h.ctxs[peer]; ok {
		return ctx
	}
	return context.Background()
}

// cancelled marks err as the caller's doing when the context of peer's
// poll has ended: the caller cut the exchange (the deadline of a tick, a
// shutdown), not the server or the exchange's own timeout. The core then
// counts no loss and no failure and backs nothing off
// (ntscore.ErrHostCancelled). It cannot change a time: it only says who
// ended an exchange that gave nothing.
func (h *hooks) cancelled(peer int, err error) error {
	if err != nil && h.context(peer).Err() != nil && !errors.Is(err, ntscore.ErrHostCancelled) {
		return fmt.Errorf("%w: %w", ntscore.ErrHostCancelled, err)
	}
	return err
}

// forget drops the address resolved for peer; forgetAll, for every peer.
func (h *hooks) forget(peer int) {
	h.mu.Lock()
	delete(h.addrs, peer)
	h.mu.Unlock()
}

func (h *hooks) forgetAll() {
	h.mu.Lock()
	clear(h.addrs)
	h.mu.Unlock()
}

// resolved is the address to dial for addr (host:port), the NTP address
// the core named for peer: the host looked up once and kept until the
// peer's next key exchange (or forget), so that a short query timeout does
// not include a DNS lookup. If the lookup fails addr itself is kept, and
// each dial looks it up. An IPv4 address when the name has one: the
// platforms' egress rules and the Nitro relay are built for IPv4, and a
// host with IPv6 may sort an IPv6 address first (localhost is ::1 on some
// CI runners). The address is only where the datagrams go: the core checks
// every answer whatever it is.
func (h *hooks) resolved(ctx context.Context, peer int, addr string) string {
	h.mu.Lock()
	kept, ok := h.addrs[peer]
	h.mu.Unlock()
	if ok && kept[0] == addr {
		return kept[1]
	}
	to := addr
	if host, port, err := net.SplitHostPort(addr); err == nil && net.ParseIP(host) == nil {
		lctx, cancel := context.WithTimeout(ctx, ExchangeTimeout)
		ips, err := net.DefaultResolver.LookupNetIP(lctx, "ip", host)
		cancel()
		if ctx.Err() != nil {
			// The caller's deadline cut the lookup: nothing is kept.
			return addr
		}
		if err != nil || len(ips) == 0 {
			if h.warn != nil {
				h.warn("nts: no address for the NTP host; each query looks it up", "host", host, "err", err)
			}
		} else {
			ip := ips[0].Unmap()
			for _, a := range ips {
				if a.Unmap().Is4() {
					ip = a.Unmap()
					break
				}
			}
			to = net.JoinHostPort(ip.String(), port)
		}
	}
	h.mu.Lock()
	h.addrs[peer] = [2]string{addr, to}
	h.mu.Unlock()
	return to
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
	ctx, cancel := context.WithTimeout(h.context(peer), timeout)
	defer cancel()
	addr := srv.KEAddr
	if addr == "" {
		addr = net.JoinHostPort(srv.Host, strconv.Itoa(KEPort))
	}
	fail := func(format string, args ...any) (int, []byte, []byte, time.Duration, error) {
		return 0, nil, nil, 0, h.cancelled(peer, fmt.Errorf("nts-ke %s: "+format, append([]any{srv.Host}, args...)...))
	}
	// The server names its NTP host in this exchange: what was resolved
	// for the last one goes.
	h.forget(peer)
	// The core refuses before it asks with no time. crypto/x509 would read
	// a zero time as the host's clock (it replaces a zero CurrentTime with
	// time.Now), so a time at or before the epoch is refused here too,
	// before the dial.
	if validity.Unix() < 1 {
		return fail("no trusted time to check the certificate (%v)", validity)
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
	dl, _ := ctx.Deadline()
	_ = raw.SetDeadline(dl)
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
		if m == 0 && err == nil {
			// Discouraged by io.Reader; crypto/tls never does it. Refused
			// rather than spun on.
			return 0, io.ErrNoProgress
		}
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

// UDPOpen is a connected UDP socket to the NTP server. timeout bounds the
// whole exchange on it: the dial, the send and every read, so that a host
// that accepts a connection and never moves (a relay that stops reading,
// a resolver that hangs) costs one query, not the clock.
func (h *hooks) UDPOpen(peer int, addr string, timeout time.Duration) (ntscore.UDPConn, error) {
	parent := h.context(peer)
	if h.resolve {
		// Before the timeout starts: the lookup has its own.
		addr = h.resolved(parent, peer, addr)
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	conn, err := dialWith(h.dial, ctx, "udp", addr)
	if err != nil {
		cancel()
		return nil, h.cancelled(peer, fmt.Errorf("ntp %s: %w", addr, err))
	}
	dl, _ := ctx.Deadline()
	_ = conn.SetDeadline(dl)
	u := &udpConn{conn: conn, addr: addr, ctx: ctx, cancel: cancel, cut: func(err error) error { return h.cancelled(peer, err) }}
	// A cancelled or expired context ends a read or a write at once,
	// through the deadline.
	u.stop = context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	return u, nil
}

type udpConn struct {
	conn   net.Conn
	addr   string
	ctx    context.Context
	cancel context.CancelFunc
	stop   func() bool
	cut    func(error) error // hooks.cancelled for this peer
}

func (u *udpConn) Send(p []byte) error {
	if _, err := u.conn.Write(p); err != nil {
		return u.cut(fmt.Errorf("ntp %s: write: %w", u.addr, err))
	}
	return nil
}

func (u *udpConn) Recv(buf []byte, wait time.Duration) (int, error) {
	_ = u.conn.SetReadDeadline(time.Now().Add(wait))
	// Set before the check: a context that ended between the two would
	// otherwise have its past deadline overwritten and wait the full wait.
	if u.ctx.Err() != nil {
		_ = u.conn.SetReadDeadline(time.Unix(1, 0))
	}
	n, err := u.conn.Read(buf)
	if err != nil {
		// A cancelled context ended the read through the deadline; the
		// caller gets the context's error, not an I/O timeout.
		if u.ctx.Err() != nil {
			err = u.ctx.Err()
		}
		return 0, u.cut(fmt.Errorf("ntp %s: %w", u.addr, err))
	}
	return n, nil
}

func (u *udpConn) Close() {
	u.stop()
	u.cancel()
	u.conn.Close()
}
