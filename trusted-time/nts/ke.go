//go:build nts

package nts

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	beevik "github.com/beevik/nts"
)

// KEConfig is one NTS-KE server.
type KEConfig struct {
	// Host is the server's DNS name: the TLS server name, and the address
	// unless Addr is set.
	Host string
	// Addr is the host:port to dial. Empty: Host and KEPort.
	Addr string
	// Roots are the CAs this server's certificate must chain to.
	Roots *x509.CertPool
	// Time is the clock that checks certificate validity. Required: the
	// runner passes its anchored clock, not the host's clock.
	Time func() time.Time
	// Dial opens the TCP connection. Nil: net.Dialer.
	Dial DialFunc
}

// KEResult is what one NTS-KE session gives.
type KEResult struct {
	Assoc *Association
	// NTPAddr is host:port of the NTP server: the one the KE server named,
	// else Host, with the negotiated port or 123 (RFC 8915 4.1.7, 4.1.8).
	NTPAddr string
	// Elapsed is the time from dial to the end of the response.
	Elapsed time.Duration
}

// Association holds the keys and cookies of one NTS-KE session, inside the
// library's session. When its cookies run out the library runs NTS-KE
// again by itself, with the same configuration. Close drops it. The
// methods are safe for concurrent use.
type Association struct {
	mu   sync.Mutex
	sess *beevik.Session
	// Server and Port are the NTP server and port the KE server named
	// (RFC 8915 sections 4.1.7, 4.1.8), or the KE host and 123.
	Server string
	Port   uint16
}

// Close drops the association.
func (a *Association) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sess = nil
}

// KeyExchange runs NTS-KE (RFC 8915 section 4): TLS 1.3 with ALPN ntske/1,
// the request, the response, and the two keys from the TLS exporter
// (section 5.1), all in the library. This side owns the socket, the roots
// and the clock the certificate is checked against.
func KeyExchange(ctx context.Context, cfg KEConfig) (*KEResult, error) {
	if cfg.Time == nil || cfg.Roots == nil || cfg.Host == "" {
		return nil, errors.New("nts: KEConfig needs Host, Roots and Time")
	}
	addr := cfg.Addr
	if addr == "" {
		addr = net.JoinHostPort(cfg.Host, strconv.Itoa(KEPort))
	}
	first := ctx
	dialer := func(network, addr string, tc *tls.Config) (*tls.Conn, error) {
		// The first exchange runs under the caller's context; the ones the
		// library runs later, when its cookies ran out, under their own
		// timeout.
		dctx, cancel := context.WithTimeout(context.Background(), exchangeTimeout)
		if first != nil && first.Err() == nil {
			cancel()
			dctx, cancel = context.WithTimeout(first, timeoutOf(first))
		}
		defer cancel()
		first = nil
		raw, err := dialWith(cfg.Dial, dctx, network, addr)
		if err != nil {
			return nil, err
		}
		if dl, ok := dctx.Deadline(); ok {
			_ = raw.SetDeadline(dl)
		}
		conn := tls.Client(raw, tc)
		if err := conn.HandshakeContext(dctx); err != nil {
			raw.Close()
			return nil, err
		}
		return conn, nil
	}
	start := time.Now()
	sess, err := beevik.NewSessionWithOptions(addr, &beevik.SessionOptions{
		TLSConfig: &tls.Config{
			ServerName: cfg.Host,
			RootCAs:    cfg.Roots,
			// RFC 8915 section 3: NTS-KE MUST NOT use a TLS version below 1.3.
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
			Time:       cfg.Time,
		},
		Timeout: timeoutOf(ctx),
		Dialer:  dialer,
	})
	if err != nil {
		return nil, wrapf(CodeKE, "nts-ke %s: %w", cfg.Host, err)
	}
	host, portStr, err := net.SplitHostPort(sess.Address())
	if err != nil {
		return nil, wrapf(CodeKE, "nts-ke %s: NTP address %q: %w", cfg.Host, sess.Address(), err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, wrapf(CodeKE, "nts-ke %s: NTP port %q: %w", cfg.Host, portStr, err)
	}
	a := &Association{sess: sess, Server: host, Port: uint16(port)}
	return &KEResult{Assoc: a, NTPAddr: sess.Address(), Elapsed: time.Since(start)}, nil
}
