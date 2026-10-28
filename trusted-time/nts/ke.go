//go:build nts

package nts

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// KEPort is the TCP port of NTS-KE (RFC 8915 section 4).
const KEPort = 4460

// DialFunc opens a connection. Go owns every socket of NTS: TCP for NTS-KE
// and UDP for NTP. Tests and a vsock proxy plug in here.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

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

func (c *KEConfig) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if c.Dial != nil {
		return c.Dial(ctx, network, addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// KeyExchange runs NTS-KE (RFC 8915 section 4): TLS 1.3 with ALPN ntske/1,
// the request, the response, and the two keys from the TLS exporter
// (section 5.1). The Rust library builds and checks the records.
func KeyExchange(ctx context.Context, cfg KEConfig) (*KEResult, error) {
	if cfg.Time == nil || cfg.Roots == nil || cfg.Host == "" {
		return nil, errors.New("nts: KEConfig needs Host, Roots and Time")
	}
	addr := cfg.Addr
	if addr == "" {
		addr = net.JoinHostPort(cfg.Host, strconv.Itoa(KEPort))
	}
	start := time.Now()
	raw, err := cfg.dial(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("nts-ke %s: %w", cfg.Host, err)
	}
	defer raw.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}
	conn := tls.Client(raw, &tls.Config{
		ServerName: cfg.Host,
		RootCAs:    cfg.Roots,
		// RFC 8915 section 3: NTS-KE MUST NOT use a TLS version below 1.3.
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		NextProtos: []string{ALPN()},
		Time:       cfg.Time,
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("nts-ke %s: TLS: %w", cfg.Host, err)
	}
	st := conn.ConnectionState()
	// RFC 8915 section 4: the connection is NTS-KE only if the server chose
	// our ALPN ID. Go accepts a server that chose none, so check here.
	if st.NegotiatedProtocol != ALPN() {
		return nil, fmt.Errorf("nts-ke %s: server chose ALPN %q, not %q", cfg.Host, st.NegotiatedProtocol, ALPN())
	}
	if _, err := conn.Write(KERequest()); err != nil {
		return nil, fmt.Errorf("nts-ke %s: write: %w", cfg.Host, err)
	}
	resp, err := readKEResponse(conn)
	if err != nil {
		return nil, fmt.Errorf("nts-ke %s: %w", cfg.Host, err)
	}
	c2s, err := st.ExportKeyingMaterial(ExporterLabel(), ExporterContext(false), KeyLen)
	if err != nil {
		return nil, fmt.Errorf("nts-ke %s: export C2S: %w", cfg.Host, err)
	}
	s2c, err := st.ExportKeyingMaterial(ExporterLabel(), ExporterContext(true), KeyLen)
	if err != nil {
		clear(c2s)
		return nil, fmt.Errorf("nts-ke %s: export S2C: %w", cfg.Host, err)
	}
	a, err := NewAssociation(resp, c2s, s2c)
	clear(c2s)
	clear(s2c)
	if err != nil {
		return nil, fmt.Errorf("nts-ke %s: %w", cfg.Host, err)
	}
	host := cfg.Host
	if a.Server != "" {
		host = a.Server
	}
	return &KEResult{Assoc: a, NTPAddr: net.JoinHostPort(host, strconv.Itoa(int(a.Port))), Elapsed: time.Since(start)}, nil
}

// readKEResponse reads until the library sees End of Message. The server
// may close the connection after it (RFC 8915 section 4).
func readKEResponse(r io.Reader) ([]byte, error) {
	buf := make([]byte, 0, 1024)
	chunk := make([]byte, 4096)
	for {
		n, err := r.Read(chunk)
		buf = append(buf, chunk[:n]...)
		if len(buf) > 0 {
			l, done, perr := KEResponseLength(buf)
			if perr != nil {
				return nil, perr
			}
			if done {
				return buf[:l], nil
			}
		}
		if len(buf) > KEMaxResponseLen {
			return nil, fmt.Errorf("response over %d octets", KEMaxResponseLen)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, fmt.Errorf("response ends after %d octets, before End of Message", len(buf))
			}
			return nil, err
		}
	}
}
