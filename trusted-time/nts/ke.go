//go:build nts

package nts

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// NTS Key Establishment (RFC 8915 section 4): TLS 1.3 with ALPN ntske/1,
// one request, one response of records, and the two keys from the TLS
// exporter (section 5.1). Untrusted bytes are read with length checks and
// every list has a cap.

const (
	// ALPN is the application protocol of NTS-KE.
	ALPN = "ntske/1"
	// ExporterLabel is the TLS exporter label of the NTS keys.
	ExporterLabel = "EXPORTER-network-time-security"
	// KeyLen is the length of each key: 32 octets for AEAD_AES_SIV_CMAC_256.
	KeyLen = sivKeyLen
	// aeadSIVCMAC256 is the one AEAD this client offers and takes.
	aeadSIVCMAC256 = 15
	// Caps of a response.
	KEMaxResponseLen = 65536 // RFC 8915 section 4: clients SHOULD accept at least 65536
	keMaxRecords     = 64    // a normal response has about 12
	keMaxBody        = 1024
	// MaxCookies is how many cookies the client keeps (RFC 8915 section
	// 4.1.6: servers SHOULD send 8).
	MaxCookies    = 8
	maxCookieLen  = 1024
	maxServerName = 255 // RFC 1035 section 2.3.4
)

// NTS-KE record types (RFC 8915 section 4.1).
const (
	recEOM          = 0
	recNextProtocol = 1
	recError        = 2
	recWarning      = 3
	recAEAD         = 4
	recCookie       = 5
	recServer       = 6
	recPort         = 7
	recCritical     = 0x8000
)

// KERequest is the request this client sends: Next Protocol NTPv4, AEAD 15,
// End of Message, all critical.
func KERequest() []byte {
	return []byte{
		0x80, recNextProtocol, 0, 2, 0, 0,
		0x80, recAEAD, 0, 2, 0, aeadSIVCMAC256,
		0x80, recEOM, 0, 0,
	}
}

// ExporterContext is the exporter context of the C2S (false) or S2C (true)
// key: protocol 0, AEAD 15, the direction (RFC 8915 section 5.1).
func ExporterContext(s2c bool) []byte {
	c := []byte{0, 0, 0, aeadSIVCMAC256, 0}
	if s2c {
		c[4] = 1
	}
	return c
}

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

// Association holds the keys and cookies of one NTS-KE session. Close wipes
// them. The methods are safe for concurrent use.
type Association struct {
	mu      sync.Mutex
	c2s     *sivKey
	s2c     *sivKey
	cookies [][]byte // oldest first; each used once
	closed  bool
	// Server and Port are the NTP server and port the KE server named
	// (RFC 8915 sections 4.1.7, 4.1.8). Server is "" if it named none.
	Server string
	Port   uint16
}

// Close wipes the cookies and drops the keys.
func (a *Association) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, c := range a.cookies {
		clear(c)
	}
	a.cookies, a.c2s, a.s2c, a.closed = nil, nil, nil, true
}

// Cookies is the number of cookies held, 0 after Close.
func (a *Association) Cookies() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.cookies)
}

// keResponse is what a parsed NTS-KE response holds.
type keResponse struct {
	cookies [][]byte
	server  string
	port    uint16
}

// parseKEResponse checks a whole response: the record rules of RFC 8915
// section 4.1, one Next Protocol record naming NTPv4, one AEAD record naming
// AEAD 15, at least one cookie, no Error or Warning, no unknown critical
// record, no repeats, no body over the caps.
func parseKEResponse(buf []byte) (*keResponse, error) {
	var (
		out            keResponse
		protocol, aead bool
		server, port   bool
		records        int
	)
	for len(buf) > 0 {
		if len(buf) < 4 {
			return nil, errors.New("truncated record header")
		}
		records++
		if records > keMaxRecords {
			return nil, fmt.Errorf("more than %d records", keMaxRecords)
		}
		typ := binary.BigEndian.Uint16(buf)
		critical := typ&recCritical != 0
		typ &^= recCritical
		n := int(binary.BigEndian.Uint16(buf[2:]))
		if n > keMaxBody {
			return nil, fmt.Errorf("record %d: body of %d octets, at most %d", typ, n, keMaxBody)
		}
		if len(buf) < 4+n {
			return nil, fmt.Errorf("record %d: truncated body", typ)
		}
		body := buf[4 : 4+n]
		buf = buf[4+n:]
		switch typ {
		case recEOM:
			if !critical || n != 0 {
				return nil, errors.New("End of Message: not critical or not empty")
			}
			if len(buf) != 0 {
				return nil, fmt.Errorf("%d octets after End of Message", len(buf))
			}
			if !protocol {
				return nil, errors.New("no Next Protocol record")
			}
			if !aead {
				return nil, errors.New("no AEAD Algorithm record")
			}
			if len(out.cookies) == 0 {
				return nil, errors.New("no cookie")
			}
			return &out, nil
		case recNextProtocol:
			if !critical || protocol || n != 2 || binary.BigEndian.Uint16(body) != 0 {
				return nil, errors.New("Next Protocol: not critical, repeated, or not NTPv4 alone")
			}
			protocol = true
		case recError:
			if n != 2 {
				return nil, errors.New("Error record: bad body")
			}
			return nil, fmt.Errorf("server error %d (RFC 8915 section 4.1.3)", binary.BigEndian.Uint16(body))
		case recWarning:
			if n != 2 {
				return nil, errors.New("Warning record: bad body")
			}
			return nil, fmt.Errorf("server warning %d (RFC 8915 section 4.1.4)", binary.BigEndian.Uint16(body))
		case recAEAD:
			// RFC 8915 section 4.1.5: the critical bit MAY be set.
			if aead || n != 2 || binary.BigEndian.Uint16(body) != aeadSIVCMAC256 {
				return nil, errors.New("AEAD Algorithm: repeated, or not AEAD_AES_SIV_CMAC_256 alone")
			}
			aead = true
		case recCookie:
			if n < 1 || n > maxCookieLen {
				return nil, fmt.Errorf("cookie of %d octets, want 1 to %d", n, maxCookieLen)
			}
			if len(out.cookies) < MaxCookies {
				out.cookies = append(out.cookies, append([]byte(nil), body...))
			}
		case recServer:
			if server || n < 1 || n > maxServerName {
				return nil, errors.New("NTPv4 Server Negotiation: repeated or bad length")
			}
			for _, c := range body {
				if c < 0x21 || c > 0x7e {
					return nil, errors.New("NTPv4 Server Negotiation: not printable ASCII")
				}
			}
			out.server, server = string(body), true
		case recPort:
			if port || n != 2 {
				return nil, errors.New("NTPv4 Port Negotiation: repeated or bad length")
			}
			out.port, port = binary.BigEndian.Uint16(body), true
		default:
			if critical {
				return nil, fmt.Errorf("unknown critical record %d", typ)
			}
		}
	}
	return nil, errors.New("response ends before End of Message")
}

// readKEResponse reads until End of Message or the cap. The server may
// close the connection after it (RFC 8915 section 4).
func readKEResponse(r io.Reader) ([]byte, error) {
	buf := make([]byte, 0, 1024)
	chunk := make([]byte, 4096)
	for {
		n, err := r.Read(chunk)
		buf = append(buf, chunk[:n]...)
		if l, done, perr := keResponseLength(buf); perr != nil {
			return nil, perr
		} else if done {
			return buf[:l], nil
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

// keResponseLength walks the records read so far: the length of the
// response once End of Message arrived, or false while it has not.
func keResponseLength(buf []byte) (int, bool, error) {
	at := 0
	for at+4 <= len(buf) {
		typ := binary.BigEndian.Uint16(buf[at:]) &^ recCritical
		n := int(binary.BigEndian.Uint16(buf[at+2:]))
		if n > keMaxBody {
			return 0, false, fmt.Errorf("record %d: body of %d octets, at most %d", typ, n, keMaxBody)
		}
		if at+4+n > len(buf) {
			return 0, false, nil
		}
		at += 4 + n
		if typ == recEOM {
			return at, true, nil
		}
	}
	return 0, false, nil
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

// KeyExchange runs NTS-KE: TLS 1.3 with ALPN ntske/1 over cfg.Dial, the
// request, the response, the keys from the exporter.
func KeyExchange(ctx context.Context, cfg KEConfig) (*KEResult, error) {
	if cfg.Time == nil || cfg.Roots == nil || cfg.Host == "" {
		return nil, errors.New("nts: KEConfig needs Host, Roots and Time")
	}
	addr := cfg.Addr
	if addr == "" {
		addr = net.JoinHostPort(cfg.Host, strconv.Itoa(KEPort))
	}
	fail := func(format string, args ...any) (*KEResult, error) {
		return nil, wrapf(CodeKE, "nts-ke %s: "+format, append([]any{cfg.Host}, args...)...)
	}
	start := time.Now()
	raw, err := dialWith(cfg.Dial, ctx, "tcp", addr)
	if err != nil {
		return fail("%w", err)
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
		NextProtos: []string{ALPN},
		Time:       cfg.Time,
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		return fail("TLS: %w", err)
	}
	st := conn.ConnectionState()
	// RFC 8915 section 4: the connection is NTS-KE only if the server chose
	// our ALPN ID. Go accepts a server that chose none, so check here.
	if st.NegotiatedProtocol != ALPN {
		return fail("server chose ALPN %q, not %q", st.NegotiatedProtocol, ALPN)
	}
	if _, err := conn.Write(KERequest()); err != nil {
		return fail("write: %w", err)
	}
	resp, err := readKEResponse(conn)
	if err != nil {
		return fail("%w", err)
	}
	parsed, err := parseKEResponse(resp)
	if err != nil {
		return fail("%w", err)
	}
	c2s, err := st.ExportKeyingMaterial(ExporterLabel, ExporterContext(false), KeyLen)
	if err != nil {
		return fail("export C2S: %w", err)
	}
	s2c, err := st.ExportKeyingMaterial(ExporterLabel, ExporterContext(true), KeyLen)
	if err != nil {
		clear(c2s)
		return fail("export S2C: %w", err)
	}
	a := &Association{cookies: parsed.cookies, Server: parsed.server, Port: parsed.port}
	a.c2s, err = newSIVKey(c2s)
	clear(c2s)
	if err == nil {
		a.s2c, err = newSIVKey(s2c)
	}
	clear(s2c)
	if err != nil {
		return fail("keys: %w", err)
	}
	if a.Port == 0 {
		a.Port = 123
	}
	host := cfg.Host
	if a.Server != "" {
		host = a.Server
	}
	return &KEResult{Assoc: a, NTPAddr: net.JoinHostPort(host, strconv.Itoa(int(a.Port))), Elapsed: time.Since(start)}, nil
}
