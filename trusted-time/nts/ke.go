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

// Why a response was refused, as the Rust core named them. KeyExchange
// wraps them in an *Error with CodeKE.
var (
	errKETruncated          = errors.New("NTS-KE response ends early, before End of Message")
	errKETooLong            = fmt.Errorf("NTS-KE response longer than %d octets", KEMaxResponseLen)
	errKETooManyRecords     = fmt.Errorf("NTS-KE response has more than %d records", keMaxRecords)
	errKERecordTooLong      = errors.New("NTS-KE record too long")
	errKETrailingData       = errors.New("NTS-KE response has data after End of Message")
	errKEBadEOM             = errors.New("NTS-KE End of Message without critical bit or with a body")
	errKEBadRecordBody      = errors.New("NTS-KE record has a bad body")
	errKECriticalBitMissing = errors.New("NTS-KE record without critical bit")
	errKEUnknownCritical    = errors.New("NTS-KE unknown critical record")
	errKEDuplicateRecord    = errors.New("NTS-KE record sent twice")
	errKEMissingRecord      = errors.New("NTS-KE record missing")
	errKEServerError        = errors.New("NTS-KE server error")
	errKEServerWarning      = errors.New("NTS-KE server warning")
	errKENoCommonProtocol   = errors.New("NTS-KE server offers no common protocol")
	errKEWrongProtocol      = errors.New("NTS-KE server chose a protocol not offered")
	errKENoCommonAEAD       = errors.New("NTS-KE server offers no common AEAD algorithm")
	errKEWrongAEAD          = errors.New("NTS-KE server chose an AEAD not offered")
)

// keResponse is what a parsed NTS-KE response holds.
type keResponse struct {
	cookies [][]byte // the first MaxCookies, in the server's order; at least one
	dropped int      // further valid cookies, not kept
	server  string   // the NTP server named (RFC 8915 section 4.1.7), "" for none
	port    uint16   // the NTP port named (section 4.1.8), 0 for none
}

// keRecord is one record: the critical bit, the type and the body.
type keRecord struct {
	critical bool
	typ      uint16
	body     []byte
}

// readKERecord reads the record at buf[at:]. ok is false if the buffer
// ends inside it; a body over the cap is an error.
func readKERecord(buf []byte, at int) (r keRecord, next int, ok bool, err error) {
	if at+4 > len(buf) {
		return r, at, false, nil
	}
	t := binary.BigEndian.Uint16(buf[at:])
	r.critical, r.typ = t&recCritical != 0, t&^recCritical
	n := int(binary.BigEndian.Uint16(buf[at+2:]))
	if n > keMaxBody {
		return r, at, false, fmt.Errorf("%w: record %d: body of %d octets, at most %d", errKERecordTooLong, r.typ, n, keMaxBody)
	}
	if at+4+n > len(buf) {
		return r, at, false, nil
	}
	r.body = buf[at+4 : at+4+n]
	return r, at + 4 + n, true, nil
}

// keResponseLength walks the records read so far: the length of the
// response once End of Message arrived, or false while it has not. It
// checks only the framing and the caps; parseKEResponse does the rest.
func keResponseLength(buf []byte) (int, bool, error) {
	at, count := 0, 0
	for {
		r, next, ok, err := readKERecord(buf, at)
		if err != nil {
			return 0, false, err
		}
		if !ok {
			if len(buf) >= KEMaxResponseLen {
				return 0, false, errKETooLong
			}
			return 0, false, nil
		}
		count++
		if count > keMaxRecords {
			return 0, false, errKETooManyRecords
		}
		if next > KEMaxResponseLen {
			return 0, false, errKETooLong
		}
		at = next
		if r.typ == recEOM {
			return at, true, nil
		}
	}
}

// ids is the 16-bit IDs of a Next Protocol or AEAD record body, or false
// if the body length is odd.
func ids(body []byte) ([]uint16, bool) {
	if len(body)%2 != 0 {
		return nil, false
	}
	out := make([]uint16, 0, len(body)/2)
	for i := 0; i < len(body); i += 2 {
		out = append(out, binary.BigEndian.Uint16(body[i:]))
	}
	return out, true
}

// serverNameOK is the rule of RFC 8915 section 4.1.7 as the Rust core
// read it: 1 to maxServerName octets of letters, digits, '.', '-' and
// ':'. That covers dotted IPv4, IPv6 text without a zone ID, and A-labels
// of a domain name.
func serverNameOK(b []byte) bool {
	if len(b) < 1 || len(b) > maxServerName {
		return false
	}
	for _, c := range b {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '-', c == ':':
		default:
			return false
		}
	}
	return true
}

// parseKEResponse checks a whole response (RFC 8915 section 4.1).
// Refused: an Error or Warning record, an unknown record with the
// critical bit, a missing Next Protocol, AEAD or New Cookie record, a
// protocol other than NTPv4, an AEAD other than AEAD_AES_SIV_CMAC_256, a
// duplicate of a record that may occur once, a bad body, and anything
// over the caps. Unknown records without the critical bit are skipped
// (section 4).
func parseKEResponse(buf []byte) (*keResponse, error) {
	if len(buf) > KEMaxResponseLen {
		return nil, errKETooLong
	}
	var (
		out            keResponse
		protocol, aead bool
		server, port   bool
		at, count      int
	)
	for {
		r, next, ok, err := readKERecord(buf, at)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errKETruncated
		}
		at = next
		count++
		if count > keMaxRecords {
			return nil, errKETooManyRecords
		}
		badBody := func(format string, args ...any) error {
			return fmt.Errorf("%w: record %d: "+format, append([]any{errKEBadRecordBody, r.typ}, args...)...)
		}
		switch r.typ {
		case recEOM:
			// Section 4.1.1: critical bit set, empty body, final record.
			if !r.critical || len(r.body) != 0 {
				return nil, errKEBadEOM
			}
			if at != len(buf) {
				return nil, fmt.Errorf("%w: %d octets", errKETrailingData, len(buf)-at)
			}
			if !protocol {
				return nil, fmt.Errorf("%w: no Next Protocol record", errKEMissingRecord)
			}
			if !aead {
				return nil, fmt.Errorf("%w: no AEAD Algorithm record", errKEMissingRecord)
			}
			// Section 4.1.6: servers MUST send at least one cookie.
			if len(out.cookies) == 0 {
				return nil, fmt.Errorf("%w: no cookie", errKEMissingRecord)
			}
			return &out, nil
		case recNextProtocol:
			// Section 4.1.2: exactly once, critical bit set, a list of
			// 16-bit IDs that is a subset of what we offered (NTPv4).
			if !r.critical {
				return nil, fmt.Errorf("%w: Next Protocol (record %d)", errKECriticalBitMissing, r.typ)
			}
			if protocol {
				return nil, fmt.Errorf("%w: record %d repeated", errKEDuplicateRecord, r.typ)
			}
			protocol = true
			list, ok := ids(r.body)
			if !ok {
				return nil, badBody("odd length")
			}
			if len(list) == 0 {
				return nil, errKENoCommonProtocol
			}
			for _, id := range list {
				if id != 0 {
					return nil, fmt.Errorf("%w: protocol %d, not NTPv4 (0)", errKEWrongProtocol, id)
				}
			}
		case recError:
			// Section 4.1.3: a 2-octet code. The client discards the keys
			// and does not go on.
			if len(r.body) != 2 {
				return nil, badBody("error code of %d octets", len(r.body))
			}
			return nil, fmt.Errorf("%w %d (RFC 8915 section 4.1.3)", errKEServerError, binary.BigEndian.Uint16(r.body))
		case recWarning:
			// Section 4.1.4: no codes are defined and unknown codes MUST be
			// treated as errors, so every warning is one.
			if len(r.body) != 2 {
				return nil, badBody("warning code of %d octets", len(r.body))
			}
			return nil, fmt.Errorf("%w %d (RFC 8915 section 4.1.4)", errKEServerWarning, binary.BigEndian.Uint16(r.body))
		case recAEAD:
			// Section 4.1.5: exactly once when NTPv4 is negotiated, the
			// critical bit MAY be set, at most one ID in a response, chosen
			// from what we offered.
			if aead {
				return nil, fmt.Errorf("%w: record %d repeated", errKEDuplicateRecord, r.typ)
			}
			aead = true
			list, ok := ids(r.body)
			switch {
			case !ok, len(list) > 1:
				return nil, badBody("%d octets, want one AEAD ID", len(r.body))
			case len(list) == 0:
				return nil, errKENoCommonAEAD
			case list[0] != aeadSIVCMAC256:
				return nil, fmt.Errorf("%w: AEAD %d, not AEAD_AES_SIV_CMAC_256 (%d)", errKEWrongAEAD, list[0], aeadSIVCMAC256)
			}
		case recCookie:
			// Section 4.1.6: opaque to the client; at least one.
			if len(r.body) < 1 || len(r.body) > maxCookieLen {
				return nil, badBody("cookie of %d octets, want 1 to %d", len(r.body), maxCookieLen)
			}
			if len(out.cookies) < MaxCookies {
				out.cookies = append(out.cookies, append([]byte(nil), r.body...))
			} else {
				out.dropped++
			}
		case recServer:
			// Section 4.1.7: at most one; an ASCII IPv4 or IPv6 address (no
			// zone ID) or a domain name.
			if server {
				return nil, fmt.Errorf("%w: record %d repeated", errKEDuplicateRecord, r.typ)
			}
			if !serverNameOK(r.body) {
				return nil, badBody("NTPv4 Server Negotiation: not a host name or address of 1 to %d octets", maxServerName)
			}
			out.server, server = string(r.body), true
		case recPort:
			// Section 4.1.8: a 16-bit port. The RFC sets no count; two
			// ports are ambiguous, so a second one is refused. Port 0 is
			// not a port a server listens on.
			if port {
				return nil, fmt.Errorf("%w: record %d repeated", errKEDuplicateRecord, r.typ)
			}
			if len(r.body) != 2 || binary.BigEndian.Uint16(r.body) == 0 {
				return nil, badBody("NTPv4 Port Negotiation: want a port of 1 to 65535 in 2 octets")
			}
			out.port, port = binary.BigEndian.Uint16(r.body), true
		default:
			// Section 4: an unknown record is ignored without the critical
			// bit and is an error with it.
			if r.critical {
				return nil, fmt.Errorf("%w %d", errKEUnknownCritical, r.typ)
			}
		}
	}
}

// readKEResponse reads until End of Message or the cap. The server may
// close the connection after it (RFC 8915 section 4.1.1: End of Message
// is the final record), so octets after it in the same read are refused.
func readKEResponse(r io.Reader) ([]byte, error) {
	buf := make([]byte, 0, 1024)
	chunk := make([]byte, 4096)
	for {
		n, err := r.Read(chunk)
		buf = append(buf, chunk[:n]...)
		if l, done, perr := keResponseLength(buf); perr != nil {
			return nil, perr
		} else if done {
			if l < len(buf) {
				return nil, fmt.Errorf("%w: %d octets", errKETrailingData, len(buf)-l)
			}
			return buf, nil
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
	// The context's deadline, or exchangeTimeout without one, bounds the
	// whole exchange; a cancelled context ends it at once.
	_ = raw.SetDeadline(time.Now().Add(timeoutOf(ctx)))
	defer context.AfterFunc(ctx, func() { _ = raw.SetDeadline(time.Unix(1, 0)) })()
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
		if ctx.Err() != nil {
			err = ctx.Err()
		}
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
