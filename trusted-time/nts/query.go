//go:build nts

package nts

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/beevik/ntp"
)

// The NTS extension fields of one NTPv4 exchange (RFC 8915 section 5, RFC
// 7822), on the NTP library's extension hook. The library builds the
// header with a random transmit timestamp, sends, reads one answer, and
// checks the origin timestamp; this side adds the Unique Identifier, the
// cookie, the placeholders and the authenticator to the request, and checks
// the answer's identifier and authenticator before the library reads its
// header.

// Extension field types (RFC 8915 section 7.6).
const (
	extUniqueID    = 0x0104
	extCookie      = 0x0204
	extPlaceholder = 0x0304
	extAuth        = 0x0404
	uniqueIDLen    = 32
	nonceLen       = 16
	// NTPMaxResponseLen bounds an answer.
	NTPMaxResponseLen = 2048
)

// Sample is one measurement. Offset is real Unix time minus Monotonic(), in
// nanoseconds; the bound holds at T4 on the Monotonic clock.
type Sample struct {
	Offset          int64
	Delay           time.Duration
	Bound           time.Duration
	T4              int64
	RootDelay       time.Duration
	RootDispersion  time.Duration
	Stratum         int
	Precision       int // log2 seconds, as the server states it
	Leap            int
	CookiesReceived int
	CookiesHeld     int
}

var (
	errNotAuthentic = errors.New("authenticator does not verify")
	errKiss         = errors.New("kiss-o'-death")
)

// appendField appends one extension field: type, length, body, zero padding
// to a multiple of 4 and at least 16 octets (RFC 7822 section 7.5).
func appendField(b []byte, typ uint16, body []byte) []byte {
	padded := max((len(body)+3)/4*4, 12)
	b = binary.BigEndian.AppendUint16(b, typ)
	b = binary.BigEndian.AppendUint16(b, uint16(4+padded))
	b = append(b, body...)
	return append(b, make([]byte, padded-len(body))...)
}

// ntsExt is the extension of one query.
type ntsExt struct {
	a        *Association
	uid      []byte
	received int
	kiss     string
}

// ProcessQuery appends the NTS fields to the request the library built.
func (e *ntsExt) ProcessQuery(buf *bytes.Buffer) error {
	a := e.a
	if len(a.cookies) == 0 {
		return &Error{Code: CodeNoCookie, Err: errors.New("no cookie left; run NTS-KE again")}
	}
	cookie := a.cookies[0]
	a.cookies = a.cookies[1:]
	e.uid = make([]byte, uniqueIDLen)
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(e.uid); err != nil {
		return err
	}
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	p := appendField(nil, extUniqueID, e.uid)
	p = appendField(p, extCookie, cookie)
	// Enough placeholders to hold MaxCookies again: the answer carries one
	// cookie for the cookie and one per placeholder (RFC 8915 section 5.7).
	for i := len(a.cookies) + 1; i < MaxCookies; i++ {
		p = appendField(p, extPlaceholder, make([]byte, len(cookie)))
	}
	clear(cookie)
	buf.Write(p)
	// The authenticator covers the header and every field before it.
	ct := a.c2s.Seal([][]byte{buf.Bytes(), nonce}, nil)
	body := binary.BigEndian.AppendUint16(nil, nonceLen)
	body = binary.BigEndian.AppendUint16(body, uint16(len(ct)))
	body = append(body, nonce...)
	body = append(body, ct...)
	buf.Write(appendField(nil, extAuth, body))
	return nil
}

// ProcessResponse checks the answer before the library reads it: our
// Unique Identifier, the authenticator with the S2C key over everything
// before it, the new cookies from the encrypted part. A Kiss-o'-Death
// (stratum 0) is taken with our identifier alone, as RFC 8915 section 5.7
// allows, and stops the query with errKiss.
func (e *ntsExt) ProcessResponse(buf []byte) error {
	if len(buf) < 48 {
		return errors.New("response shorter than an NTP header")
	}
	if len(buf) > NTPMaxResponseLen {
		return fmt.Errorf("response of %d octets, at most %d", len(buf), NTPMaxResponseLen)
	}
	if buf[0]&0x07 != 4 {
		return errors.New("response is not mode 4")
	}
	var uidOK, authenticated bool
	for at := 48; at < len(buf); {
		if at+4 > len(buf) {
			return errors.New("truncated extension field")
		}
		typ := binary.BigEndian.Uint16(buf[at:])
		n := int(binary.BigEndian.Uint16(buf[at+2:]))
		if n < 16 || n%4 != 0 || at+n > len(buf) {
			return fmt.Errorf("extension field %#04x of %d octets", typ, n)
		}
		body := buf[at+4 : at+n]
		switch typ {
		case extUniqueID:
			if uidOK || !bytes.Equal(bytes.TrimRight(body, "\x00"), e.uid) && !bytes.Equal(body, e.uid) {
				return errors.New("Unique Identifier is not this request's")
			}
			uidOK = true
		case extAuth:
			if authenticated || !uidOK {
				return errors.New("authenticator repeated or before the Unique Identifier")
			}
			if len(body) < 4 {
				return errNotAuthentic
			}
			nl, cl := int(binary.BigEndian.Uint16(body)), int(binary.BigEndian.Uint16(body[2:]))
			nlPad := (nl + 3) / 4 * 4
			if nl < 1 || len(body) < 4+nlPad+cl {
				return errNotAuthentic
			}
			nonce, ct := body[4:4+nl], body[4+nlPad:4+nlPad+cl]
			plain, ok := e.a.s2c.Open([][]byte{buf[:at], nonce}, ct)
			if !ok {
				return errNotAuthentic
			}
			if err := e.takeCookies(plain); err != nil {
				return err
			}
			authenticated = true
		}
		at += n
	}
	if !uidOK {
		return errors.New("no Unique Identifier of ours")
	}
	if buf[1] == 0 {
		code := string(buf[12:16])
		for _, c := range code {
			if c < 'A' || c > 'Z' {
				return errors.New("Kiss-o'-Death with a code that is not ASCII letters")
			}
		}
		e.kiss = code
		return errKiss
	}
	if !authenticated {
		return errors.New("no authenticator")
	}
	return nil
}

// takeCookies keeps the cookies of the decrypted part, up to MaxCookies
// held, and refuses more than the placeholders plus one (RFC 8915 5.7).
func (e *ntsExt) takeCookies(plain []byte) error {
	for at := 0; at < len(plain); {
		if at+4 > len(plain) {
			return errors.New("truncated encrypted field")
		}
		typ := binary.BigEndian.Uint16(plain[at:])
		n := int(binary.BigEndian.Uint16(plain[at+2:]))
		if n < 4 || n%4 != 0 || at+n > len(plain) {
			return fmt.Errorf("encrypted field %#04x of %d octets", typ, n)
		}
		if typ == extCookie {
			e.received++
			if e.received > MaxCookies {
				return fmt.Errorf("more than %d cookies in one answer", MaxCookies)
			}
			c := plain[at+4 : at+n]
			if len(c) >= 1 && len(c) <= maxCookieLen && len(e.a.cookies) < MaxCookies {
				e.a.cookies = append(e.a.cookies, append([]byte(nil), c...))
			}
		}
		at += n
	}
	return nil
}

// Query sends one NTS-protected NTP request to addr (KEResult.NTPAddr) over
// UDP and checks the answer. T1 and T4 come from Monotonic, so the sample's
// offset is real time minus Monotonic. A Kiss-o'-Death gives a *KissError;
// an answer that is not authentic or not ours gives an *Error with CodeNTP;
// without a cookie left, an *Error with CodeNoCookie. The first answer is
// taken: a forged datagram fails this query. dial may be nil.
func (a *Association) Query(ctx context.Context, addr string, pivot time.Time, dial DialFunc) (Sample, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return Sample{}, errors.New("nts: association closed")
	}
	ext := &ntsExt{a: a}
	opts := ntp.QueryOptions{
		Version:       4,
		Timeout:       timeoutOf(ctx),
		GetSystemTime: monoTime,
		Extensions:    []ntp.Extension{ext},
		Dialer: func(_, remote string) (net.Conn, error) {
			return dialWith(dial, ctx, "udp", remote)
		},
	}
	resp, err := ntp.QueryWithOptions(addr, opts)
	var e *Error
	switch {
	case ext.kiss != "":
		return Sample{CookiesHeld: len(a.cookies)}, &KissError{Code: ext.kiss}
	case errors.As(err, &e):
		return Sample{}, err
	case err != nil && ext.uid == nil:
		return Sample{}, fmt.Errorf("ntp %s: %w", addr, err)
	case errors.Is(err, ntp.ErrServerResponseMismatch), errors.Is(err, errNotAuthentic):
		return Sample{}, wrapf(CodeNTP, "ntp %s: %w", addr, err)
	case err != nil:
		var ne net.Error
		if errors.As(err, &ne) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return Sample{}, fmt.Errorf("ntp %s: %w", addr, err)
		}
		return Sample{}, wrapf(CodeNTP, "ntp %s: %w", addr, err)
	}
	s, err := measure(resp)
	if err != nil {
		return Sample{}, wrapf(CodeSample, "ntp %s: %w", addr, err)
	}
	s.CookiesReceived, s.CookiesHeld = ext.received, len(a.cookies)
	return s, nil
}
