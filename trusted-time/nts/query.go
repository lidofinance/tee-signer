//go:build nts

package nts

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/beevik/ntp"
	beevik "github.com/beevik/nts"
)

// Sample is one measurement. Offset is real Unix time minus Monotonic(), in
// nanoseconds; the bound holds at T4 on the Monotonic clock.
type Sample struct {
	Offset         int64
	Delay          time.Duration
	Bound          time.Duration
	T4             int64
	RootDelay      time.Duration
	RootDispersion time.Duration
	Stratum        int
	Precision      int // log2 seconds, as the server states it
	Leap           int
}

// recordConn keeps the last datagram read, so a Kiss-o'-Death the library
// refuses as incomplete can still be read for its code.
type recordConn struct {
	net.Conn
	last []byte
}

func (c *recordConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.last = append(c.last[:0], b[:n]...)
	}
	return n, err
}

// Query sends one NTS-protected NTP request to the association's server
// over UDP and checks the answer. addr must be the association's NTP
// address (KEResult.NTPAddr); dial may be nil. T1 and T4 come from
// Monotonic, so the sample's offset is real time minus Monotonic. A
// Kiss-o'-Death gives a *KissError; a response that is not authentic or
// not ours gives an *Error with CodeNTP. When the cookies ran out the
// library runs NTS-KE again first.
func (a *Association) Query(ctx context.Context, addr string, pivot time.Time, dial DialFunc) (Sample, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sess == nil {
		return Sample{}, errors.New("nts: association closed")
	}
	if addr != a.sess.Address() {
		return Sample{}, fmt.Errorf("nts: query to %s, the association's server is %s", addr, a.sess.Address())
	}
	rc := &recordConn{}
	opts := ntp.QueryOptions{
		Version:       4,
		Timeout:       timeoutOf(ctx),
		GetSystemTime: monoTime,
		Dialer: func(_, remote string) (net.Conn, error) {
			c, err := dialWith(dial, ctx, "udp", remote)
			if err != nil {
				return nil, err
			}
			rc.Conn = c
			return rc, nil
		},
	}
	resp, err := a.sess.QueryWithOptions(&opts)
	switch {
	case err == nil:
	case errors.Is(err, beevik.ErrAuthFailedOnServer):
		// NTS-NAK: the server does not know our cookies (RFC 8915 5.7).
		return Sample{}, &KissError{Code: "NTSN"}
	case errors.Is(err, beevik.ErrMissingExtField), errors.Is(err, beevik.ErrAuthFailedOnClient),
		errors.Is(err, beevik.ErrUniqueIDMismatch), errors.Is(err, beevik.ErrInvalidFormat),
		errors.Is(err, ntp.ErrServerResponseMismatch):
		if code, ok := kissOf(rc.last); ok {
			return Sample{}, &KissError{Code: code}
		}
		return Sample{}, wrapf(CodeNTP, "ntp %s: response refused: %w", addr, err)
	default:
		return Sample{}, fmt.Errorf("ntp %s: %w", addr, err)
	}
	if resp.Stratum == 0 {
		return Sample{}, &KissError{Code: resp.KissCode}
	}
	s, err := measure(resp)
	if err != nil {
		return Sample{}, wrapf(CodeSample, "ntp %s: %w", addr, err)
	}
	return s, nil
}

// kissOf reads a Kiss-o'-Death out of a raw response the library refused:
// mode 4, stratum 0, and a Unique Identifier field (RFC 8915 section 5.7:
// a KoD is taken only with the request's identifier, which the library
// compared before it refused the packet for its missing authenticator).
func kissOf(p []byte) (string, bool) {
	if len(p) < 48 || p[0]&0x07 != 4 || p[1] != 0 {
		return "", false
	}
	code := string(p[12:16])
	for _, c := range code {
		if c < 'A' || c > 'Z' {
			return "", false
		}
	}
	for rest := p[48:]; len(rest) >= 4; {
		typ, n := binary.BigEndian.Uint16(rest), int(binary.BigEndian.Uint16(rest[2:]))
		if n < 4 || n > len(rest) {
			return "", false
		}
		if typ == 0x0104 { // Unique Identifier
			return code, true
		}
		rest = rest[n:]
	}
	return "", false
}
