//go:build nts

package nts

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// One NTS-protected NTP query over UDP: the request from buildRequest with
// the oldest cookie, the answers checked by pendingRequest.verify until one
// is ours and authentic, the measurement by measure.

// newRequest builds an NTP request with the next cookie and takes that
// cookie out of the jar: each cookie goes out once (RFC 8915 section 5.7).
// random is RequestRandomLen octets from a CSPRNG: the transmit timestamp,
// the Unique Identifier and the nonce. The request asks for enough
// placeholders to hold MaxCookies again after the response, which carries
// one cookie plus one per placeholder (section 5.7), within the size limit
// of maxPlaceholders.
// The cookie comes back as well: the caller wipes it once the request was
// sent, or puts it back with returnCookie if the request never left.
func (a *Association) newRequest(random []byte) ([]byte, *pendingRequest, []byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, nil, nil, errors.New("nts: association closed")
	}
	if len(random) != RequestRandomLen {
		return nil, nil, nil, fmt.Errorf("nts: %d random octets, want %d", len(random), RequestRandomLen)
	}
	if len(a.cookies) == 0 {
		return nil, nil, nil, &Error{Code: CodeNoCookie, Err: errors.New("no cookie left; run NTS-KE again")}
	}
	cookie := a.cookies[0]
	a.cookies = a.cookies[1:]
	in := requestInput{transmit: ntpTimestamp(binary.BigEndian.Uint64(random)), cookie: cookie}
	copy(in.uniqueID[:], random[8:])
	copy(in.nonce[:], random[8+uniqueIDLen:])
	// The jar holds this cookie no more, so the response should bring
	// MaxCookies - held new ones: one for the cookie, the rest for the
	// placeholders.
	in.placeholders = min(max(MaxCookies-1-len(a.cookies), 0), maxPlaceholders(len(cookie)))
	packet, req, err := buildRequest(a.c2s, &in)
	if err != nil {
		a.cookies = append([][]byte{cookie}, a.cookies...)
		return nil, nil, nil, &Error{Code: CodeNTP, Err: err}
	}
	return packet, req, cookie, nil
}

// returnCookie puts a cookie that never left the process back at the front
// of the jar: once per cookie (RFC 8915 section 5.7) counts cookies that
// were sent.
func (a *Association) returnCookie(cookie []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		clear(cookie)
		return
	}
	a.cookies = append([][]byte{cookie}, a.cookies...)
}

// keepCookies adds the cookies of an authentic response to the jar, newest
// last, and drops the oldest beyond MaxCookies. It returns how many are
// held.
func (a *Association) keepCookies(cookies [][]byte) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return 0
	}
	a.cookies = append(a.cookies, cookies...)
	for len(a.cookies) > MaxCookies {
		clear(a.cookies[0])
		a.cookies = a.cookies[1:]
	}
	return len(a.cookies)
}

// Query sends one NTS-protected NTP request to addr (host:port, from
// KEResult.NTPAddr) over UDP and checks the answers. It reads until an
// answer is ours and authentic, a Kiss-o'-Death with our Unique Identifier
// arrives, or ctx ends: a datagram that fails the check may be a forgery
// (one sent before the real answer, say), so it is dropped and the real
// answer can still come. The last refusal is in the error if the time runs
// out. T1 and T4 come from Monotonic, so the sample's offset is real time
// minus Monotonic; pivot only picks the NTP era. A Kiss-o'-Death gives a
// *KissError; a measurement the RFC 5905 checks refuse gives an *Error with
// CodeSample; without a cookie left, an *Error with CodeNoCookie. dial may
// be nil.
func (a *Association) Query(ctx context.Context, addr string, pivot time.Time, dial DialFunc) (Sample, error) {
	random := make([]byte, RequestRandomLen)
	if _, err := rand.Read(random); err != nil {
		return Sample{}, err
	}
	packet, req, cookie, err := a.newRequest(random)
	if err != nil {
		return Sample{}, err
	}
	a.mu.Lock()
	s2c := a.s2c
	a.mu.Unlock()
	if s2c == nil {
		return Sample{}, errors.New("nts: association closed")
	}
	conn, err := dialWith(dial, ctx, "udp", addr)
	if err != nil {
		a.returnCookie(cookie)
		return Sample{}, fmt.Errorf("ntp %s: %w", addr, err)
	}
	defer conn.Close()
	// The context's deadline, or exchangeTimeout without one, bounds the
	// exchange; a cancelled context ends the read loop at once.
	deadline := time.Now().Add(timeoutOf(ctx))
	_ = conn.SetDeadline(deadline)
	defer context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })()

	t1 := Monotonic()
	if _, err := conn.Write(packet); err != nil {
		a.returnCookie(cookie)
		return Sample{}, fmt.Errorf("ntp %s: write: %w", addr, err)
	}
	clear(cookie)
	// One octet over the limit, so an oversized answer is seen as such and
	// not cut.
	buf := make([]byte, NTPMaxResponseLen+1)
	var last error
	var kiss *KissError
	for {
		n, err := conn.Read(buf)
		t4 := Monotonic()
		if err != nil {
			if kiss != nil {
				// Nothing authentic followed the Kiss-o'-Death: it stands.
				return Sample{CookiesHeld: a.Cookies()}, kiss
			}
			// A cancelled context ended the read through the deadline; the
			// caller gets the context's error, not an I/O timeout.
			if ctx.Err() != nil {
				err = ctx.Err()
			}
			if last != nil {
				return Sample{}, fmt.Errorf("ntp %s: %w (and earlier: %w)", addr, err, last)
			}
			return Sample{}, fmt.Errorf("ntp %s: %w", addr, err)
		}
		v, err := req.verify(s2c, buf[:n])
		if err != nil {
			last = wrapf(CodeNTP, "%w", err)
			continue
		}
		if v.kiss != "" {
			// A Kiss-o'-Death does not end the query: a forged one may come
			// before the real answer. The query reads on for kissGrace, or
			// to its deadline if that is sooner, and reports the KoD only
			// if nothing authentic follows.
			kiss = &KissError{Code: v.kiss, Authentic: v.kissAuthentic}
			if g := time.Now().Add(kissGrace); g.Before(deadline) {
				_ = conn.SetDeadline(g)
			}
			continue
		}
		// The cookies of an authentic response are kept even if the
		// measurement is refused: they are good for the next one.
		held := a.keepCookies(v.time.cookies)
		s, err := measure(v.time, t1, t4, pivot.UnixNano())
		if err != nil {
			return Sample{}, wrapf(CodeSample, "ntp %s: %w", addr, err)
		}
		s.CookiesHeld = held
		return s, nil
	}
}
