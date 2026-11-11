//go:build nts

package nts

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"time"
)

// Query sends one NTS-protected NTP request to addr (host:port, from
// KEResult.NTPAddr) over UDP and checks the answer. It reads until a
// response verifies, a Kiss-o'-Death arrives, or ctx ends: a packet the
// library refuses (CodeNTP) may be a forgery, so the real answer can still
// come. pivot only picks the NTP era. dial may be nil.
func (a *Association) Query(ctx context.Context, addr string, pivot time.Time, dial DialFunc) (Sample, error) {
	random := make([]byte, RequestRandomLen)
	if _, err := rand.Read(random); err != nil {
		return Sample{}, err
	}
	packet, req, err := a.NewRequest(random)
	if err != nil {
		return Sample{}, err
	}
	defer req.Close()
	return exchange(ctx, addr, packet, func(p []byte, t1, t4 int64) (Sample, error) { return req.Verify(p, t1, t4, pivot) }, dial)
}

// QueryPlain is Query with plain NTP (RFC 5905), no NTS: no key exchange,
// no cookies, and nothing authenticates the answer. addr is host:port,
// usually port 123. Anyone on the path who sees the request can answer it
// with any time; the answer only has to echo the random transmit timestamp.
func QueryPlain(ctx context.Context, addr string, pivot time.Time, dial DialFunc) (Sample, error) {
	random := make([]byte, PlainRandomLen)
	if _, err := rand.Read(random); err != nil {
		return Sample{}, err
	}
	packet, req, err := NewPlainRequest(random)
	if err != nil {
		return Sample{}, err
	}
	defer req.Close()
	return exchange(ctx, addr, packet, func(p []byte, t1, t4 int64) (Sample, error) { return req.Verify(p, t1, t4, pivot) }, dial)
}

// exchange sends packet to addr over UDP and passes each datagram that
// comes back to verify, with the Monotonic times before the send (t1) and
// after the receipt (t4). It reads on past a packet verify refuses with
// CodeNTP, until one is accepted, a Kiss-o'-Death or another error comes,
// or ctx ends. A packet whose header passes but whose sample fails
// (CodeSample) ends the query: the library marked the request answered
// first. With plain NTP anyone who sees the request can send such a packet
// and so spoil one query; it costs that sample, not a wrong time.
func exchange(ctx context.Context, addr string, packet []byte, verify func(p []byte, t1, t4 int64) (Sample, error), dial DialFunc) (Sample, error) {
	var conn net.Conn
	var err error
	if dial != nil {
		conn, err = dial(ctx, "udp", addr)
	} else {
		var d net.Dialer
		// A connected UDP socket: the kernel drops datagrams from other
		// addresses.
		conn, err = d.DialContext(ctx, "udp", addr)
	}
	if err != nil {
		return Sample{}, fmt.Errorf("ntp %s: %w", addr, err)
	}
	defer conn.Close()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(5 * time.Second)
	}
	_ = conn.SetDeadline(deadline)

	t1 := Monotonic()
	if _, err := conn.Write(packet); err != nil {
		return Sample{}, fmt.Errorf("ntp %s: write: %w", addr, err)
	}
	// One octet over the library's limit, so an oversized answer is seen
	// as such and not cut.
	buf := make([]byte, NTPMaxResponseLen+1)
	var last error
	for {
		n, err := conn.Read(buf)
		t4 := Monotonic()
		if err != nil {
			if last != nil {
				return Sample{}, fmt.Errorf("ntp %s: %w (and earlier: %v)", addr, err, last)
			}
			return Sample{}, fmt.Errorf("ntp %s: %w", addr, err)
		}
		s, err := verify(buf[:n], t1, t4)
		var e *Error
		if errors.As(err, &e) && e.Code == CodeNTP {
			last = err
			continue
		}
		if err != nil {
			return s, fmt.Errorf("ntp %s: %w", addr, err)
		}
		return s, nil
	}
}
