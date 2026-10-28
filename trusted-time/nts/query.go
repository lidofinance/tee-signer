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

	var conn net.Conn
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
		s, err := req.Verify(buf[:n], t1, t4, pivot)
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
