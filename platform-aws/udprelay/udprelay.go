// Package udprelay carries UDP datagrams over a stream connection. An AWS
// Nitro enclave has no network, so the NTS clock's NTP queries go over vsock
// to a relay on the parent instance, which sends them on as UDP and sends the
// answers back (cmd/udprelay). NTS-KE is TCP and goes through vsock-proxy.
//
// The relay is not trusted, like the rest of the parent. Every NTS answer is
// authenticated with keys from NTS-KE (AEAD_AES_SIV_CMAC_256, RFC 8915
// section 5.6), so the relay can delay or drop a datagram but not forge one.
// A delay widens the error bound of that sample (delay/2) and cannot move
// the time outside it. The allowlist and the rate limits are for the parent's
// sake: they keep the relay from being an open UDP proxy for whatever runs
// in the enclave.
//
// Protocol, one destination per stream connection:
//
//	frame   = length (u16, big endian) || payload, 1 <= length <= MaxFrame
//	client -> relay   one frame: the destination, "host:port" in ASCII
//	relay -> client   one frame: status, 0x00 accepted, or 0x01 || reason
//	then both ways    frames of one UDP datagram each
//
// A frame of length 0 or over the limit ends the connection. The relay sends
// a datagram from the client only to the destination it accepted, on a
// connected UDP socket, so it only passes on answers from that address.
package udprelay

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/signer-protocol/transport"
)

const (
	// MaxDatagram is the largest datagram either side sends. The NTS
	// library builds requests of at most 1280 octets and accepts answers of
	// at most 2048 (nts/README.md, caps).
	MaxDatagram = 2048
	// MaxDest is the longest destination frame: a DNS name (255) and a port.
	MaxDest = 262
	// maxReason caps the reason text of a refusal.
	maxReason = 200
)

var errFrame = errors.New("udprelay: bad frame length")

// writeFrame writes one frame in one Write call.
func writeFrame(w io.Writer, p []byte) error {
	if len(p) == 0 || len(p) > 0xffff {
		return errFrame
	}
	buf := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(buf, uint16(len(p)))
	copy(buf[2:], p)
	_, err := w.Write(buf)
	return err
}

// readFrame reads one frame of 1 to max octets into buf (len(buf) >= max).
func readFrame(r io.Reader, buf []byte, max int) ([]byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(h[:]))
	if n == 0 || n > max {
		return nil, fmt.Errorf("%w: %d (1 to %d)", errFrame, n, max)
	}
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// printable keeps the printable ASCII of an untrusted text, cut to n octets.
func printable(b []byte, n int) string {
	var s strings.Builder
	for _, c := range b {
		if s.Len() >= n {
			break
		}
		if c >= 0x20 && c < 0x7f {
			s.WriteByte(c)
		} else {
			s.WriteByte('?')
		}
	}
	return s.String()
}

// Conn is a client connection to one destination through the relay. Each
// Write sends one datagram and each Read returns one, as on a connected UDP
// socket. A Read into a buffer shorter than the datagram returns the first
// len(b) octets, as UDP does.
type Conn struct {
	net.Conn
	dest string
	buf  []byte
}

// Dest is the destination the relay accepted.
func (c *Conn) Dest() string { return c.dest }

func (c *Conn) Write(p []byte) (int, error) {
	if len(p) == 0 || len(p) > MaxDatagram {
		return 0, fmt.Errorf("udprelay: datagram of %d octets (1 to %d)", len(p), MaxDatagram)
	}
	if err := writeFrame(c.Conn, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *Conn) Read(b []byte) (int, error) {
	p, err := readFrame(c.Conn, c.buf, MaxDatagram)
	if err != nil {
		return 0, err
	}
	return copy(b, p), nil
}

// Dial connects to the relay at relay and asks for dest (host:port). It
// returns once the relay has accepted dest, or the relay's reason.
func Dial(ctx context.Context, relay transport.Addr, dest string) (*Conn, error) {
	if len(dest) == 0 || len(dest) > MaxDest {
		return nil, fmt.Errorf("udprelay: destination of %d octets", len(dest))
	}
	c, err := transport.Dial(ctx, relay)
	if err != nil {
		return nil, fmt.Errorf("udprelay: dial %s: %w", relay, err)
	}
	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(5 * time.Second)
	}
	_ = c.SetDeadline(dl)
	buf := make([]byte, MaxDatagram)
	if err := writeFrame(c, []byte(dest)); err != nil {
		c.Close()
		return nil, fmt.Errorf("udprelay: %s: %w", dest, err)
	}
	st, err := readFrame(c, buf, 1+maxReason)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("udprelay: %s: no status from the relay: %w", dest, err)
	}
	if st[0] != 0 {
		c.Close()
		return nil, fmt.Errorf("udprelay: relay refused %s: %s", dest, printable(st[1:], maxReason))
	}
	_ = c.SetDeadline(time.Time{})
	return &Conn{Conn: c, dest: dest, buf: buf}, nil
}
