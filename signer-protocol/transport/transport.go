// Package transport parses the address strings used by the remote backend
// and the runner, and dials or listens on them:
//
//	tcp:HOST:PORT     e.g. tcp:127.0.0.1:7100
//	unix:PATH         e.g. unix:/run/signer/runner.sock
//	vsock:CID:PORT    e.g. vsock:16:7100 (dial an enclave from its parent)
//	vsock:any:PORT    listen on every local CID (inside an enclave)
//
// A vsock address always parses. Dialing or listening on one works only in
// a binary built with the platform_aws tag (vsock.go): a Nitro enclave and
// its parent instance are the only users of vsock, and the others do not
// carry the vsock library. Everywhere else it fails with ErrNoVsock.
package transport

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
)

// ErrNoVsock is the error for a vsock address in a binary without vsock.
var ErrNoVsock = errors.New("transport: vsock is not built into this binary")

// vsockDial and vsockListen are set by vsock.go (build tag platform_aws).
var (
	vsockDial   func(cid, port uint32) (net.Conn, error)
	vsockListen func(cid, port uint32) (net.Listener, error)
)

// HasVsock says whether this binary can dial and listen on vsock addresses.
func HasVsock() bool { return vsockDial != nil && vsockListen != nil }

// Addr is a parsed address.
type Addr struct {
	Network string // tcp, unix or vsock
	Address string // host:port or path, for tcp and unix
	CID     uint32 // vsock only; math.MaxUint32 means any
	Port    uint32 // vsock only
}

// AnyCID is VMADDR_CID_ANY.
const AnyCID = math.MaxUint32

func (a Addr) String() string {
	if a.Network == "vsock" {
		cid := strconv.FormatUint(uint64(a.CID), 10)
		if a.CID == AnyCID {
			cid = "any"
		}
		return fmt.Sprintf("vsock:%s:%d", cid, a.Port)
	}
	return a.Network + ":" + a.Address
}

// Parse parses an address string.
func Parse(s string) (Addr, error) {
	network, rest, ok := strings.Cut(s, ":")
	if !ok || rest == "" {
		return Addr{}, fmt.Errorf("transport: %q: want tcp:HOST:PORT, unix:PATH or vsock:CID:PORT", s)
	}
	switch network {
	case "tcp":
		if _, _, err := net.SplitHostPort(rest); err != nil {
			return Addr{}, fmt.Errorf("transport: %q: %w", s, err)
		}
		return Addr{Network: "tcp", Address: rest}, nil
	case "unix":
		return Addr{Network: "unix", Address: rest}, nil
	case "vsock":
		cidStr, portStr, ok := strings.Cut(rest, ":")
		if !ok {
			return Addr{}, fmt.Errorf("transport: %q: want vsock:CID:PORT", s)
		}
		cid := uint64(AnyCID)
		if cidStr != "any" {
			var err error
			if cid, err = strconv.ParseUint(cidStr, 10, 32); err != nil {
				return Addr{}, fmt.Errorf("transport: %q: bad CID", s)
			}
		}
		port, err := strconv.ParseUint(portStr, 10, 32)
		if err != nil {
			return Addr{}, fmt.Errorf("transport: %q: bad port", s)
		}
		return Addr{Network: "vsock", CID: uint32(cid), Port: uint32(port)}, nil
	}
	return Addr{}, fmt.Errorf("transport: %q: unknown network %q", s, network)
}

// Dial connects to a.
func Dial(ctx context.Context, a Addr) (net.Conn, error) {
	if a.Network == "vsock" {
		if a.CID == AnyCID {
			return nil, fmt.Errorf("transport: cannot dial vsock CID any")
		}
		if vsockDial == nil {
			return nil, ErrNoVsock
		}
		// The vsock dial has no context; the caller's deadline applies to I/O.
		return vsockDial(a.CID, a.Port)
	}
	var d net.Dialer
	return d.DialContext(ctx, a.Network, a.Address)
}

// Listen listens on a. A stale unix socket file is removed first.
func Listen(a Addr) (net.Listener, error) {
	switch a.Network {
	case "vsock":
		if vsockListen == nil {
			return nil, ErrNoVsock
		}
		// AnyCID binds VMADDR_CID_ANY, the usual choice inside an enclave.
		return vsockListen(a.CID, a.Port)
	case "unix":
		if fi, err := os.Lstat(a.Address); err == nil && fi.Mode()&os.ModeSocket != 0 {
			_ = os.Remove(a.Address)
		}
	}
	return net.Listen(a.Network, a.Address)
}
