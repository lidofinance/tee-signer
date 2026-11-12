package udprelay

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lidofinance/tee-signer/trusted-time/ntscatalog"
)

// Allowlist decides which destinations the relay sends to. A destination is
// host:port as the NTS-KE server named it (RFC 8915 sections 4.1.7 and
// 4.1.8): a DNS name or an IP address, and a port.
//
//   - The port must be one of Ports (NTP 123; Netnod negotiates 4123).
//   - A name must be one of Names, exactly (case and a trailing dot aside).
//     The relay resolves it itself and sends to the first public address
//     (IPv4 first), or one in Nets.
//   - An address must lie in one of Nets, or be a public address that one
//     of Names resolves to now (cached for TTL).
//   - Public: global unicast, not private, not in notPublic (shared space,
//     NAT64, 6to4 and other special blocks). A DNS answer that points a
//     name at a private or special address (the VPC's IPv4 space, the
//     parent's private address, loopback) gets no datagram. The relay
//     cannot tell a public address of this VPC or of the parent (an
//     Elastic IP, the VPC's global IPv6 block) from an NTP server's: a DNS
//     answer that names one is sent to. Such an answer comes from the
//     parent's resolver, which the host runs; the host can send datagrams
//     there itself, and NTS requests carry nothing a receiver can use.
//
// Nothing else goes out: no other name is resolved, no other address is
// reached. Netnod's NTS-KE servers name NTP servers by address, and those
// addresses are not among the ones nts.netnod.se resolves to, so they
// need Nets.
type Allowlist struct {
	Names []string
	Nets  []netip.Prefix
	Ports []uint16
	// Lookup resolves a name. Nil: net.DefaultResolver.
	Lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	// TTL of a resolved name. 0: 5 minutes.
	TTL time.Duration

	mu    sync.Mutex
	cache map[string]resolved
}

type resolved struct {
	addrs []netip.Addr
	err   error
	at    time.Time
}

// DefaultNames are the NTP host names of every NTS-KE host a runner of this
// image may dial (trusted-time/ntscatalog Endpoints and NTPHosts): each
// host's own name, which the client uses when NTS-KE names none, and the
// names NTS-KE servers name instead (Meta: time.meta.com), and the hosts
// plain NTP asks in their place (Netnod: ntp.se, FER: ntp.hr). The parent cannot
// see which servers the enclave's command chose, so it allows all of them.
var DefaultNames = ntscatalog.NTPHosts(ntscatalog.Builtin.Endpoints())

// DefaultPorts: NTP, and the port Netnod's NTS-KE negotiates.
var DefaultPorts = []uint16{123, 4123}

// DefaultNets hold NTP servers that NTS-KE servers name by address outside
// their own names' addresses (Netnod: each IPv4 address of nts.netnod.se
// names another NTP server in 194.58.203.0 to 194.58.207.255, port 4123).
var DefaultNets = defaultNets()

func defaultNets() []netip.Prefix {
	var out []netip.Prefix
	for _, n := range ntscatalog.NTPNets(ntscatalog.Builtin.Endpoints()) {
		out = append(out, netip.MustParsePrefix(n)) // ntscatalog.Check parsed them
	}
	return out
}

// Default is the allowlist of the NTS servers a runner of this image may dial.
func Default() *Allowlist {
	return &Allowlist{Names: slices.Clone(DefaultNames), Nets: slices.Clone(DefaultNets), Ports: slices.Clone(DefaultPorts)}
}

// ParsePorts parses "123,4123".
func ParsePorts(s string) ([]uint16, error) {
	var out []uint16
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		p, err := strconv.ParseUint(f, 10, 16)
		if err != nil || p == 0 {
			return nil, fmt.Errorf("udprelay: port %q", f)
		}
		out = append(out, uint16(p))
	}
	return out, nil
}

// ParseNets parses "194.58.200.0/21,2a01:3f7::/32".
func ParseNets(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		p, err := netip.ParsePrefix(f)
		if err != nil {
			return nil, fmt.Errorf("udprelay: network %q: %w", f, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// ParseNames parses "a.example,b.example".
func ParseNames(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = canonName(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func canonName(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

// refusal is a destination the allowlist does not let through.
type refusal struct{ reason string }

func (r refusal) Error() string { return r.reason }

func (a *Allowlist) lookup(ctx context.Context, name string) ([]netip.Addr, error) {
	ttl := a.TTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	a.mu.Lock()
	if r, ok := a.cache[name]; ok {
		// A failed lookup is kept for a tenth of the TTL, so a down
		// resolver is not asked once per datagram.
		if age := time.Since(r.at); (r.err == nil && age < ttl) || (r.err != nil && age < ttl/10) {
			a.mu.Unlock()
			return r.addrs, r.err
		}
	}
	a.mu.Unlock()
	look := a.Lookup
	if look == nil {
		look = func(ctx context.Context, h string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", h)
		}
	}
	addrs, err := look(ctx, name)
	for i := range addrs {
		addrs[i] = addrs[i].Unmap()
	}
	a.mu.Lock()
	if a.cache == nil {
		a.cache = map[string]resolved{}
	}
	a.cache[name] = resolved{addrs: addrs, err: err, at: time.Now()}
	a.mu.Unlock()
	return addrs, err
}

// usable: an address a datagram may go to.
func usable(ip netip.Addr) bool {
	return ip.IsValid() && !ip.IsUnspecified() && !ip.IsMulticast() && !ip.IsLinkLocalUnicast()
}

// notPublic are blocks a DNS answer must not point a name at, besides
// loopback and private: shared space (RFC 6598), "this network", IETF
// protocol assignments, benchmarking, reserved, and the IPv6 forms that
// carry an IPv4 address (NAT64, 6to4), which could reach a private one.
var notPublic = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2002::/16"),
}

// public: a global unicast address that is not private (RFC 1918,
// fc00::/7) and in no block of notPublic.
func public(ip netip.Addr) bool {
	if !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	for _, p := range notPublic {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

func (a *Allowlist) inNets(ip netip.Addr) bool {
	for _, n := range a.Nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// nameAddr: an address a name of the allowlist resolved to that a datagram
// may go to. It must be public unless Nets holds it: a DNS answer that
// points a catalog name at a private address of the parent or the VPC must
// not turn the relay toward them (the tests allow loopback with Nets).
// Public addresses of the VPC are not known here (see Allowlist).
func (a *Allowlist) nameAddr(ip netip.Addr) bool {
	return usable(ip) && (public(ip) || a.inNets(ip))
}

// Check returns the UDP address for dest, or why dest is refused (an error
// whose text is the reason sent to the client).
func (a *Allowlist) Check(ctx context.Context, dest string) (netip.AddrPort, error) {
	host, ps, err := net.SplitHostPort(dest)
	if err != nil {
		return netip.AddrPort{}, refusal{"not host:port"}
	}
	p, err := strconv.ParseUint(ps, 10, 16)
	if err != nil || !slices.Contains(a.Ports, uint16(p)) {
		return netip.AddrPort{}, refusal{"port " + ps + " not allowed"}
	}
	port := uint16(p)
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if ip.Zone() != "" || !usable(ip) {
			return netip.AddrPort{}, refusal{"address " + host + " not allowed"}
		}
		if a.inNets(ip) {
			return netip.AddrPortFrom(ip, port), nil
		}
		// Before any lookup: an address that is not public can never pass,
		// so it costs no DNS query of the allowed names.
		if !public(ip) {
			return netip.AddrPort{}, refusal{"address " + host + " not in the allowlist"}
		}
		for _, name := range a.Names {
			addrs, err := a.lookup(ctx, name)
			if err == nil && slices.Contains(addrs, ip) {
				return netip.AddrPortFrom(ip, port), nil
			}
		}
		return netip.AddrPort{}, refusal{"address " + host + " not in the allowlist"}
	}
	name := canonName(host)
	if !slices.Contains(a.Names, name) {
		return netip.AddrPort{}, refusal{"name " + host + " not in the allowlist"}
	}
	addrs, err := a.lookup(ctx, name)
	if err != nil {
		return netip.AddrPort{}, refusal{"cannot resolve " + name}
	}
	// IPv4 first: the parent may have no IPv6 route.
	for _, v4 := range []bool{true, false} {
		for _, ip := range addrs {
			if ip.Is4() == v4 && a.nameAddr(ip) {
				return netip.AddrPortFrom(ip, port), nil
			}
		}
	}
	return netip.AddrPort{}, refusal{"no usable address for " + name}
}
