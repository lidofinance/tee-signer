// Package ntscatalog is the built-in list of NTS servers a runner image
// knows. It holds names, operators, the file names of the pinned roots and
// the Nitro routing data, with no build tag and no cgo, so the runner, the
// host agent and signer-admin can all read it. The roots themselves stay in
// trusted-time/nts (roots.go), which checks each file against its pin.
//
// An ID is never removed from the catalog and never reused. A later image
// must still load every setup that names it, so an entry the image no
// longer wants changes its Status instead.
package ntscatalog

import (
	"fmt"
	"net/netip"
	"strings"
)

// Status of a catalog entry.
type Status uint8

const (
	// Active: new setups may name it, the runner dials it.
	Active Status = iota
	// Retired: new setups may not name it, a runner whose setup names it
	// still dials it. For an operator that stops its service: dialing it
	// costs a failed query, not a refusal.
	Retired
	// Withdrawn: the runner does not dial it. For an operator or a root
	// the image no longer trusts. Only a new image withdraws an entry.
	Withdrawn
)

func (s Status) String() string {
	switch s {
	case Active:
		return "active"
	case Retired:
		return "retired"
	case Withdrawn:
		return "withdrawn"
	}
	return fmt.Sprintf("status(%d)", uint8(s))
}

// NTSServer is one NTS-KE server.
type NTSServer struct {
	ID       string   // named in setups; stable, lower case
	Host     string   // TLS name and NTS-KE host, port 4460
	Operator string   // who runs it; the quorum counts one server per operator
	Roots    []string // files under trusted-time/nts/roots
	// NTPNets are address blocks of the NTP servers the NTS-KE server
	// names that its own name does not resolve to (Netnod). The Nitro UDP
	// relay allows them.
	NTPNets   []string
	NitroPort uint32 // vsock port of its vsock-proxy route on the Nitro parent
	Status    Status
}

// Catalog is the built-in list.
type Catalog struct {
	NTS []NTSServer
}

// Builtin is the catalog of this image: the four operators the runner has
// dialed so far. PTB runs ptbtime1, 2 and 3; one of them is listed, since
// the quorum needs distinct operators.
var Builtin = Catalog{
	NTS: []NTSServer{
		{ID: "cloudflare", Host: "time.cloudflare.com", Operator: "cloudflare", Roots: []string{"sslcom-root-ecc.pem"}, NitroPort: 8005},
		{ID: "netnod", Host: "nts.netnod.se", Operator: "netnod", Roots: []string{"isrg-root-x1.pem", "isrg-root-x2.pem"},
			NTPNets: []string{"194.58.200.0/21"}, NitroPort: 8006},
		{ID: "ptb", Host: "ptbtime1.ptb.de", Operator: "ptb", Roots: []string{"isrg-root-x1.pem", "isrg-root-x2.pem"}, NitroPort: 8007},
		{ID: "time.nl", Host: "ntppool1.time.nl", Operator: "time.nl", Roots: []string{"isrg-root-x1.pem", "isrg-root-x2.pem"}, NitroPort: 8008},
	},
}

// MaxLabel is the longest ID and operator label, in octets. The quorum in
// the Rust core refuses longer operator labels (MAX_OPERATOR_LEN).
const MaxLabel = 32

// Dialed are the NTS servers a runner dials: every entry that is not
// withdrawn, in catalog order.
func (c *Catalog) Dialed() []NTSServer {
	var out []NTSServer
	for _, e := range c.NTS {
		if e.Status != Withdrawn {
			out = append(out, e)
		}
	}
	return out
}

// Check is the catalog's own consistency: IDs unique and lower case, one
// NTS server per operator, a known status, host and roots set, NTP nets
// that parse, and a distinct Nitro vsock port for every server. A test runs it on Builtin.
func (c *Catalog) Check() error {
	ids := map[string]bool{}
	ops := map[string]string{}
	ports := map[uint32]string{}
	for _, e := range c.NTS {
		if e.ID == "" || e.ID != strings.ToLower(e.ID) || len(e.ID) > MaxLabel {
			return fmt.Errorf("ntscatalog: ID %q: 1 to %d lower-case octets", e.ID, MaxLabel)
		}
		if ids[e.ID] {
			return fmt.Errorf("ntscatalog: ID %q twice", e.ID)
		}
		ids[e.ID] = true
		if e.Host == "" || len(e.Roots) == 0 || e.Operator == "" || len(e.Operator) > MaxLabel {
			return fmt.Errorf("ntscatalog: NTS server %s: host, roots and an operator of 1 to %d octets required", e.ID, MaxLabel)
		}
		if e.Status > Withdrawn {
			return fmt.Errorf("ntscatalog: NTS server %s: %v", e.ID, e.Status)
		}
		if prev, dup := ops[e.Operator]; dup {
			return fmt.Errorf("ntscatalog: NTS servers %s and %s share operator %s", prev, e.ID, e.Operator)
		}
		ops[e.Operator] = e.ID
		for _, n := range e.NTPNets {
			if p, err := netip.ParsePrefix(n); err != nil || p != p.Masked() {
				return fmt.Errorf("ntscatalog: NTS server %s: NTP net %q is not a masked CIDR prefix", e.ID, n)
			}
		}
		if e.NitroPort == 0 {
			return fmt.Errorf("ntscatalog: NTS server %s has no vsock port", e.ID)
		}
		if prev, dup := ports[e.NitroPort]; dup {
			return fmt.Errorf("ntscatalog: vsock port %d for %s and %s", e.NitroPort, prev, e.ID)
		}
		ports[e.NitroPort] = e.ID
	}
	return nil
}
