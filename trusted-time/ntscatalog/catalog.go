// Package ntscatalog is the built-in list of NTS servers a runner image
// knows. It holds names, operators, the file names of the pinned roots and
// the Nitro routing data, with no build tag and no cgo, so the runner, the
// host agent and signer-admin can all read it. The roots themselves stay in
// trusted-time/nts (roots.go), which checks each file against its pin.
//
// The list is catalog.json, embedded in the binary: it is part of the
// image like the code, and nothing at run time can change it. A test
// parses it and runs Check, so a bad entry fails the build, not a start.
//
// An ID is never removed from the catalog and never reused. A later image
// must still load every setup that names it, so an entry the image no
// longer wants changes its Status instead.
package ntscatalog

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
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
	// Note is free text for reviewers: why the entry is there, the
	// operator's terms. The runner does not read it.
	Note string
}

// Catalog is the built-in list.
type Catalog struct {
	NTS []NTSServer
}

//go:embed catalog.json
var builtinJSON []byte

// Builtin is the catalog of this image, from catalog.json. An image whose
// file does not parse or check does not start; the package test makes
// sure the build never gets that far.
var Builtin = mustParse(builtinJSON)

func mustParse(b []byte) Catalog {
	c, err := Parse(b)
	if err != nil {
		panic(err)
	}
	return c
}

// jsonServer is one entry of catalog.json.
type jsonServer struct {
	ID        string   `json:"id"`
	Host      string   `json:"host"`
	Operator  string   `json:"operator"`
	Roots     []string `json:"roots"`
	NTPNets   []string `json:"ntp_nets"`
	NitroPort uint32   `json:"nitro_port"`
	Status    string   `json:"status"`
	Note      string   `json:"note"`
}

// Parse reads a catalog in the catalog.json format and checks it (Check).
// It refuses unknown fields, keys that repeat or differ in case from the
// format's (encoding/json would take the last one, or match "Status" to
// "status"), anything after the catalog, and a missing or unknown status.
// So what a reviewer reads in the file is what the runner gets.
func Parse(b []byte) (Catalog, error) {
	if err := strictKeys(b); err != nil {
		return Catalog{}, fmt.Errorf("ntscatalog: %w", err)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var raw struct {
		NTS []jsonServer `json:"nts"`
	}
	if err := d.Decode(&raw); err != nil {
		return Catalog{}, fmt.Errorf("ntscatalog: %w", err)
	}
	var c Catalog
	for _, r := range raw.NTS {
		s, err := parseStatus(r.Status)
		if err != nil {
			return Catalog{}, fmt.Errorf("ntscatalog: NTS server %q: %w", r.ID, err)
		}
		c.NTS = append(c.NTS, NTSServer{ID: r.ID, Host: r.Host, Operator: r.Operator, Roots: r.Roots,
			NTPNets: r.NTPNets, NitroPort: r.NitroPort, Status: s, Note: r.Note})
	}
	if err := c.Check(); err != nil {
		return Catalog{}, err
	}
	return c, nil
}

// formatKeys are the keys of catalog.json by place: the top object and
// each entry of "nts".
var formatKeys = map[string][]string{
	"":      {"nts"},
	"nts[]": {"id", "host", "operator", "roots", "ntp_nets", "nitro_port", "status", "note"},
}

// strictKeys walks the whole document once: every object key must appear
// exactly once and be spelled as in formatKeys, and the document must end
// after its one value.
func strictKeys(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	if err := walkValue(d, ""); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("data after the catalog")
	}
	return nil
}

func walkValue(d *json.Decoder, path string) error {
	t, err := d.Token()
	if err != nil {
		return err
	}
	switch t {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.More() {
			kt, err := d.Token()
			if err != nil {
				return err
			}
			k, _ := kt.(string)
			if seen[k] {
				return fmt.Errorf("key %q twice", k)
			}
			seen[k] = true
			if allowed, ok := formatKeys[path]; !ok || !slices.Contains(allowed, k) {
				return fmt.Errorf("unknown key %q", k)
			}
			if err := walkValue(d, path+k); err != nil {
				return err
			}
		}
		_, err = d.Token() // the closing brace
		return err
	case json.Delim('['):
		for d.More() {
			if err := walkValue(d, path+"[]"); err != nil {
				return err
			}
		}
		_, err = d.Token() // the closing bracket
		return err
	}
	return nil
}

func parseStatus(s string) (Status, error) {
	for _, st := range []Status{Active, Retired, Withdrawn} {
		if s == st.String() {
			return st, nil
		}
	}
	return 0, fmt.Errorf("status %q: want active, retired or withdrawn", s)
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

// validID: 1 to MaxLabel of a-z, 0-9, '.' and '-'. Setups will list IDs,
// so an ID holds no separator, space or upper case.
func validID(id string) bool {
	if id == "" || len(id) > MaxLabel {
		return false
	}
	for _, c := range []byte(id) {
		if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

// Check is the catalog's own consistency: valid unique IDs, one
// NTS server per operator, a known status, host and roots set, NTP nets
// that parse, and a distinct Nitro vsock port for every server. Parse runs
// it on every catalog it reads.
func (c *Catalog) Check() error {
	ids := map[string]bool{}
	ops := map[string]string{}
	ports := map[uint32]string{}
	for _, e := range c.NTS {
		if !validID(e.ID) {
			return fmt.Errorf("ntscatalog: ID %q: 1 to %d of a-z, 0-9, '.' and '-'", e.ID, MaxLabel)
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
