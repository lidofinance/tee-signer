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
	"strings"
)

// Status of a catalog entry.
type Status uint8

const (
	// Active: new setups may name it; the runner dials it when it is
	// Default or a setup names it.
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
	// Terms says whether a signer may use the server as the operator's
	// published terms stand (Open), or whoever writes the setup must ask
	// the operator first (Ask). The image never decides that for a user.
	Terms Terms
	// Regions are where the server was measured close enough to count:
	// RegionGlobal (anycast), or some of RegionEU, RegionNA, RegionSA,
	// RegionAPAC. See RegionRule.
	Regions []string
	// TermsURL is the operator's page the Terms were read from. Required
	// for Open; an Ask entry may have none (terms not public).
	TermsURL string
	// Alt are other hosts of the same operator (anycast, more sites).
	// They count as the same operator. This image does not dial them.
	Alt []AltHost
	// Default: the runner dials it while setups cannot name servers yet.
	Default bool
	// Note is free text for reviewers: why the entry is there, the
	// operator's terms. The runner does not read it.
	Note string
}

// AltHost is another NTS-KE host of an entry's operator. Roots empty: the
// entry's roots.
type AltHost struct {
	Host  string
	Roots []string
	Note  string
}

// Terms of an operator, as its own published pages state them.
type Terms uint8

const (
	// Open: free to use, no contact needed, no limit the clock breaks.
	Open Terms = iota
	// Ask: the operator wants contact before regular use, or states a
	// limit the clock's polling exceeds. Only a setup whose writer asked
	// may name it.
	Ask
)

func (t Terms) String() string {
	switch t {
	case Open:
		return "open"
	case Ask:
		return "ask"
	}
	return fmt.Sprintf("terms(%d)", uint8(t))
}

// Regions. RegionRule is how an entry earns one.
const (
	RegionGlobal = "global"
	RegionEU     = "eu"
	RegionNA     = "na"
	RegionSA     = "sa"
	RegionAPAC   = "apac"
)

// RegionRule: a server is in a region when its median NTP round trip was
// under 180 ms from every test point there. The clock refuses an error
// bound over 100 ms and a sample's bound is about half the round trip plus
// the server's own root distance, so 180 ms leaves a margin. Anycast
// servers that met the rule everywhere are RegionGlobal.
const RegionRule = "median round trip under 180 ms from every test point in the region"

var regions = []string{RegionGlobal, RegionEU, RegionNA, RegionSA, RegionAPAC}

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
	Terms     string   `json:"terms"`
	TermsURL  string   `json:"terms_url"`
	Regions   []string `json:"regions"`
	Alt       []struct {
		Host  string   `json:"host"`
		Roots []string `json:"roots"`
		Note  string   `json:"note"`
	} `json:"alt"`
	Default bool   `json:"default"`
	Note    string `json:"note"`
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
		t, err := parseTerms(r.Terms)
		if err != nil {
			return Catalog{}, fmt.Errorf("ntscatalog: NTS server %q: %w", r.ID, err)
		}
		e := NTSServer{ID: r.ID, Host: r.Host, Operator: r.Operator, Roots: r.Roots,
			NTPNets: r.NTPNets, NitroPort: r.NitroPort, Status: s, Terms: t, TermsURL: r.TermsURL,
			Regions: r.Regions, Default: r.Default, Note: r.Note}
		for _, a := range r.Alt {
			e.Alt = append(e.Alt, AltHost{Host: a.Host, Roots: a.Roots, Note: a.Note})
		}
		c.NTS = append(c.NTS, e)
	}
	if err := c.Check(); err != nil {
		return Catalog{}, err
	}
	return c, nil
}

// formatKeys are the keys of catalog.json by place: the top object and
// each entry of "nts".
var formatKeys = map[string][]string{
	"":           {"nts"},
	"nts[]":      {"id", "host", "operator", "roots", "ntp_nets", "nitro_port", "status", "terms", "terms_url", "regions", "alt", "default", "note"},
	"nts[]alt[]": {"host", "roots", "note"},
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

func parseTerms(s string) (Terms, error) {
	for _, t := range []Terms{Open, Ask} {
		if s == t.String() {
			return t, nil
		}
	}
	return 0, fmt.Errorf("terms %q: want open or ask", s)
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

// Dialed are the NTS servers a runner dials while setups cannot name
// servers: the Default entries that are not withdrawn, in catalog order.
func (c *Catalog) Dialed() []NTSServer {
	var out []NTSServer
	for _, e := range c.NTS {
		if e.Default && e.Status != Withdrawn {
			out = append(out, e)
		}
	}
	return out
}

// ForRegion are the active entries a new setup for region may name, in
// catalog order: those tagged with region or RegionGlobal, and with Terms
// Open unless withAsk. nil for an unknown region. signer-admin suggests
// these; the setup writer picks.
func (c *Catalog) ForRegion(region string, withAsk bool) []NTSServer {
	if region == RegionGlobal || !slices.Contains(regions, region) {
		return nil
	}
	var out []NTSServer
	for _, e := range c.NTS {
		if e.Status != Active || (e.Terms == Ask && !withAsk) {
			continue
		}
		if slices.Contains(e.Regions, region) || slices.Contains(e.Regions, RegionGlobal) {
			out = append(out, e)
		}
	}
	return out
}

// checkRegions: at least one, each known, none twice, and RegionGlobal
// only alone.
func checkRegions(rs []string) error {
	if len(rs) == 0 {
		return errors.New("no regions")
	}
	for i, r := range rs {
		if !slices.Contains(regions, r) {
			return fmt.Errorf("unknown region %q", r)
		}
		if slices.Contains(rs[:i], r) {
			return fmt.Errorf("region %q twice", r)
		}
	}
	if slices.Contains(rs, RegionGlobal) && len(rs) > 1 {
		return errors.New("region global goes alone")
	}
	return nil
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
// NTS server per operator, a known status and terms, a terms URL for open
// terms, host and roots set, every host (alt hosts too) once in the
// catalog, known regions (RegionGlobal alone), NTP nets that parse, and a
// distinct Nitro vsock port for every server. Parse runs it on every catalog it
// reads.
func (c *Catalog) Check() error {
	ids := map[string]bool{}
	ops := map[string]string{}
	hosts := map[string]string{}
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
		if e.Terms > Ask {
			return fmt.Errorf("ntscatalog: NTS server %s: %v", e.ID, e.Terms)
		}
		if err := checkRegions(e.Regions); err != nil {
			return fmt.Errorf("ntscatalog: NTS server %s: %w", e.ID, err)
		}
		if e.TermsURL != "" && !strings.HasPrefix(e.TermsURL, "https://") && !strings.HasPrefix(e.TermsURL, "http://") {
			return fmt.Errorf("ntscatalog: NTS server %s: terms_url %q is not a web URL", e.ID, e.TermsURL)
		}
		if e.Terms == Open && e.TermsURL == "" {
			return fmt.Errorf("ntscatalog: NTS server %s: open terms need the terms_url they were read from", e.ID)
		}
		if prev, dup := hosts[e.Host]; dup {
			return fmt.Errorf("ntscatalog: host %s in %s and %s", e.Host, prev, e.ID)
		}
		hosts[e.Host] = e.ID
		for _, a := range e.Alt {
			if a.Host == "" {
				return fmt.Errorf("ntscatalog: NTS server %s: alt host empty", e.ID)
			}
			if prev, dup := hosts[a.Host]; dup {
				return fmt.Errorf("ntscatalog: host %s in %s and %s", a.Host, prev, e.ID)
			}
			hosts[a.Host] = e.ID
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
