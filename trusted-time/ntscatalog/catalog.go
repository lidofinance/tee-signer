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
	"net/url"
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
	NTPNets []string
	// NTPNames are NTP host names the NTS-KE server names other than its
	// own (Meta's names time.meta.com). The Nitro UDP relay allows them.
	NTPNames  []string
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
	// They count as the same operator. The runner dials one only when a
	// deployment names it as id@host and it has a NitroPort.
	Alt []AltHost
	// Default: the runner dials it while setups cannot name servers yet.
	Default bool
	// Note is free text for reviewers: why the entry is there, the
	// operator's terms. The runner does not read it.
	Note string
}

// AltHost is another NTS-KE host of an entry's operator. Roots empty: the
// entry's roots. NitroPort set: a deployment may choose it in place of the
// entry's host (-nts-terms-confirmed id@host), and Nitro routes it on that
// port; 0: listed for reference only.
type AltHost struct {
	Host      string
	Roots     []string
	NitroPort uint32
	Note      string
}

// Endpoint is one NTS-KE host a runner of this image may dial: an entry's
// host, or an alt host with a Nitro port, with the roots and NTP names that
// go with it.
type Endpoint struct {
	ID        string // the entry
	Operator  string
	Host      string
	Roots     []string
	NTPNames  []string
	NTPNets   []string
	NitroPort uint32
}

// Endpoints are every host a runner of this image may dial, in catalog
// order: each entry that is not withdrawn, then its alt hosts that have a
// Nitro port. The Nitro parent routes all of them (platform/setup) and its
// UDP relay allows their NTP hosts, since the parent cannot see which ones
// the enclave's command chose; the enclave dials only its own choice.
func (c *Catalog) Endpoints() []Endpoint {
	var out []Endpoint
	for _, e := range c.NTS {
		if e.Status == Withdrawn {
			continue
		}
		out = append(out, e.endpoint())
		for _, a := range e.Alt {
			if a.NitroPort != 0 {
				out = append(out, e.altEndpoint(a))
			}
		}
	}
	return out
}

func (e NTSServer) altEndpoint(a AltHost) Endpoint {
	roots := a.Roots
	if len(roots) == 0 {
		roots = e.Roots
	}
	return Endpoint{ID: e.ID, Operator: e.Operator, Host: a.Host, Roots: slices.Clone(roots), NTPNames: slices.Clone(e.NTPNames),
		NTPNets: slices.Clone(e.NTPNets), NitroPort: a.NitroPort}
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
	NTS    []NTSServer
	Coarse []Coarse
}

// Coarse is one HTTPS-date host of the NTS clock's coarse check. An image
// names its coarse URLs in its command (-nts-coarse-urls); on a platform
// with pinned roots each must be a catalog entry, and its source trusts
// that entry's roots and no others.
type Coarse struct {
	ID string
	// URL is https; {region} stands for the setup's region.
	URL string
	// Roots are files under trusted-time/nts/roots.
	Roots []string
	// CloudRoots names a cloud's pinned set in platform/cloudroots: one of
	// CloudRootSets, or "" for none.
	CloudRoots string
	Note       string
}

// CloudRootSets are the values of Coarse.CloudRoots.
var CloudRootSets = []string{"aws", "google", "azure"}

// CoarseFor is the entry whose URL is url as the image names it (with
// {region} not yet filled in).
func (c *Catalog) CoarseFor(url string) (Coarse, bool) {
	for _, e := range c.Coarse {
		if e.URL == url {
			return e, true
		}
	}
	return Coarse{}, false
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
	NTPNames  []string `json:"ntp_names"`
	NitroPort uint32   `json:"nitro_port"`
	Status    string   `json:"status"`
	Terms     string   `json:"terms"`
	TermsURL  string   `json:"terms_url"`
	Regions   []string `json:"regions"`
	Alt       []struct {
		Host      string   `json:"host"`
		Roots     []string `json:"roots"`
		NitroPort uint32   `json:"nitro_port"`
		Note      string   `json:"note"`
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
		NTS    []jsonServer `json:"nts"`
		Coarse []struct {
			ID         string   `json:"id"`
			URL        string   `json:"url"`
			Roots      []string `json:"roots"`
			CloudRoots string   `json:"cloud_roots"`
			Note       string   `json:"note"`
		} `json:"coarse"`
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
			NTPNets: r.NTPNets, NTPNames: r.NTPNames, NitroPort: r.NitroPort, Status: s, Terms: t, TermsURL: r.TermsURL,
			Regions: r.Regions, Default: r.Default, Note: r.Note}
		for _, a := range r.Alt {
			e.Alt = append(e.Alt, AltHost{Host: a.Host, Roots: a.Roots, NitroPort: a.NitroPort, Note: a.Note})
		}
		c.NTS = append(c.NTS, e)
	}
	for _, r := range raw.Coarse {
		c.Coarse = append(c.Coarse, Coarse{ID: r.ID, URL: r.URL, Roots: r.Roots, CloudRoots: r.CloudRoots, Note: r.Note})
	}
	if err := c.Check(); err != nil {
		return Catalog{}, err
	}
	return c, nil
}

// formatKeys are the keys of catalog.json by place: the top object and
// each entry of "nts" and "coarse".
var formatKeys = map[string][]string{
	"":           {"nts", "coarse"},
	"coarse[]":   {"id", "url", "roots", "cloud_roots", "note"},
	"nts[]":      {"id", "host", "operator", "roots", "ntp_nets", "ntp_names", "nitro_port", "status", "terms", "terms_url", "regions", "alt", "default", "note"},
	"nts[]alt[]": {"host", "roots", "nitro_port", "note"},
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

// MaxServers is the most servers a runner may dial: the Rust core's
// quorum refuses more (MAX_SERVERS), so a larger set would fail every
// quorum. An nts-tagged test in trusted-time/nts ties both numbers to the
// core's.
const MaxServers = 16

// NTPHosts are the NTP host names a runner that dials endpoints can be
// sent to: each host, which the client uses when NTS-KE names no NTP
// server (RFC 8915 section 4.1.7), then its NTPNames. The Nitro UDP relay
// allows them for Endpoints.
func NTPHosts(eps []Endpoint) []string {
	var out []string
	for _, e := range eps {
		out = append(out, e.Host)
		out = append(out, e.NTPNames...)
	}
	return out
}

// NTPNets are the NTP address blocks of eps, without repeats.
func NTPNets(eps []Endpoint) []string {
	var out []string
	for _, e := range eps {
		for _, n := range e.NTPNets {
			if !slices.Contains(out, n) {
				out = append(out, n)
			}
		}
	}
	return out
}

// Dialed are the NTS servers a runner dials while setups cannot name
// servers: the Default entries that are not withdrawn, in catalog order.
func (c *Catalog) Dialed() []NTSServer {
	var out []NTSServer
	for _, e := range c.NTS {
		if e.Default && e.Status != Withdrawn {
			out = append(out, e.clone())
		}
	}
	return out
}

// clone is e with its own slices, so a caller that changes them does not
// change the catalog.
func (e NTSServer) clone() NTSServer {
	e.Roots, e.NTPNets, e.NTPNames, e.Regions = slices.Clone(e.Roots), slices.Clone(e.NTPNets), slices.Clone(e.NTPNames), slices.Clone(e.Regions)
	e.Alt = slices.Clone(e.Alt)
	for i := range e.Alt {
		e.Alt[i].Roots = slices.Clone(e.Alt[i].Roots)
	}
	return e
}

// WithConfirmed is the Dialed set plus the entries ids names, in catalog
// order: what a deployment dials whose writer confirmed those operators'
// terms (the runner's -nts-terms-confirmed). An id must name an entry that
// is not Default; a withdrawn one is refused, since the image no longer
// trusts it. Ask and open entries both qualify. A spec is "id", for the
// entry's host, or "id@host" for one of its alt hosts that has a Nitro
// port (Endpoints routes only those).
func (c *Catalog) WithConfirmed(specs []string) ([]Endpoint, error) {
	want := map[string]string{} // id -> chosen host, "" for the entry's own
	for _, s := range specs {
		id, host, at := strings.Cut(s, "@")
		if id == "" || (at && host == "") {
			return nil, fmt.Errorf("ntscatalog: bad choice %q: want id or id@host", s)
		}
		if _, dup := want[id]; dup {
			return nil, fmt.Errorf("ntscatalog: %q named twice", id)
		}
		want[id] = host
	}
	var out []Endpoint
	for _, e := range c.NTS {
		host, named := want[e.ID]
		delete(want, e.ID)
		switch {
		case named && e.Default:
			return nil, fmt.Errorf("ntscatalog: %q is in the default set already", e.ID)
		case named && e.Status == Withdrawn:
			return nil, fmt.Errorf("ntscatalog: %q is withdrawn from this image", e.ID)
		case named && host != "" && host != e.Host:
			i := slices.IndexFunc(e.Alt, func(a AltHost) bool { return a.Host == host && a.NitroPort != 0 })
			if i < 0 {
				return nil, fmt.Errorf("ntscatalog: %q has no alt host %q with a Nitro port", e.ID, host)
			}
			out = append(out, e.altEndpoint(e.Alt[i]))
		case named, e.Default && e.Status != Withdrawn:
			out = append(out, e.endpoint())
		}
	}
	for id := range want {
		return nil, fmt.Errorf("ntscatalog: no entry %q", id)
	}
	if len(out) > MaxServers {
		return nil, fmt.Errorf("ntscatalog: %d servers with the confirmed ones, at most %d", len(out), MaxServers)
	}
	return out, nil
}

func (e NTSServer) endpoint() Endpoint {
	return Endpoint{ID: e.ID, Operator: e.Operator, Host: e.Host, Roots: slices.Clone(e.Roots), NTPNames: slices.Clone(e.NTPNames),
		NTPNets: slices.Clone(e.NTPNets), NitroPort: e.NitroPort}
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
// so an ID holds no separator, space or upper case. Operator labels follow
// the same rule: "ptb" and "PTB " must not count as two operators, and the
// status line lists them comma-separated.
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

// validHost: a DNS name in lower case, without a trailing dot, of a-z,
// 0-9, '.' and '-', so one host cannot appear twice in two spellings.
func validHost(h string) bool {
	if h == "" || len(h) > 253 || strings.HasPrefix(h, ".") || strings.HasSuffix(h, ".") || strings.Contains(h, "..") {
		return false
	}
	for _, c := range []byte(h) {
		if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

// checkRoots: .pem file names under trusted-time/nts/roots, none empty.
// Whether each is pinned, the nts-tagged TestPinnedRoots checks.
func checkRoots(roots []string) error {
	for _, r := range roots {
		if !strings.HasSuffix(r, ".pem") || len(r) == len(".pem") || strings.ContainsAny(r, `/\ `) {
			return fmt.Errorf("root %q: a .pem file name", r)
		}
	}
	return nil
}

// Check is the catalog's own consistency: valid unique IDs, one
// NTS server per operator, operator labels of the ID rule, a known status
// and terms, a terms URL for open terms, host and roots set, hosts in lower
// case and every host (alt hosts too) once in the catalog, root file names,
// known regions (RegionGlobal alone), NTP nets that parse, a distinct Nitro
// vsock port for every server, and a default set of 1 to MaxServers. Parse
// runs it on every catalog it reads, so an empty catalog ("{}", null) is
// refused too.
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
		if !validID(e.Operator) {
			return fmt.Errorf("ntscatalog: NTS server %s: operator %q: a-z, 0-9, '.' and '-'", e.ID, e.Operator)
		}
		if !validHost(e.Host) {
			return fmt.Errorf("ntscatalog: NTS server %s: host %q: a lower-case DNS name", e.ID, e.Host)
		}
		if err := checkRoots(e.Roots); err != nil {
			return fmt.Errorf("ntscatalog: NTS server %s: %w", e.ID, err)
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
			if !validHost(a.Host) {
				return fmt.Errorf("ntscatalog: NTS server %s: alt host %q: a lower-case DNS name", e.ID, a.Host)
			}
			if err := checkRoots(a.Roots); err != nil {
				return fmt.Errorf("ntscatalog: NTS server %s: alt host %s: %w", e.ID, a.Host, err)
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
		for _, n := range e.NTPNames {
			if !validHost(n) || n == e.Host {
				return fmt.Errorf("ntscatalog: NTS server %s: NTP name %q: a lower-case DNS name other than the server's own", e.ID, n)
			}
		}
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
		for _, a := range e.Alt {
			if a.NitroPort == 0 {
				continue
			}
			if prev, dup := ports[a.NitroPort]; dup {
				return fmt.Errorf("ntscatalog: vsock port %d for %s and %s (%s)", a.NitroPort, prev, e.ID, a.Host)
			}
			ports[a.NitroPort] = e.ID + "@" + a.Host
		}
	}
	if err := c.checkCoarse(); err != nil {
		return err
	}
	// A runner with no default server, or more than the quorum takes, could
	// never form a quorum.
	if d := len(c.Dialed()); d == 0 || d > MaxServers {
		return fmt.Errorf("ntscatalog: %d default servers (not withdrawn), want 1 to %d", d, MaxServers)
	}
	return nil
}

// checkCoarse: valid unique IDs and URLs, https URLs with no user, query
// or fragment, and roots: files, a known cloud set, or both.
func (c *Catalog) checkCoarse() error {
	ids := map[string]bool{}
	urls := map[string]bool{}
	for _, e := range c.Coarse {
		if !validID(e.ID) {
			return fmt.Errorf("ntscatalog: coarse ID %q: 1 to %d of a-z, 0-9, '.' and '-'", e.ID, MaxLabel)
		}
		if ids[e.ID] {
			return fmt.Errorf("ntscatalog: coarse ID %q twice", e.ID)
		}
		ids[e.ID] = true
		if urls[e.URL] {
			return fmt.Errorf("ntscatalog: coarse URL %s twice", e.URL)
		}
		urls[e.URL] = true
		u, err := url.Parse(strings.ReplaceAll(e.URL, "{region}", "region"))
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("ntscatalog: coarse %s: URL %q: https, a host, no user, query or fragment", e.ID, e.URL)
		}
		if e.CloudRoots != "" && !slices.Contains(CloudRootSets, e.CloudRoots) {
			return fmt.Errorf("ntscatalog: coarse %s: cloud_roots %q: want one of %v", e.ID, e.CloudRoots, CloudRootSets)
		}
		if e.CloudRoots == "" && len(e.Roots) == 0 {
			return fmt.Errorf("ntscatalog: coarse %s: no roots", e.ID)
		}
		if err := checkRoots(e.Roots); err != nil {
			return fmt.Errorf("ntscatalog: coarse %s: %w", e.ID, err)
		}
	}
	return nil
}
