package ntscatalog

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestBuiltinIsConsistent(t *testing.T) {
	if err := Builtin.Check(); err != nil {
		t.Fatal(err)
	}
	if n := len(Builtin.Dialed()); n < 3 {
		t.Fatalf("builtin dials %d servers, the quorum needs 3", n)
	}
}

// The default set holds only operators whose terms are open, active, and in
// eu and na or global, so a runner dials no operator that asks for contact
// unless its deployment confirmed it. It has 6: a deployment adds one more
// (-nts-terms-confirmed) to run the shift schedule, which needs 7.
func TestDefaultSet(t *testing.T) {
	var ids []string
	for _, e := range Builtin.Dialed() {
		ids = append(ids, e.ID)
		if e.Terms != Open || e.Status != Active {
			t.Errorf("default %s: terms %v, status %v", e.ID, e.Terms, e.Status)
		}
		global := slices.Contains(e.Regions, RegionGlobal)
		if !global && !slices.Contains(e.Regions, RegionEU) {
			t.Errorf("default %s: regions %v, not eu", e.ID, e.Regions)
		}
	}
	if strings.Join(ids, ",") != "cloudflare,netnod,ptb,bev,meta,wiktel" {
		t.Fatalf("default set %v", ids)
	}
}

func TestNTPHostsAndNets(t *testing.T) {
	eps := []Endpoint{{Host: "a.example", NTPNets: []string{"192.0.2.0/24"}},
		{Host: "b.example", NTPNames: []string{"ntp.b.example"}, NTPNets: []string{"192.0.2.0/24", "198.51.100.0/24"}}}
	if got := NTPHosts(eps); strings.Join(got, ",") != "a.example,b.example,ntp.b.example" {
		t.Fatalf("NTPHosts %v", got)
	}
	if got := NTPNets(eps); strings.Join(got, ",") != "192.0.2.0/24,198.51.100.0/24" {
		t.Fatalf("NTPNets %v", got)
	}
}

func confirmCatalog() Catalog {
	return Catalog{NTS: []NTSServer{
		{ID: "d", Operator: "op-d", Host: "d.example", Roots: []string{"r.pem"}, NitroPort: 9001, Default: true},
		{ID: "t", Operator: "op-t", Host: "t1.example", Roots: []string{"r.pem"}, NitroPort: 9002, Terms: Ask,
			Alt: []AltHost{{Host: "t2.example"}, {Host: "any.t.example", Roots: []string{"s.pem"}, NitroPort: 9010}}},
		{ID: "gone", Operator: "op-g", Host: "g.example", Roots: []string{"r.pem"}, NitroPort: 9003, Status: Withdrawn, Default: true},
		{ID: "x", Operator: "op-x", Host: "x.example", Roots: []string{"r.pem"}, NitroPort: 9004, Status: Withdrawn},
	}}
}

func TestWithConfirmed(t *testing.T) {
	c := confirmCatalog()
	hosts := func(eps []Endpoint) string {
		var s []string
		for _, e := range eps {
			s = append(s, e.Host+"/"+e.Operator+"/"+strings.Join(e.Roots, "+"))
		}
		return strings.Join(s, ",")
	}
	for _, tc := range []struct {
		specs []string
		want  string
	}{
		{nil, "d.example/op-d/r.pem"},
		{[]string{"t"}, "d.example/op-d/r.pem,t1.example/op-t/r.pem"},
		{[]string{"t@t1.example"}, "d.example/op-d/r.pem,t1.example/op-t/r.pem"},
		{[]string{"t@any.t.example"}, "d.example/op-d/r.pem,any.t.example/op-t/s.pem"},
	} {
		eps, err := c.WithConfirmed(tc.specs)
		if err != nil || hosts(eps) != tc.want {
			t.Errorf("%v: %s %v, want %s", tc.specs, hosts(eps), err, tc.want)
		}
	}
	if eps, _ := c.WithConfirmed([]string{"t@any.t.example"}); eps[1].NitroPort != 9010 {
		t.Errorf("alt port %d", eps[1].NitroPort)
	}
	for _, tc := range []struct {
		specs []string
		want  string
	}{
		{[]string{"t", "t@any.t.example"}, "twice"},
		{[]string{"d"}, "default set already"},
		{[]string{"x"}, "withdrawn"},
		{[]string{"nope"}, "no entry"},
		{[]string{"t@t2.example"}, "no alt host"},
		{[]string{"t@other.example"}, "no alt host"},
		{[]string{"t@"}, "bad choice"},
		{[]string{"@any.t.example"}, "bad choice"},
	} {
		if _, err := c.WithConfirmed(tc.specs); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: %v, want %q", tc.specs, err, tc.want)
		}
	}
}

// Endpoints: every entry that is not withdrawn, then its alt hosts with a
// Nitro port; the built-in catalog routes TimeNL's anycast host too.
func TestEndpoints(t *testing.T) {
	var got []string
	c := confirmCatalog()
	for _, e := range c.Endpoints() {
		got = append(got, fmt.Sprintf("%s:%d", e.Host, e.NitroPort))
	}
	if strings.Join(got, ",") != "d.example:9001,t1.example:9002,any.t.example:9010" {
		t.Fatalf("endpoints %v", got)
	}
	var any bool
	for _, e := range Builtin.Endpoints() {
		if e.Host == "any.time.nl" && e.ID == "time.nl" && e.NitroPort == 8018 {
			any = true
		}
	}
	if !any {
		t.Error("any.time.nl is not a built-in endpoint on port 8018")
	}
	if _, err := Builtin.WithConfirmed([]string{"time.nl@any.time.nl"}); err != nil {
		t.Error(err)
	}
}

func okCatalog() Catalog {
	return Catalog{NTS: []NTSServer{
		{ID: "a", Host: "a.example", Operator: "op-a", Roots: []string{"r.pem"}, NitroPort: 9001,
			Terms: Open, TermsURL: "https://a.example/terms", Regions: []string{"eu"}, Default: true,
			Alt: []AltHost{{Host: "a2.example"}}},
		{ID: "b", Host: "b.example", Operator: "op-b", Roots: []string{"r.pem"}, NitroPort: 9002, NTPNets: []string{"192.0.2.0/24"},
			Terms: Ask, Regions: []string{"global"}, Default: true},
	}}
}

func TestCheckRefuses(t *testing.T) {
	if c := okCatalog(); c.Check() != nil {
		t.Fatal(c.Check())
	}
	for name, tc := range map[string]struct {
		edit func(c *Catalog)
		want string
	}{
		"upper-case ID":    {func(c *Catalog) { c.NTS[0].ID = "A" }, "a-z, 0-9"},
		"empty ID":         {func(c *Catalog) { c.NTS[0].ID = "" }, "a-z, 0-9"},
		"long ID":          {func(c *Catalog) { c.NTS[0].ID = strings.Repeat("a", MaxLabel+1) }, "a-z, 0-9"},
		"comma in ID":      {func(c *Catalog) { c.NTS[0].ID = "a,b" }, "a-z, 0-9"},
		"space in ID":      {func(c *Catalog) { c.NTS[0].ID = "time nl" }, "a-z, 0-9"},
		"non-ASCII ID":     {func(c *Catalog) { c.NTS[0].ID = "zeit-é" }, "a-z, 0-9"},
		"repeated ID":      {func(c *Catalog) { c.NTS[1].ID = "a" }, "twice"},
		"no host":          {func(c *Catalog) { c.NTS[0].Host = "" }, "required"},
		"no roots":         {func(c *Catalog) { c.NTS[0].Roots = nil }, "required"},
		"no operator":      {func(c *Catalog) { c.NTS[0].Operator = "" }, "required"},
		"long operator":    {func(c *Catalog) { c.NTS[0].Operator = strings.Repeat("o", MaxLabel+1) }, "required"},
		"shared operator":  {func(c *Catalog) { c.NTS[1].Operator = "op-a" }, "share operator"},
		"bad status":       {func(c *Catalog) { c.NTS[0].Status = Withdrawn + 1 }, "status("},
		"bad terms":        {func(c *Catalog) { c.NTS[0].Terms = Ask + 1 }, "terms("},
		"open without url": {func(c *Catalog) { c.NTS[0].TermsURL = "" }, "terms_url"},
		"url not web":      {func(c *Catalog) { c.NTS[1].TermsURL = "ftp://b.example" }, "not a web URL"},
		"no regions":       {func(c *Catalog) { c.NTS[0].Regions = nil }, "no regions"},
		"unknown region":   {func(c *Catalog) { c.NTS[0].Regions = []string{"mars"} }, "unknown region"},
		"region twice":     {func(c *Catalog) { c.NTS[0].Regions = []string{"eu", "eu"} }, "twice"},
		"global not alone": {func(c *Catalog) { c.NTS[1].Regions = []string{"global", "eu"} }, "alone"},
		"empty alt":        {func(c *Catalog) { c.NTS[0].Alt = []AltHost{{}} }, "alt host empty"},
		"alt is a host":    {func(c *Catalog) { c.NTS[1].Alt = []AltHost{{Host: "a.example"}} }, "host a.example"},
		"alt in two":       {func(c *Catalog) { c.NTS[1].Alt = []AltHost{{Host: "a2.example"}} }, "host a2.example"},
		"host twice":       {func(c *Catalog) { c.NTS[1].Host = "a.example" }, "host a.example"},
		"bad net":          {func(c *Catalog) { c.NTS[1].NTPNets = []string{"192.0.2.1/24"} }, "masked CIDR"},
		"ntp name is host": {func(c *Catalog) { c.NTS[0].NTPNames = []string{"a.example"} }, "NTP name"},
		"ntp name port":    {func(c *Catalog) { c.NTS[0].NTPNames = []string{"ntp.a.example:123"} }, "NTP name"},
		"no port":          {func(c *Catalog) { c.NTS[0].NitroPort = 0 }, "no vsock port"},
		"shared port":      {func(c *Catalog) { c.NTS[1].NitroPort = 9001 }, "vsock port 9001"},
		"alt shares port":  {func(c *Catalog) { c.NTS[0].Alt[0].NitroPort = 9002 }, "vsock port 9002"},
	} {
		c := okCatalog()
		tc.edit(&c)
		if err := c.Check(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

func TestDialedIsDefaultNotWithdrawn(t *testing.T) {
	c := Catalog{NTS: []NTSServer{{ID: "a", Default: true}, {ID: "b", Default: true, Status: Retired},
		{ID: "c", Default: true, Status: Withdrawn}, {ID: "d"}, {ID: "e", Default: true}}}
	var got []string
	for _, e := range c.Dialed() {
		got = append(got, e.ID)
	}
	if strings.Join(got, ",") != "a,b,e" {
		t.Fatalf("dialed %v", got)
	}
}

func TestForRegion(t *testing.T) {
	c := Catalog{NTS: []NTSServer{
		{ID: "g", Regions: []string{"global"}},
		{ID: "eu", Regions: []string{"eu", "na"}},
		{ID: "ask", Terms: Ask, Regions: []string{"eu"}},
		{ID: "old", Status: Retired, Regions: []string{"eu"}},
		{ID: "gone", Status: Withdrawn, Regions: []string{"global"}},
		{ID: "sa", Regions: []string{"sa"}},
	}}
	ids := func(es []NTSServer) string {
		var s []string
		for _, e := range es {
			s = append(s, e.ID)
		}
		return strings.Join(s, ",")
	}
	for _, tc := range []struct {
		region  string
		withAsk bool
		want    string
	}{
		{"eu", false, "g,eu"}, {"eu", true, "g,eu,ask"}, {"na", false, "g,eu"}, {"sa", false, "g,sa"},
		{"apac", true, "g"}, {"global", true, ""}, {"mars", true, ""},
	} {
		if got := ids(c.ForRegion(tc.region, tc.withAsk)); got != tc.want {
			t.Errorf("ForRegion(%s, %v) = %s, want %s", tc.region, tc.withAsk, got, tc.want)
		}
	}
}

// What the built-in catalog offers each region with open terms only. South
// America has 4 (Cloudflare, Meta, Wiktel, NIC.br). Asia and Oceania have
// no NTS operator close enough of their own: there the open set is the two
// global anycast services, below the quorum's 3.
func TestBuiltinOpenSetPerRegion(t *testing.T) {
	for region, min := range map[string]int{RegionEU: 6, RegionNA: 6, RegionSA: 4} {
		if n := len(Builtin.ForRegion(region, false)); n < min {
			t.Errorf("%s: %d open servers, want at least %d", region, n, min)
		}
	}
	var apac []string
	for _, e := range Builtin.ForRegion(RegionAPAC, false) {
		apac = append(apac, e.ID)
	}
	if !slices.Equal(apac, []string{"cloudflare", "meta"}) {
		t.Errorf("apac open set %v: update this test and nts.md if it grew", apac)
	}
}

// The embedded catalog.json parses and checks, and Builtin is that file.
func TestEmbeddedCatalogParses(t *testing.T) {
	c, err := Parse(builtinJSON)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.NTS) != len(Builtin.NTS) || c.NTS[0].ID != Builtin.NTS[0].ID {
		t.Fatalf("parsed %d entries, Builtin %d", len(c.NTS), len(Builtin.NTS))
	}
	for _, e := range Builtin.NTS {
		if e.Note == "" {
			t.Errorf("%s: no note; say why it is in the catalog and the operator's terms", e.ID)
		}
	}
	var timenl NTSServer
	for _, e := range Builtin.NTS {
		if e.ID == "time.nl" {
			timenl = e
		}
	}
	if len(timenl.Alt) != 4 || timenl.Alt[3].Host != "any.time.nl" || len(timenl.Alt[3].Roots) != 2 || len(timenl.Alt[0].Roots) != 0 {
		t.Fatalf("time.nl alt hosts %+v", timenl.Alt)
	}
}

const testEntry = `{"id":"a","host":"a.example","operator":"op-a","roots":["r.pem"],"nitro_port":9001,"status":"active","terms":"open","terms_url":"https://a.example/","regions":["eu"]`

func TestParseRefuses(t *testing.T) {
	entry := testEntry + `}`
	with := func(extra string) string { return `{"nts":[` + testEntry + `,` + extra + `}]}` }
	c, err := Parse([]byte(`{"nts":[` + testEntry + `,"alt":[{"host":"a2.example","roots":["s.pem"],"note":"n"}],"default":true}]}`))
	if err != nil || c.NTS[0].Status != Active || c.NTS[0].Terms != Open || !c.NTS[0].Default || c.NTS[0].Alt[0].Roots[0] != "s.pem" {
		t.Fatalf("good catalog: %+v %v", c, err)
	}
	for name, tc := range map[string]struct{ in, want string }{
		"unknown field":      {with(`"port":1`), "unknown key"},
		"unknown top key":    {`{"nts":[` + entry + `],"extra":[]}`, "unknown key"},
		"coarse unknown key": {`{"nts":[` + entry + `],"coarse":[{"id":"x","url":"https://x.example/","cloud_roots":"aws","port":1}]}`, "unknown key"},
		"coarse http":        {`{"nts":[` + entry + `],"coarse":[{"id":"x","url":"http://x.example/","cloud_roots":"aws"}]}`, "https"},
		"coarse query":       {`{"nts":[` + entry + `],"coarse":[{"id":"x","url":"https://x.example/?a=1","cloud_roots":"aws"}]}`, "https"},
		"coarse cloud":       {`{"nts":[` + entry + `],"coarse":[{"id":"x","url":"https://x.example/","cloud_roots":"ibm"}]}`, "cloud_roots"},
		"coarse no roots":    {`{"nts":[` + entry + `],"coarse":[{"id":"x","url":"https://x.example/"}]}`, "no roots"},
		"coarse id twice":    {`{"nts":[` + entry + `],"coarse":[{"id":"x","url":"https://x.example/","cloud_roots":"aws"},{"id":"x","url":"https://y.example/","cloud_roots":"aws"}]}`, "twice"},
		"coarse url twice":   {`{"nts":[` + entry + `],"coarse":[{"id":"x","url":"https://x.example/","cloud_roots":"aws"},{"id":"y","url":"https://x.example/","cloud_roots":"aws"}]}`, "twice"},
		"unknown alt key":    {with(`"alt":[{"host":"a2.example","port":1}]`), "unknown key"},
		"trailing data":      {`{"nts":[` + entry + `]} {}`, "data after"},
		"trailing brace":     {`{"nts":[` + entry + `]}}`, "ntscatalog"},
		"trailing ]":         {`{"nts":[` + entry + `]}]`, "ntscatalog"},
		"key twice":          {with(`"status":"withdrawn"`), "twice"},
		"key case":           {with(`"Status":"withdrawn"`), "unknown key"},
		"nts twice":          {`{"nts":[],"nts":[` + entry + `]}`, "twice"},
		"object in list":     {`{"nts":[{"id":"a","roots":[{"x":1}]}]}`, "unknown key"},
		"no status":          {`{"nts":[{"id":"a","host":"a.example","operator":"op-a","roots":["r.pem"],"nitro_port":9001,"terms":"open"}]}`, "status"},
		"bad status":         {`{"nts":[{"id":"a","host":"a.example","operator":"op-a","roots":["r.pem"],"nitro_port":9001,"status":"Active"}]}`, "status"},
		"no terms":           {`{"nts":[{"id":"a","host":"a.example","operator":"op-a","roots":["r.pem"],"nitro_port":9001,"status":"active"}]}`, "terms"},
		"bad terms":          {`{"nts":[{"id":"a","host":"a.example","operator":"op-a","roots":["r.pem"],"nitro_port":9001,"status":"active","terms":"free"}]}`, "terms"},
		"check fails":        {`{"nts":[` + entry + `,` + entry + `]}`, "twice"},
		"not an object":      {`[]`, "ntscatalog"},
		"wrong type":         {`{"nts":[{"id":"a","roots":"r.pem"}]}`, "ntscatalog"},
	} {
		if _, err := Parse([]byte(tc.in)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}
