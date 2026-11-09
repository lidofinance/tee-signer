package ntscatalog

import (
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

func TestCheckRefuses(t *testing.T) {
	ok := func() Catalog {
		return Catalog{NTS: []NTSServer{
			{ID: "a", Host: "a.example", Operator: "op-a", Roots: []string{"r.pem"}, NitroPort: 9001},
			{ID: "b", Host: "b.example", Operator: "op-b", Roots: []string{"r.pem"}, NitroPort: 9002, NTPNets: []string{"192.0.2.0/24"}},
		}}
	}
	if c := ok(); c.Check() != nil {
		t.Fatal(c.Check())
	}
	for name, tc := range map[string]struct {
		edit func(c *Catalog)
		want string
	}{
		"upper-case ID":   {func(c *Catalog) { c.NTS[0].ID = "A" }, "a-z, 0-9"},
		"empty ID":        {func(c *Catalog) { c.NTS[0].ID = "" }, "a-z, 0-9"},
		"long ID":         {func(c *Catalog) { c.NTS[0].ID = strings.Repeat("a", MaxLabel+1) }, "a-z, 0-9"},
		"comma in ID":     {func(c *Catalog) { c.NTS[0].ID = "a,b" }, "a-z, 0-9"},
		"space in ID":     {func(c *Catalog) { c.NTS[0].ID = "time nl" }, "a-z, 0-9"},
		"non-ASCII ID":    {func(c *Catalog) { c.NTS[0].ID = "zeit-é" }, "a-z, 0-9"},
		"repeated ID":     {func(c *Catalog) { c.NTS[1].ID = "a" }, "twice"},
		"no host":         {func(c *Catalog) { c.NTS[0].Host = "" }, "required"},
		"no roots":        {func(c *Catalog) { c.NTS[0].Roots = nil }, "required"},
		"no operator":     {func(c *Catalog) { c.NTS[0].Operator = "" }, "required"},
		"long operator":   {func(c *Catalog) { c.NTS[0].Operator = strings.Repeat("o", MaxLabel+1) }, "required"},
		"shared operator": {func(c *Catalog) { c.NTS[1].Operator = "op-a" }, "share operator"},
		"bad status":      {func(c *Catalog) { c.NTS[0].Status = Withdrawn + 1 }, "status("},
		"bad net":         {func(c *Catalog) { c.NTS[1].NTPNets = []string{"192.0.2.1/24"} }, "masked CIDR"},
		"no port":         {func(c *Catalog) { c.NTS[0].NitroPort = 0 }, "no vsock port"},
		"shared port":     {func(c *Catalog) { c.NTS[1].NitroPort = 9001 }, "vsock port 9001"},
	} {
		c := ok()
		tc.edit(&c)
		if err := c.Check(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

func TestDialedSkipsWithdrawn(t *testing.T) {
	c := Catalog{NTS: []NTSServer{{ID: "a"}, {ID: "b", Status: Retired}, {ID: "c", Status: Withdrawn}, {ID: "d"}}}
	var got []string
	for _, e := range c.Dialed() {
		got = append(got, e.ID)
	}
	if strings.Join(got, ",") != "a,b,d" {
		t.Fatalf("dialed %v", got)
	}
}
