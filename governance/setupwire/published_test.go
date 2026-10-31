package setupwire

import (
	"slices"
	"strings"
	"testing"
)

func setupLeaves(t *testing.T, s *Setup) (pub, locked, open []Leaf) {
	t.Helper()
	pub, err := s.PublicLeaves()
	if err != nil {
		t.Fatal(err)
	}
	if locked, err = s.Locked.Leaves(s.PolicySalts.Locked); err != nil {
		t.Fatal(err)
	}
	if open, err = s.Open.Leaves(s.PolicySalts.Open); err != nil {
		t.Fatal(err)
	}
	return pub, locked, open
}

// TestPolicyFromLeaves: the published leaves of every sample setup rebuild
// its public part, with the setup's policy_root.
func TestPolicyFromLeaves(t *testing.T) {
	for name, s := range samples(t) {
		t.Run(name, func(t *testing.T) {
			pub, locked, open := setupLeaves(t, s)
			p, err := PolicyFromLeaves(pub, locked, open)
			if err != nil {
				t.Fatal(err)
			}
			want, _ := s.PolicyRoot()
			got, err := p.Root()
			if err != nil || got != want {
				t.Fatalf("root %x, want %x (%v)", got, want, err)
			}
			if p.ClusterID != s.ClusterID || p.Chain != s.Chain || !slices.Equal(p.Locked.SlotTimeChanges, s.Locked.SlotTimeChanges) {
				t.Fatalf("decoded %+v", p)
			}
			if sp, _ := s.Policy().Root(); sp != want {
				t.Fatal("Setup.Policy has another root")
			}
		})
	}
}

// TestPolicyFromLeavesRefuses: wrong names, bytes moved between leaves,
// trailing bytes and a zero salt.
func TestPolicyFromLeavesRefuses(t *testing.T) {
	s := samples(t)["setup-gcp"]
	for _, tc := range []struct {
		name string
		edit func(pub, locked, open []Leaf) ([]Leaf, []Leaf, []Leaf)
		want string
	}{
		{"leaf missing", func(p, l, o []Leaf) ([]Leaf, []Leaf, []Leaf) { return p[:15], l, o }, "15 public leaves"},
		{"renamed", func(p, l, o []Leaf) ([]Leaf, []Leaf, []Leaf) { l[3].Name = "allowed_images"; return p, l, o }, `"allowed_images"`},
		{"bytes moved", func(p, l, o []Leaf) ([]Leaf, []Leaf, []Leaf) {
			// handover_generation's first byte moves to the end of
			// cluster_id: the same concatenation, other leaves.
			p[1].Value = append(slices.Clone(p[1].Value), p[2].Value[0])
			p[2].Value = p[2].Value[1:]
			return p, l, o
		}, "does not encode back"},
		{"trailing byte", func(p, l, o []Leaf) ([]Leaf, []Leaf, []Leaf) {
			o[1].Value = append(slices.Clone(o[1].Value), 0)
			return p, l, o
		}, "trailing"},
		{"format 1", func(p, l, o []Leaf) ([]Leaf, []Leaf, []Leaf) { p[0].Value = []byte{1}; return p, l, o }, "setup_format_version 1"},
		{"zero salt", func(p, l, o []Leaf) ([]Leaf, []Leaf, []Leaf) { l[0].Salt = [32]byte{}; return p, l, o }, "salt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pub, locked, open := setupLeaves(t, s)
			pub, locked, open = tc.edit(pub, locked, open)
			_, err := PolicyFromLeaves(pub, locked, open)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}
