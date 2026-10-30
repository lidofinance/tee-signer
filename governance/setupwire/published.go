package setupwire

import (
	"bytes"
	"fmt"
)

// Policy is the public part of a setup: the public group and version 0 of
// the locked and open groups, with their salts. It is what a watchdog
// rebuilds from the leaves an operator publishes (attestation-statement.md,
// section 1), without the private part.
type Policy struct {
	ClusterID              [32]byte
	HandoverGeneration     uint64
	Chain                  Chain
	Safety                 Safety
	MaxKeys                uint32
	SlashingLogMinLockDays uint32
	SigningMode            SigningMode
	Locked                 Locked
	Open                   Open
	Salts                  PolicySalts
}

// Policy is the setup's public part.
func (s *Setup) Policy() *Policy {
	return &Policy{ClusterID: s.ClusterID, HandoverGeneration: s.HandoverGeneration, Chain: s.Chain, Safety: s.Safety,
		MaxKeys: s.MaxKeys, SlashingLogMinLockDays: s.SlashingLogMinLockDays, SigningMode: s.SigningMode, Locked: s.Locked, Open: s.Open,
		Salts: s.PolicySalts}
}

// setup is a setup with the public part only, for the field lists and the
// rules of the public part.
func (p *Policy) setup() *Setup {
	return &Setup{ClusterID: p.ClusterID, HandoverGeneration: p.HandoverGeneration, Chain: p.Chain, Safety: p.Safety,
		MaxKeys: p.MaxKeys, SlashingLogMinLockDays: p.SlashingLogMinLockDays, SigningMode: p.SigningMode, Locked: p.Locked, Open: p.Open,
		PolicySalts: p.Salts}
}

// Check applies the value rules of the public part and checks its salts.
func (p *Policy) Check() error {
	s := p.setup()
	if err := s.checkPublic(); err != nil {
		return err
	}
	if err := s.checkGroups(); err != nil {
		return err
	}
	return p.Salts.check()
}

// Leaves are the leaves of the three groups, in leaf order.
func (p *Policy) Leaves() (public, locked, open []Leaf, err error) {
	if err := p.Check(); err != nil {
		return nil, nil, nil, err
	}
	s := p.setup()
	return leaves(s.publicFields(), p.Salts.Public), leaves(p.Locked.fields(), p.Salts.Locked), leaves(p.Open.fields(), p.Salts.Open), nil
}

// Root is policy_root.
func (p *Policy) Root() ([32]byte, error) {
	pub, locked, open, err := p.Leaves()
	if err != nil {
		return [32]byte{}, err
	}
	return PolicyRootOf(GroupRoot(pub), GroupRoot(locked), GroupRoot(open)), nil
}

// PolicyFromLeaves rebuilds the public part from the leaves of its three
// groups, each list in leaf order with every name, value and salt. It is as
// strict as DecodeSetup: the names must be the leaf names in order, the
// values must decode with nothing left over and pass the value rules, and
// each value must be the exact bytes the decoded field encodes to, so one
// policy has one set of leaves.
func PolicyFromLeaves(public, locked, open []Leaf) (*Policy, error) {
	pubNames, lockedNames, openNames := LeafNames()
	groups := []struct {
		what   string
		leaves []Leaf
		names  []string
	}{{"public", public, pubNames}, {"locked", locked, lockedNames}, {"open", open, openNames}}
	values := make([][]byte, len(groups))
	salts := make([]Salts, len(groups))
	for i, g := range groups {
		if len(g.leaves) != len(g.names) {
			return nil, fmt.Errorf("policy: %d %s leaves, want %d", len(g.leaves), g.what, len(g.names))
		}
		for j, l := range g.leaves {
			if l.Name != g.names[j] {
				return nil, fmt.Errorf("policy: %s leaf %d is %q, want %q", g.what, j, l.Name, g.names[j])
			}
			values[i] = append(values[i], l.Value...)
			salts[i] = append(salts[i], l.Salt)
		}
	}
	p := &Policy{Salts: PolicySalts{Public: salts[0], Locked: salts[1], Open: salts[2]}}
	r := &reader{b: values[0]}
	v := r.u8()
	if r.err == nil && v != FormatVersion {
		return nil, fmt.Errorf("policy: setup_format_version %d, want %d", v, FormatVersion)
	}
	r.fixed(p.ClusterID[:])
	p.HandoverGeneration = r.u64()
	readChain(r, &p.Chain)
	readSafety(r, &p.Safety)
	p.MaxKeys = r.u32()
	p.SlashingLogMinLockDays = r.u32()
	p.SigningMode = SigningMode(r.u8())
	if err := r.done(); err != nil {
		return nil, fmt.Errorf("policy: public: %w", err)
	}
	r = &reader{b: values[1]}
	readLocked(r, &p.Locked)
	if err := r.done(); err != nil {
		return nil, fmt.Errorf("policy: locked: %w", err)
	}
	r = &reader{b: values[2]}
	readOpen(r, &p.Open)
	if err := r.done(); err != nil {
		return nil, fmt.Errorf("policy: open: %w", err)
	}
	pub, lk, op, err := p.Leaves()
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	for i, got := range [][]Leaf{pub, lk, op} {
		for j := range got {
			if !bytes.Equal(got[j].Value, groups[i].leaves[j].Value) {
				return nil, fmt.Errorf("policy: %s leaf %s does not encode back to the same bytes", groups[i].what, got[j].Name)
			}
		}
	}
	return p, nil
}
