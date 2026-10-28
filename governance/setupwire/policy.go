package setupwire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
)

// The split setup hash (research/attestation-prover.md, "Signer changes",
// items 1 and 2; docs/attestation-statement.md in the cloud repo):
//
//	leaf                = H(CtxPolicyLeaf, name_len:u8 name value_len:u32 value salt[32])
//	group root          = Merkle root of the group's leaves (MerkleRoot)
//	policy_root         = H(CtxPolicyRoot, public_root locked_root open_root)
//	platform_commitment = H(CtxPlatformCommitment, platform_salt[32] private)
//	setup_hash          = H(CtxSetup, policy_root platform_commitment)
//
// H(ctx, x) is ctx.Hash(x): SHA-256 over len:u16 ctx x. A leaf's value is
// the field's bytes in the setup (setupwire.go), its name the field's key
// in the human form. Each leaf has a salt of its own, so an operator can
// publish some leaves and withhold others, and a withheld value with few
// possible values cannot be found by trying them.
//
// The root of the locked and the open group is also the group's hash at
// version 0 (Setup.GroupHash), and an update carries the root of its new
// group (update.go), so a field stays checkable, or can stay withheld,
// after updates too.

// Leaf counts of the three groups.
const (
	NumPublicLeaves = 16
	NumLockedLeaves = 19
	NumOpenLeaves   = 2
)

// Salts are the 32-byte salts of a group's leaves, in leaf order.
type Salts [][32]byte

// PolicySalts are the salts of every policy leaf.
type PolicySalts struct {
	Public Salts
	Locked Salts
	Open   Salts
}

// checkSalts refuses a list of the wrong length or with a zero salt. A
// zero salt is a salt nobody drew.
func checkSalts(what string, s Salts, n int) error {
	if len(s) != n {
		if len(s) == 0 {
			return fmt.Errorf("%s: no salts; signer-config draws them", what)
		}
		return fmt.Errorf("%s: %d salts, want one for each of the %d leaves", what, len(s), n)
	}
	for i, salt := range s {
		if salt == ([32]byte{}) {
			return fmt.Errorf("%s: salt %d is zero", what, i)
		}
	}
	return nil
}

func (p *PolicySalts) check() error {
	if err := checkSalts("public", p.Public, NumPublicLeaves); err != nil {
		return err
	}
	if err := checkSalts("locked", p.Locked, NumLockedLeaves); err != nil {
		return err
	}
	return checkSalts("open", p.Open, NumOpenLeaves)
}

// NewSalts draws n salts from r (crypto/rand.Reader outside tests).
func NewSalts(r io.Reader, n int) (Salts, error) {
	out := make(Salts, n)
	for i := range out {
		if _, err := io.ReadFull(r, out[i][:]); err != nil {
			return nil, fmt.Errorf("salts: %w", err)
		}
		if out[i] == ([32]byte{}) {
			return nil, errors.New("salts: the random source gave 32 zero bytes")
		}
	}
	return out, nil
}

// NewPolicySalts draws the salts of every policy leaf from r.
func NewPolicySalts(r io.Reader) (PolicySalts, error) {
	var p PolicySalts
	var err error
	if p.Public, err = NewSalts(r, NumPublicLeaves); err != nil {
		return p, err
	}
	if p.Locked, err = NewSalts(r, NumLockedLeaves); err != nil {
		return p, err
	}
	p.Open, err = NewSalts(r, NumOpenLeaves)
	return p, err
}

// Salted reports whether the setup has salts. One read from an operator's
// human file has none until signer-config draws them.
func (s *Setup) Salted() bool { return !s.unsalted() }

// DrawSalts gives the setup the policy salts p and a platform salt from r.
// signer-config setup draws p once for the signers of a cluster and calls
// this for each of them.
func (s *Setup) DrawSalts(p PolicySalts, r io.Reader) error {
	ps, err := NewSalts(r, 1)
	if err != nil {
		return err
	}
	s.PolicySalts = PolicySalts{Public: slices.Clone(p.Public), Locked: slices.Clone(p.Locked), Open: slices.Clone(p.Open)}
	s.PlatformSalt = ps[0]
	return s.PolicySalts.check()
}

// Leaf is one leaf of the policy tree.
type Leaf struct {
	Name  string
	Value []byte
	Salt  [32]byte
}

// Hash is the leaf's hash.
func (l *Leaf) Hash() [32]byte {
	b := make([]byte, 0, 1+len(l.Name)+4+len(l.Value)+32)
	b = append(b, uint8(len(l.Name)))
	b = append(b, l.Name...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(l.Value)))
	b = append(b, l.Value...)
	b = append(b, l.Salt[:]...)
	return CtxPolicyLeaf.Hash(b)
}

// leaves pairs the fields of a group with its salts.
func leaves(fs []field, salts Salts) []Leaf {
	out := make([]Leaf, len(fs))
	for i, f := range fs {
		w := &writer{}
		f.write(w)
		out[i] = Leaf{Name: f.name, Value: w.b, Salt: salts[i]}
	}
	return out
}

// MerkleRoot is the root over leaf hashes: the list padded with zero
// hashes to the next power of two, then each level the node hashes of
// pairs, H(CtxPolicyNode, left right), up to one hash. One leaf is its own
// root. A leaf or node hash is never 32 zero bytes (that would be a
// SHA-256 preimage), so a padding entry cannot pose as a leaf.
func MerkleRoot(hashes [][32]byte) [32]byte {
	if len(hashes) == 0 {
		return [32]byte{}
	}
	n := 1
	for n < len(hashes) {
		n *= 2
	}
	level := make([][32]byte, n)
	copy(level, hashes)
	for len(level) > 1 {
		next := make([][32]byte, len(level)/2)
		for i := range next {
			next[i] = CtxPolicyNode.Hash(level[2*i][:], level[2*i+1][:])
		}
		level = next
	}
	return level[0]
}

// GroupRoot is the root of the leaves.
func GroupRoot(ls []Leaf) [32]byte {
	hs := make([][32]byte, len(ls))
	for i := range ls {
		hs[i] = ls[i].Hash()
	}
	return MerkleRoot(hs)
}

// PublicLeaves are the leaves of the setup's public group.
func (s *Setup) PublicLeaves() ([]Leaf, error) {
	if err := s.Check(); err != nil {
		return nil, err
	}
	return leaves(s.publicFields(), s.PolicySalts.Public), nil
}

// Leaves are the leaves of the group with salts.
func (l *Locked) Leaves(salts Salts) ([]Leaf, error) {
	if err := l.Check(); err != nil {
		return nil, err
	}
	if err := checkSalts("locked", salts, NumLockedLeaves); err != nil {
		return nil, err
	}
	return leaves(l.fields(), salts), nil
}

// Root is the root of the group's leaves with salts.
func (l *Locked) Root(salts Salts) ([32]byte, error) {
	ls, err := l.Leaves(salts)
	if err != nil {
		return [32]byte{}, err
	}
	return GroupRoot(ls), nil
}

// Leaves are the leaves of the group with salts.
func (o *Open) Leaves(salts Salts) ([]Leaf, error) {
	if err := o.Check(); err != nil {
		return nil, err
	}
	if err := checkSalts("open", salts, NumOpenLeaves); err != nil {
		return nil, err
	}
	return leaves(o.fields(), salts), nil
}

// Root is the root of the group's leaves with salts.
func (o *Open) Root(salts Salts) ([32]byte, error) {
	ls, err := o.Leaves(salts)
	if err != nil {
		return [32]byte{}, err
	}
	return GroupRoot(ls), nil
}

// PolicyRootOf is policy_root over the three group roots.
func PolicyRootOf(public, locked, open [32]byte) [32]byte {
	return CtxPolicyRoot.Hash(public[:], locked[:], open[:])
}

// PolicyRoot is the setup's policy_root.
func (s *Setup) PolicyRoot() ([32]byte, error) {
	pub, err := s.PublicLeaves()
	if err != nil {
		return [32]byte{}, err
	}
	lr, err := s.Locked.Root(s.PolicySalts.Locked)
	if err != nil {
		return [32]byte{}, err
	}
	or, err := s.Open.Root(s.PolicySalts.Open)
	if err != nil {
		return [32]byte{}, err
	}
	return PolicyRootOf(GroupRoot(pub), lr, or), nil
}

// PrivateBytes is the private part as the setup carries it, the bytes
// platform_commitment covers.
func (s *Setup) PrivateBytes() ([]byte, error) {
	if err := s.Check(); err != nil {
		return nil, err
	}
	w := &writer{}
	s.writePrivate(w)
	return w.b, nil
}

// PlatformCommitment is the setup's platform_commitment.
func (s *Setup) PlatformCommitment() ([32]byte, error) {
	b, err := s.PrivateBytes()
	if err != nil {
		return [32]byte{}, err
	}
	return CtxPlatformCommitment.Hash(s.PlatformSalt[:], b), nil
}

// SetupHashOf is setup_hash over its two halves.
func SetupHashOf(policyRoot, platformCommitment [32]byte) [32]byte {
	return CtxSetup.Hash(policyRoot[:], platformCommitment[:])
}

// Hash is the setup's setup_hash.
func (s *Setup) Hash() ([32]byte, error) {
	pr, err := s.PolicyRoot()
	if err != nil {
		return [32]byte{}, err
	}
	pc, err := s.PlatformCommitment()
	if err != nil {
		return [32]byte{}, err
	}
	return SetupHashOf(pr, pc), nil
}

// SetupHash decodes raw strictly and returns its setup_hash.
func SetupHash(raw []byte) ([32]byte, error) {
	s, err := DecodeSetup(raw)
	if err != nil {
		return [32]byte{}, err
	}
	return s.Hash()
}
