package setupwire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Published is what a handover target shows of its setup: the public part
// with every salt, and platform_commitment. setup_hash follows from the
// two; the private part stays with the target.
type Published struct {
	Policy             *Policy
	PlatformCommitment [32]byte
}

// PublishedVersion is the version byte of the encoding below.
const PublishedVersion = 1

// MaxPublished bounds an encoded Published: no larger than a whole setup.
const MaxPublished = MaxSetup

// PublishedOf is the published part of a full setup (for tests and the
// target's tool).
func PublishedOf(s *Setup) (*Published, error) {
	pc, err := s.PlatformCommitment()
	if err != nil {
		return nil, err
	}
	return &Published{Policy: s.Policy(), PlatformCommitment: pc}, nil
}

// SetupHash is setup_hash = H(policy_root, platform_commitment). It fails
// on a policy the value rules refuse.
func (p *Published) SetupHash() ([32]byte, error) {
	r, err := p.Policy.Root()
	if err != nil {
		return [32]byte{}, err
	}
	return SetupHashOf(r, p.PlatformCommitment), nil
}

// Encode is
//
//	published = version:u8(1) platform_commitment[32]
//	            group group group            (public, locked, open)
//	group     = leaf_count:u8 {value_len:u32 value salt[32]}
//
// with the leaves of each group in leaf order. The leaf names are fixed by
// the format (LeafNames), so they are not sent.
func (p *Published) Encode() ([]byte, error) {
	pub, locked, open, err := p.Policy.Leaves()
	if err != nil {
		return nil, err
	}
	b := append([]byte{PublishedVersion}, p.PlatformCommitment[:]...)
	for _, g := range [][]Leaf{pub, locked, open} {
		b = append(b, uint8(len(g)))
		for _, l := range g {
			b = binary.BigEndian.AppendUint32(b, uint32(len(l.Value)))
			b = append(b, l.Value...)
			b = append(b, l.Salt[:]...)
		}
	}
	if len(b) > MaxPublished {
		return nil, fmt.Errorf("published policy: %d bytes, at most %d", len(b), MaxPublished)
	}
	return b, nil
}

// DecodePublished reads Encode's form strictly: the version, the leaf
// count of each group, no trailing bytes, and leaves that rebuild a valid
// public part (PolicyFromLeaves: the values decode with nothing left over,
// pass the value rules and encode back to the same bytes; no salt is zero).
func DecodePublished(b []byte) (*Published, error) {
	if len(b) > MaxPublished {
		return nil, fmt.Errorf("published policy: %d bytes, at most %d", len(b), MaxPublished)
	}
	if len(b) < 1+32 {
		return nil, errors.New("published policy: too short")
	}
	if b[0] != PublishedVersion {
		return nil, fmt.Errorf("published policy: version %d, want %d", b[0], PublishedVersion)
	}
	p := &Published{}
	copy(p.PlatformCommitment[:], b[1:33])
	b = b[33:]
	pubNames, lockedNames, openNames := LeafNames()
	var groups [3][]Leaf
	for i, names := range [][]string{pubNames, lockedNames, openNames} {
		if len(b) < 1 {
			return nil, errors.New("published policy: too short")
		}
		if int(b[0]) != len(names) {
			return nil, fmt.Errorf("published policy: group %d has %d leaves, want %d", i, b[0], len(names))
		}
		b = b[1:]
		for _, name := range names {
			if len(b) < 4 {
				return nil, errors.New("published policy: too short")
			}
			n := binary.BigEndian.Uint32(b)
			if uint64(n)+32 > uint64(len(b)-4) {
				return nil, fmt.Errorf("published policy: leaf %s: too short", name)
			}
			l := Leaf{Name: name, Value: append([]byte(nil), b[4:4+n]...)}
			copy(l.Salt[:], b[4+n:4+n+32])
			groups[i] = append(groups[i], l)
			b = b[4+n+32:]
		}
	}
	if len(b) != 0 {
		return nil, fmt.Errorf("published policy: %d trailing bytes", len(b))
	}
	pol, err := PolicyFromLeaves(groups[0], groups[1], groups[2])
	if err != nil {
		return nil, err
	}
	p.Policy = pol
	return p, nil
}
