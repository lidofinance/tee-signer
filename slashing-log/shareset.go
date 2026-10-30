package markstore

import (
	"bytes"
	"crypto/sha256"
	"slices"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// ShareSet is the share set commitment a record carries: the root of the
// stored share records the runner wrote (Current), and the root of the set
// after a write it announced and may not have made yet (Pending). A runner
// at start loads the stored records only if their root is one of the two;
// else it loads every key without history and with a fresh source floor
// (durable-state.md, "Share records").
type ShareSet struct {
	Current [32]byte
	Pending *[32]byte
}

// Clone copies s.
func (s *ShareSet) Clone() *ShareSet {
	if s == nil {
		return nil
	}
	c := &ShareSet{Current: s.Current}
	if s.Pending != nil {
		p := *s.Pending
		c.Pending = &p
	}
	return c
}

// Vouches reports whether root is the set's current or pending root. A nil
// set vouches for the empty set only.
func (s *ShareSet) Vouches(root [32]byte) bool {
	if s == nil {
		return root == ShareSetRoot(nil)
	}
	return root == s.Current || s.Pending != nil && root == *s.Pending
}

func sameShares(a, b *ShareSet) bool {
	switch {
	case a == nil || b == nil:
		return a == nil && b == nil
	case a.Current != b.Current || (a.Pending == nil) != (b.Pending == nil):
		return false
	}
	return a.Pending == nil || *a.Pending == *b.Pending
}

// ShareSetRoot is the root of a set of stored share records: sha256 over
// the context "signer-share-set-v1" and, in pubkey order, each pubkey and
// the sha256 of its sealed record as stored.
func ShareSetRoot(recs map[backend.Pubkey][32]byte) [32]byte {
	pks := make([]backend.Pubkey, 0, len(recs))
	for pk := range recs {
		pks = append(pks, pk)
	}
	slices.SortFunc(pks, func(a, b backend.Pubkey) int { return bytes.Compare(a[:], b[:]) })
	h := sha256.New()
	h.Write([]byte("signer-share-set-v1"))
	for _, pk := range pks {
		r := recs[pk]
		h.Write(pk[:])
		h.Write(r[:])
	}
	return [32]byte(h.Sum(nil))
}
