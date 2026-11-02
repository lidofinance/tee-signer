package handover

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// The carry: what a target needs besides the shares and the mark: the
// set of shares the source hands over (server/handover_source.go).
//
//	carry = version:u8(1) total:u32 keys_hash[32] has_exits:u8(0)
//
// has_exits is always 0: an image with exit approvals carried the day's
// exits after it, and this one carries none and refuses a carry that has
// them. The key set is how many shares the source hands over and
// backend.KeysHash over their (pubkey, share_pubkey) pairs. The target
// ends its import only when it holds exactly that set (SHC-01): the
// page's total alone is not authenticated.
//
// Every HANDOVER response carries one after the shares (message.go). Each
// share of the response is sealed under CtxHandoverShare over its header
// and CtxHandoverCarry's hash of the carry, so a host or tool that drops
// or edits the carry makes every share fail to open.

// CarryVersion is the version byte of the carry.
const CarryVersion = 1

// MaxCarry bounds an encoded carry.
const MaxCarry = 1 + 4 + 32 + 1

// Carry is what a source carries besides the shares.
type Carry struct {
	Set KeySet // the key set the source hands over
}

// KeySet is the set of shares a source hands over.
type KeySet struct {
	Total    uint32
	KeysHash [32]byte // backend.KeysHash of the (pubkey, share_pubkey) pairs
}

// SetOf is the key set of keys.
func SetOf(keys []backend.ValidatorKey) KeySet {
	return KeySet{Total: uint32(len(keys)), KeysHash: backend.KeysHash(keys)}
}

// Holds reports whether keys are exactly the set.
func (k *KeySet) Holds(keys []backend.ValidatorKey) bool {
	return uint64(len(keys)) == uint64(k.Total) && backend.KeysHash(keys) == k.KeysHash
}

// Encode is the carry's encoding.
func (c *Carry) Encode() ([]byte, error) {
	p := []byte{CarryVersion}
	p = binary.BigEndian.AppendUint32(p, c.Set.Total)
	p = append(p, c.Set.KeysHash[:]...)
	return append(p, 0), nil
}

// DecodeCarry reads a carry strictly: version 1, has_exits 0, no
// trailing bytes.
func DecodeCarry(b []byte) (*Carry, error) {
	if len(b) > MaxCarry {
		return nil, fmt.Errorf("handover carry: %d bytes, at most %d", len(b), MaxCarry)
	}
	c := &cursor{b: b}
	if v := c.u8(); c.err == nil && v != CarryVersion {
		return nil, fmt.Errorf("handover carry: version %d, want %d", v, CarryVersion)
	}
	out := &Carry{}
	out.Set.Total = c.u32()
	copy(out.Set.KeysHash[:], c.take(32))
	if has := c.u8(); c.err == nil && has != 0 {
		return nil, errors.New("handover carry: has_exits is not 0 (exits from an image with exit approvals)")
	}
	if err := c.done(); err != nil {
		return nil, err
	}
	return out, nil
}

// Hash is the carry's hash, which each share's associated data takes.
func (c *Carry) Hash() ([32]byte, error) {
	enc, err := c.Encode()
	if err != nil {
		return [32]byte{}, err
	}
	return setupwire.CtxHandoverCarry.Hash(enc), nil
}

// AAD is the HPKE associated data the share is sealed under in a
// response whose carry has hash carry: CtxHandoverShare over the header
// and that hash.
func (s *Share) AAD(carry [32]byte) []byte {
	return setupwire.CtxHandoverShare.Message(s.Header(), carry[:])
}

// CarryHash is the hash of the response's carry.
func (r *Response) CarryHash() ([32]byte, error) { return r.Carry.Hash() }
