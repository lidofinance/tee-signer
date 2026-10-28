package handover

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// The carry: the mark log state a target needs besides the shares and
// the mark, and the set of shares the source hands over
// (server/handover_source.go).
//
//	carry = version:u8(1) total:u32 keys_hash[32] has_exits:u8
//	        [day:u64 stake:u64 count:u16 {pubkey[48] validator_index:u64 exit_epoch:u64 stake:u64 nonce[32]}]
//
// The exits are the day's exits of the source's mark log with their
// validator keys, their stake and their approvals' nonces, so a handover
// frees neither the day's stake cap nor a used approval, and a repeat of a
// carried exit matches on the target (markstore.ExitEntry).
// The key set is how many shares the source hands over and
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

// MaxCarriedExits bounds the exits of a carry: the mark log's bound
// (markstore.MaxExitsPerDay).
const MaxCarriedExits = 200

// MaxCarry bounds an encoded carry.
const MaxCarry = 1 + 4 + 32 + 1 + 8 + 8 + 2 + MaxCarriedExits*(48+8+8+8+32)

// Carry is what a source carries besides the shares.
type Carry struct {
	Set   KeySet // the key set the source hands over
	Exits *Exits // the day's exits in the source's mark log; nil: none
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

// Exits is the day's exits of the source's mark log.
type Exits struct {
	Day     uint64 // unix seconds / 86400 on the source's trusted clock
	Stake   uint64 // Gwei counted against exit_stake_cap_per_day
	Entries []Exit
}

// Exit is one exit of the day.
type Exit struct {
	Pubkey         backend.Pubkey
	ValidatorIndex uint64
	ExitEpoch      uint64
	Stake          uint64
	Nonce          [32]byte // the exit approval's
}

func (e *Exits) check() error {
	if n := len(e.Entries); n < 1 || n > MaxCarriedExits {
		return fmt.Errorf("handover carry: %d exits, want 1 to %d", n, MaxCarriedExits)
	}
	var sum uint64
	for _, x := range e.Entries {
		if sum+x.Stake < sum {
			return errors.New("handover carry: exit stake overflows")
		}
		sum += x.Stake
	}
	if sum != e.Stake {
		return fmt.Errorf("handover carry: the exits count %d Gwei, the day's stake is %d", sum, e.Stake)
	}
	return nil
}

// Encode is the carry's encoding.
func (c *Carry) Encode() ([]byte, error) {
	p := []byte{CarryVersion}
	p = binary.BigEndian.AppendUint32(p, c.Set.Total)
	p = append(p, c.Set.KeysHash[:]...)
	if c.Exits == nil {
		return append(p, 0), nil
	}
	if err := c.Exits.check(); err != nil {
		return nil, err
	}
	p = append(p, 1)
	p = binary.BigEndian.AppendUint64(p, c.Exits.Day)
	p = binary.BigEndian.AppendUint64(p, c.Exits.Stake)
	p = binary.BigEndian.AppendUint16(p, uint16(len(c.Exits.Entries)))
	for _, x := range c.Exits.Entries {
		p = append(p, x.Pubkey[:]...)
		p = binary.BigEndian.AppendUint64(p, x.ValidatorIndex)
		p = binary.BigEndian.AppendUint64(p, x.ExitEpoch)
		p = binary.BigEndian.AppendUint64(p, x.Stake)
		p = append(p, x.Nonce[:]...)
	}
	return p, nil
}

// DecodeCarry reads a carry strictly: version 1, a presence byte of 0 or
// 1, 1 to MaxCarriedExits exits whose stakes sum to the day's, no
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
	switch has := c.u8(); {
	case c.err != nil:
	case has > 1:
		return nil, errors.New("handover carry: bad exits flag")
	case has == 1:
		e := &Exits{}
		e.Day = c.u64()
		e.Stake = c.u64()
		n := int(c.u16())
		if c.err == nil && (n < 1 || n > MaxCarriedExits) {
			return nil, fmt.Errorf("handover carry: %d exits, want 1 to %d", n, MaxCarriedExits)
		}
		for range n {
			if c.err != nil {
				break
			}
			var x Exit
			copy(x.Pubkey[:], c.take(48))
			x.ValidatorIndex = c.u64()
			x.ExitEpoch = c.u64()
			x.Stake = c.u64()
			copy(x.Nonce[:], c.take(32))
			e.Entries = append(e.Entries, x)
		}
		if c.err == nil {
			if err := e.check(); err != nil {
				return nil, err
			}
		}
		out.Exits = e
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
