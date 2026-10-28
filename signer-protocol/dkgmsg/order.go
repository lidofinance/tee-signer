package dkgmsg

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

// DKG orders (backend/dkgorder): the key generation of a runner with a
// setup. The relay pushes the signed order with DKG_ORDER; each runner
// checks it, keeps it sealed with its arrival time and answers with its
// state. Every key generation message for that order then travels in a
// DKG_IN_ORDER envelope that names the order, so one runner serves several
// orders (the Dirk fork lanes and the Charon lane) and keeps their shares
// apart.
const (
	// TypeOrder takes a signed DKG order and returns its OrderState.
	TypeOrder wire.MsgType = 0x27
	// TypeInOrder carries a HELLO, DEAL, FINISH, COMMIT, ABORT or
	// SETUP_SIGN of one order: order_hash[32] type:u8 payload. The answer
	// is the inner message's.
	TypeInOrder wire.MsgType = 0x28
)

// Order outcomes of DKG_ORDER.
const (
	OrderAccepted uint8 = 1 // new on this runner, or replaces a copy whose signatures no longer count
	OrderKnown    uint8 = 2 // the runner holds it already; its arrival time stays
)

// OrderStatus is where an order stands on one runner.
type OrderStatus uint8

const (
	// OrderPending: it waits out its time from the arrival.
	OrderPending OrderStatus = 1
	// OrderActive: it makes keys and signs their setup messages.
	OrderActive OrderStatus = 2
	// OrderExpired: past not_after it makes no more keys; the setup
	// messages of the keys it made are still signed.
	OrderExpired OrderStatus = 3
	// OrderVoid: its signatures do not verify under the approver set in
	// force (a rotation), or an image it names left the allowed list. It
	// does nothing until approvers in force sign it again.
	OrderVoid OrderStatus = 4
)

func (s OrderStatus) String() string {
	switch s {
	case OrderPending:
		return "pending"
	case OrderActive:
		return "active"
	case OrderExpired:
		return "expired"
	case OrderVoid:
		return "void"
	}
	return fmt.Sprintf("status %d", s)
}

// OrderState is the DKG_ORDER answer.
type OrderState struct {
	Outcome  uint8
	Status   OrderStatus
	Hash     [32]byte
	Position uint8  // this runner's participant index, from 0
	Arrived  uint64 // Unix seconds, on the runner's clock
	ActAt    uint64 // arrival plus the wait
	NotAfter uint64
	// Why says what makes the order void, or is empty.
	Why string
}

// OrderStateLen is the length of an encoded OrderState without Why.
const OrderStateLen = 1 + 1 + 32 + 1 + 8 + 8 + 8 + 2

// MaxOrderWhy bounds the reason text.
const MaxOrderWhy = 512

// Encode: outcome:u8 status:u8 hash[32] position:u8 arrived:u64 act_at:u64
// not_after:u64 why_len:u16 why.
func (s *OrderState) Encode() []byte {
	why := s.Why
	if len(why) > MaxOrderWhy {
		why = why[:MaxOrderWhy]
	}
	b := make([]byte, 0, OrderStateLen+len(why))
	b = append(b, s.Outcome, byte(s.Status))
	b = append(b, s.Hash[:]...)
	b = append(b, s.Position)
	b = binary.BigEndian.AppendUint64(b, s.Arrived)
	b = binary.BigEndian.AppendUint64(b, s.ActAt)
	b = binary.BigEndian.AppendUint64(b, s.NotAfter)
	b = binary.BigEndian.AppendUint16(b, uint16(len(why)))
	return append(b, why...)
}

func DecodeOrderState(b []byte) (*OrderState, error) {
	r := &reader{b: b}
	s := &OrderState{Outcome: r.u8(), Status: OrderStatus(r.u8())}
	r.fixed(s.Hash[:])
	s.Position = r.u8()
	s.Arrived = r.u64()
	s.ActAt = r.u64()
	s.NotAfter = r.u64()
	n := int(r.u16())
	if r.err == nil && n > MaxOrderWhy {
		return nil, fmt.Errorf("dkgmsg: order state reason of %d bytes, at most %d", n, MaxOrderWhy)
	}
	s.Why = string(r.take(n))
	if err := r.done(); err != nil {
		return nil, err
	}
	if s.Outcome != OrderAccepted && s.Outcome != OrderKnown || s.Status < OrderPending || s.Status > OrderVoid {
		return nil, errors.New("dkgmsg: order state with an unknown outcome or status")
	}
	return s, nil
}

func (r *reader) u64() uint64 {
	if v := r.take(8); v != nil {
		return binary.BigEndian.Uint64(v)
	}
	return 0
}

// InOrder is a key generation message of one order.
type InOrder struct {
	Order   [32]byte
	Type    wire.MsgType
	Payload []byte
}

// inOrderTypes are the messages that travel in a DKG_IN_ORDER envelope.
func inOrderType(t wire.MsgType) bool {
	switch t {
	case TypeHello, TypeDeal, TypeFinish, TypeCommit, TypeAbort, TypeSetupSign:
		return true
	}
	return false
}

// Encode: order_hash[32] type:u8 payload.
func (m *InOrder) Encode() ([]byte, error) {
	if !inOrderType(m.Type) {
		return nil, fmt.Errorf("dkgmsg: message type %#02x does not travel in an order envelope", byte(m.Type))
	}
	b := make([]byte, 0, 33+len(m.Payload))
	b = append(b, m.Order[:]...)
	b = append(b, byte(m.Type))
	return append(b, m.Payload...), nil
}

func DecodeInOrder(b []byte) (*InOrder, error) {
	if len(b) < 33 {
		return nil, errShort
	}
	m := &InOrder{Type: wire.MsgType(b[32]), Payload: b[33:]}
	copy(m.Order[:], b)
	if !inOrderType(m.Type) {
		return nil, fmt.Errorf("dkgmsg: message type %#02x does not travel in an order envelope", b[32])
	}
	return m, nil
}
