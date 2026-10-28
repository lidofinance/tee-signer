package dkgmsg

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

// ---- DKG_OPERATOR --------------------------------------------------------

const ctxOperator = "signer-dkg-operator-v1"

// OperatorRequest asks for the runner's operator key with a fresh nonce.
type OperatorRequest struct{ Nonce []byte }

// Encode: nonce_len:u8 nonce.
func (q *OperatorRequest) Encode() ([]byte, error) {
	if len(q.Nonce) < MinNonce || len(q.Nonce) > MaxNonce {
		return nil, fmt.Errorf("dkgmsg: operator request needs a nonce of %d to %d bytes", MinNonce, MaxNonce)
	}
	return append([]byte{byte(len(q.Nonce))}, q.Nonce...), nil
}

func DecodeOperatorRequest(b []byte) (*OperatorRequest, error) {
	r := &reader{b: b}
	q := &OperatorRequest{Nonce: append([]byte(nil), r.take(int(r.u8()))...)}
	if err := r.done(); err != nil {
		return nil, err
	}
	if _, err := q.Encode(); err != nil {
		return nil, err
	}
	return q, nil
}

// OperatorInfo is a runner's operator key: an Ed25519 key the runner made
// once and keeps sealed, so only a runner that can unseal that operator's
// storage (its sealing key comes from the operator's own KMS or Key Vault)
// reports it. The policy pins it per position. Identity binds
// backend.DKGOperatorUserData(AttestNonce(), Identity), a context of its own,
// so an IDENTITY answer for the same nonce does not pass for it.
type OperatorInfo struct {
	Nonce    []byte
	Key      [32]byte
	Identity *backend.Identity
}

// AttestNonce is the nonce the runner attests the identity with.
func (o *OperatorInfo) AttestNonce() []byte {
	h := sha256.New()
	h.Write([]byte(ctxOperator))
	h.Write([]byte{byte(len(o.Nonce))})
	h.Write(o.Nonce)
	h.Write(o.Key[:])
	return h.Sum(nil)
}

// Encode: nonce_len:u8 nonce key[32] identity.
func (o *OperatorInfo) Encode() ([]byte, error) {
	id, err := wire.EncodeIdentity(o.Identity)
	if err != nil {
		return nil, err
	}
	p := append([]byte{byte(len(o.Nonce))}, o.Nonce...)
	p = append(p, o.Key[:]...)
	return append(p, id...), nil
}

func DecodeOperatorInfo(b []byte) (*OperatorInfo, error) {
	r := &reader{b: b}
	o := &OperatorInfo{Nonce: append([]byte(nil), r.take(int(r.u8()))...)}
	r.fixed(o.Key[:])
	if r.err != nil {
		return nil, r.err
	}
	id, err := wire.DecodeIdentity(r.b)
	if err != nil {
		return nil, err
	}
	o.Identity = id
	return o, nil
}

// ---- DKG_SETUP_SIGN ------------------------------------------------------

// SetupKind names what a DKG_SETUP_SIGN request asks the runner to sign.
type SetupKind uint8

const (
	// SetupDeposit: DepositMessage(pubkey, withdrawal_credentials, amount)
	// under DOMAIN_DEPOSIT with the genesis fork version.
	SetupDeposit SetupKind = 1
	// SetupRegistration: a builder registration (ValidatorRegistrationV1).
	SetupRegistration SetupKind = 2
	// SetupCharonLock: a whole Charon cluster-lock.json; the runner signs the
	// lock hash it computes with each of its shares the lock names.
	SetupCharonLock SetupKind = 3
)

// MaxLock bounds the lock JSON of a SetupCharonLock request.
const MaxLock = wire.MaxFrame - 1024

// Deposit is the full DepositMessage.
type Deposit struct {
	Pubkey                backend.Pubkey
	WithdrawalCredentials backend.Root
	Amount                uint64 // gwei
}

// SetupRequest is one DKG_SETUP_SIGN request; exactly one of the fields
// for its kind is set.
type SetupRequest struct {
	Kind         SetupKind
	Deposit      *Deposit
	Registration *backend.ValidatorRegistration
	Lock         []byte
}

// Encode: kind:u8 then, by kind, pubkey[48] withdrawal_credentials[32]
// amount:u64; or the 84-byte SSZ of the registration; or the lock JSON.
func (q *SetupRequest) Encode() ([]byte, error) {
	p := []byte{byte(q.Kind)}
	switch q.Kind {
	case SetupDeposit:
		if q.Deposit == nil {
			return nil, errors.New("dkgmsg: deposit request without a deposit")
		}
		p = append(p, q.Deposit.Pubkey[:]...)
		p = append(p, q.Deposit.WithdrawalCredentials[:]...)
		return binary.BigEndian.AppendUint64(p, q.Deposit.Amount), nil
	case SetupRegistration:
		if q.Registration == nil {
			return nil, errors.New("dkgmsg: registration request without a registration")
		}
		b, err := backend.EncodeSSZ(q.Registration)
		if err != nil {
			return nil, err
		}
		return append(p, b...), nil
	case SetupCharonLock:
		if len(q.Lock) == 0 || len(q.Lock) > MaxLock {
			return nil, errors.New("dkgmsg: lock missing or too large")
		}
		return append(p, q.Lock...), nil
	}
	return nil, fmt.Errorf("dkgmsg: unknown setup kind %d", q.Kind)
}

func DecodeSetupRequest(b []byte) (*SetupRequest, error) {
	if len(b) < 1 {
		return nil, errShort
	}
	q := &SetupRequest{Kind: SetupKind(b[0])}
	body := b[1:]
	switch q.Kind {
	case SetupDeposit:
		if len(body) != 48+32+8 {
			return nil, errors.New("dkgmsg: deposit request: want 88 bytes")
		}
		d := &Deposit{Amount: binary.BigEndian.Uint64(body[80:])}
		copy(d.Pubkey[:], body[:48])
		copy(d.WithdrawalCredentials[:], body[48:80])
		q.Deposit = d
	case SetupRegistration:
		m, err := backend.DecodeSSZ(backend.KindValidatorRegistration, body)
		if err != nil {
			return nil, fmt.Errorf("dkgmsg: registration: %w", err)
		}
		q.Registration = m.(*backend.ValidatorRegistration)
	case SetupCharonLock:
		if len(body) == 0 || len(body) > MaxLock {
			return nil, errors.New("dkgmsg: lock missing or too large")
		}
		q.Lock = append([]byte(nil), body...)
	default:
		return nil, fmt.Errorf("dkgmsg: unknown setup kind %d", q.Kind)
	}
	return q, nil
}

// LockSignature is one share's signature over a lock hash.
type LockSignature struct {
	Pubkey    backend.Pubkey // validator key
	Signature backend.Signature
}

// LockSigned is the answer to SetupCharonLock.
type LockSigned struct {
	LockHash   backend.Root
	Signatures []LockSignature
}

// Encode: lock_hash[32] count:u16 (pubkey[48] signature[96])*.
func (l *LockSigned) Encode() []byte {
	p := append([]byte(nil), l.LockHash[:]...)
	p = binary.BigEndian.AppendUint16(p, uint16(len(l.Signatures)))
	for _, s := range l.Signatures {
		p = append(p, s.Pubkey[:]...)
		p = append(p, s.Signature[:]...)
	}
	return p
}

func DecodeLockSigned(b []byte) (*LockSigned, error) {
	r := &reader{b: b}
	l := &LockSigned{}
	r.fixed(l.LockHash[:])
	n := int(r.u16())
	for range n {
		var s LockSignature
		r.fixed(s.Pubkey[:])
		r.fixed(s.Signature[:])
		if r.err != nil {
			break
		}
		l.Signatures = append(l.Signatures, s)
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	return l, nil
}
