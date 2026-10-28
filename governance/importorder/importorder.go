// Package importorder is the import order: k approvers in force sign it
// under setupwire.CtxImportOrder, and a runner with a setup takes a sealed
// share (IMPORT_SHARE_SEALED) only under one. It names the target runner,
// the validators, the threshold split the shares come from and, for each
// validator, the hash of the split's public commitments (Feldman), so a
// share the runner takes must be a point of that validator's polynomial.
//
// It follows package handoverorder: fixed binary form, strict decoder,
// signatures over the body, verified against the approver set in force.
//
//	body   = 'I' version:u8(1) cluster_id[32] chain_hash[32]
//	         target_setup_hash[32] not_after:u64
//	         t:u8 n:u8 share_index:u8 count:u16 {validator_pubkey[48] commitments_hash[32]}
//	order  = 'J' version:u8(1) body_len:u32 body
//	         sig_count:u8 {position:u8 signature[64]}
//
// Integers are big endian. share_index is the target signer's x
// coordinate in the split (1 to n). commitments_hash is CommitmentsHash of
// the validator's t commitments; commitment 0 is the validator key.
//
// The order's hash is SHA-256 over CtxImportOrder and the body.
package importorder

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

const (
	Version = 1
	// MaxValidators bounds the validators of one order.
	MaxValidators = 1024
	// MaxSize bounds a signed order: MaxValidators entries and eight
	// signatures.
	MaxSize = 2 + 4 + 2 + 32*3 + 8 + 5 + MaxValidators*(48+32) + 1 + setupwire.MaxApprovers*65

	kindBody  = 'I'
	kindOrder = 'J'
)

// Entry is one validator of an order.
type Entry struct {
	Pubkey          backend.Pubkey
	CommitmentsHash [32]byte
}

// Body is what the approvers sign.
type Body struct {
	ClusterID [32]byte
	ChainHash [32]byte // setupwire.Chain.Hash of the target's setup
	Target    [32]byte // setup_hash of the runner that takes the shares
	// NotAfter, Unix seconds: from then on the runner takes no share under
	// the order.
	NotAfter   uint64
	T, N       uint8
	ShareIndex uint8
	Validators []Entry
}

// Order is a signed import order.
type Order struct {
	Body      Body
	Approvals []setupwire.Approval // ascending positions
}

// CommitmentsHash is the hash an order names for a validator's public
// commitments: SHA-256 over CtxImportCommitments and the points in order.
func CommitmentsHash(commitments []backend.Pubkey) [32]byte {
	parts := make([][]byte, len(commitments))
	for i := range commitments {
		parts[i] = commitments[i][:]
	}
	return setupwire.CtxImportCommitments.Hash(parts...)
}

// Check applies the body's value rules. 2t > n: two disjoint groups of
// signers cannot both reach t. A chain's own margin rule comes on top
// (setupwire.CheckThreshold).
func (b *Body) Check() error {
	switch {
	case b.ClusterID == ([32]byte{}):
		return errors.New("import order: cluster_id is zero")
	case b.Target == ([32]byte{}):
		return errors.New("import order: target setup_sha256 is zero")
	case b.NotAfter == 0:
		return errors.New("import order: not_after is 0")
	case b.T < 1 || b.T > b.N:
		return fmt.Errorf("import order: threshold %d of %d, want 1 to n", b.T, b.N)
	case 2*int(b.T) <= int(b.N):
		return fmt.Errorf("import order: threshold %d of %d, want more than half", b.T, b.N)
	case b.ShareIndex < 1 || b.ShareIndex > b.N:
		return fmt.Errorf("import order: share index %d, want 1 to %d", b.ShareIndex, b.N)
	case len(b.Validators) < 1 || len(b.Validators) > MaxValidators:
		return fmt.Errorf("import order: %d validators, want 1 to %d", len(b.Validators), MaxValidators)
	}
	seen := map[backend.Pubkey]bool{}
	for i, v := range b.Validators {
		if seen[v.Pubkey] {
			return fmt.Errorf("import order: validator %d (%s) named twice", i, v.Pubkey.String()[:18])
		}
		seen[v.Pubkey] = true
		if v.CommitmentsHash == ([32]byte{}) {
			return fmt.Errorf("import order: validator %d: commitments hash is zero", i)
		}
	}
	return nil
}

// Encode checks the body and returns the bytes the approvers sign.
func (b *Body) Encode() ([]byte, error) {
	if err := b.Check(); err != nil {
		return nil, err
	}
	p := []byte{kindBody, Version}
	p = append(p, b.ClusterID[:]...)
	p = append(p, b.ChainHash[:]...)
	p = append(p, b.Target[:]...)
	p = binary.BigEndian.AppendUint64(p, b.NotAfter)
	p = append(p, b.T, b.N, b.ShareIndex)
	p = binary.BigEndian.AppendUint16(p, uint16(len(b.Validators)))
	for _, v := range b.Validators {
		p = append(p, v.Pubkey[:]...)
		p = append(p, v.CommitmentsHash[:]...)
	}
	return p, nil
}

var errShort = errors.New("importorder: message too short")

func header(p []byte, kind byte, what string) ([]byte, error) {
	if len(p) < 2 {
		return nil, errShort
	}
	if p[0] != kind {
		return nil, fmt.Errorf("importorder: not a %s (kind byte %#02x, want %#02x)", what, p[0], kind)
	}
	if p[1] != Version {
		return nil, fmt.Errorf("importorder: %s version %d, want %d", what, p[1], Version)
	}
	return p[2:], nil
}

// DecodeBody reads a body strictly: no unknown kind or version, values
// Check accepts, no trailing bytes.
func DecodeBody(raw []byte) (*Body, error) {
	if len(raw) > MaxSize {
		return nil, fmt.Errorf("importorder: body is %d bytes, at most %d", len(raw), MaxSize)
	}
	p, err := header(raw, kindBody, "import order body")
	if err != nil {
		return nil, err
	}
	if len(p) < 32*3+8+3+2 {
		return nil, errShort
	}
	b := &Body{}
	copy(b.ClusterID[:], p)
	copy(b.ChainHash[:], p[32:])
	copy(b.Target[:], p[64:])
	b.NotAfter = binary.BigEndian.Uint64(p[96:])
	b.T, b.N, b.ShareIndex = p[104], p[105], p[106]
	count := int(binary.BigEndian.Uint16(p[107:]))
	p = p[109:]
	if count > MaxValidators || len(p) != count*(48+32) {
		return nil, fmt.Errorf("importorder: %d validators in %d bytes", count, len(p))
	}
	for i := range count {
		var v Entry
		copy(v.Pubkey[:], p[i*80:])
		copy(v.CommitmentsHash[:], p[i*80+48:])
		b.Validators = append(b.Validators, v)
	}
	again, err := b.Encode()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(again, raw) {
		return nil, errors.New("importorder: body does not encode back to the same bytes")
	}
	return b, nil
}

// Hash is the hash of an order body: SHA-256 over CtxImportOrder and it.
func Hash(body []byte) [32]byte { return setupwire.CtxImportOrder.Hash(body) }

// SignBodyHashed is SignBody in the hash-then-sign form (CtxImportOrderHash).
func SignBodyHashed(key ed25519.PrivateKey, body []byte) [64]byte {
	return setupwire.SignApproval(key, setupwire.CtxImportOrder, true, body)
}

// SignBody is one approver's signature over an encoded body.
func SignBody(key ed25519.PrivateKey, body []byte) [64]byte {
	var sig [64]byte
	copy(sig[:], ed25519.Sign(key, setupwire.CtxImportOrder.Message(body)))
	return sig
}

func (o *Order) check() error {
	if err := o.Body.Check(); err != nil {
		return err
	}
	if n := len(o.Approvals); n < 1 || n > setupwire.MaxApprovers {
		return fmt.Errorf("import order: %d approver signatures, want 1 to %d", n, setupwire.MaxApprovers)
	}
	for i, a := range o.Approvals {
		if a.Position >= setupwire.MaxApprovers {
			return fmt.Errorf("import order: signature by position %d, at most %d", a.Position, setupwire.MaxApprovers-1)
		}
		if i > 0 && a.Position <= o.Approvals[i-1].Position {
			return errors.New("import order: approver signatures must be in ascending position order, one per approver")
		}
	}
	return nil
}

// Encode returns the signed order.
func (o *Order) Encode() ([]byte, error) {
	if err := o.check(); err != nil {
		return nil, err
	}
	body, err := o.Body.Encode()
	if err != nil {
		return nil, err
	}
	p := []byte{kindOrder, Version}
	p = binary.BigEndian.AppendUint32(p, uint32(len(body)))
	p = append(p, body...)
	p = append(p, uint8(len(o.Approvals)))
	for _, a := range o.Approvals {
		p = append(p, a.Position)
		p = append(p, a.Signature[:]...)
	}
	return p, nil
}

// Decode reads a signed order strictly. It checks the layout and the
// values, not the signatures: Verify does that.
func Decode(raw []byte) (*Order, error) {
	if len(raw) > MaxSize {
		return nil, fmt.Errorf("importorder: order is %d bytes, at most %d", len(raw), MaxSize)
	}
	p, err := header(raw, kindOrder, "import order")
	if err != nil {
		return nil, err
	}
	if len(p) < 4 {
		return nil, errShort
	}
	n := binary.BigEndian.Uint32(p)
	if n > MaxSize || int(n) > len(p)-4 {
		return nil, errShort
	}
	body, err := DecodeBody(p[4 : 4+n])
	if err != nil {
		return nil, err
	}
	p = p[4+n:]
	o := &Order{Body: *body}
	if len(p) < 1 {
		return nil, errShort
	}
	count := int(p[0])
	p = p[1:]
	if count > setupwire.MaxApprovers || len(p) != count*65 {
		return nil, fmt.Errorf("importorder: %d approver signatures in %d bytes", count, len(p))
	}
	for i := range count {
		a := setupwire.Approval{Position: p[i*65]}
		copy(a.Signature[:], p[i*65+1:])
		o.Approvals = append(o.Approvals, a)
	}
	again, err := o.Encode()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(again, raw) {
		return nil, errors.New("importorder: order does not encode back to the same bytes")
	}
	return o, nil
}

// Verify checks the signatures against the approver set in force: every
// signature verifies and at least k approvers of the set signed.
func (o *Order) Verify(active *setupwire.ApproverSet) error {
	if err := o.check(); err != nil {
		return err
	}
	body, err := o.Body.Encode()
	if err != nil {
		return err
	}
	for _, a := range o.Approvals {
		if int(a.Position) >= len(active.Keys) {
			return fmt.Errorf("import order: signature by approver %d, the set in force has %d", a.Position, len(active.Keys))
		}
		if !setupwire.VerifyApproval(active.Keys[a.Position], setupwire.CtxImportOrder, a.Signature, body) {
			return fmt.Errorf("import order: the signature of approver %d does not verify under the set in force", a.Position)
		}
	}
	if len(o.Approvals) < int(active.ApprovalsNeeded) {
		return fmt.Errorf("import order: %d approver signatures, approvals_needed is %d", len(o.Approvals), active.ApprovalsNeeded)
	}
	return nil
}

// Matches checks that the order is for this setup (cluster, chain,
// target), still valid at now, and names pk; it returns pk's entry.
func (b *Body) Matches(s *setupwire.Setup, setupHash [32]byte, now uint64, pk backend.Pubkey) (*Entry, error) {
	switch {
	case b.ClusterID != s.ClusterID:
		return nil, errors.New("import order: for another cluster_id")
	case b.ChainHash != s.Chain.Hash():
		return nil, errors.New("import order: for another chain")
	case b.Target != setupHash:
		return nil, fmt.Errorf("import order: its target is setup %x, this signer's is %x", b.Target[:8], setupHash[:8])
	case now >= b.NotAfter:
		return nil, fmt.Errorf("import order: expired at %d (now %d)", b.NotAfter, now)
	}
	for i := range b.Validators {
		if b.Validators[i].Pubkey == pk {
			return &b.Validators[i], nil
		}
	}
	return nil, fmt.Errorf("import order: does not name validator %s", pk.String()[:18])
}
