// Package exitapproval is the exit approval of the OP-TEE trusted app
// (signer_ta.h, struct signer_ta_exit_approval), taken by the runner too
// (issue #4 F4): exit_approvals_needed approvers of the set in force allow
// one voluntary exit, bound to the validator key, its index and the exit
// epoch, state the validator's effective balance, and carry a nonce. The
// runner holds it in memory until an exit matches it or it expires; the
// exit is signed only if one matches and the day's stake cap has room.
//
// The approval has the TA's layout, so one signed approval serves both:
//
//	approval = magic:u64le ("SIGPEXA1") genesis_validators_root[32]
//	           pubkey[48] validator_index:u64le exit_epoch:u64le
//	           effective_balance:u64le (Gwei) not_after:u64le nonce[32]
//	signed   = approval[152] sig_count:u8 {position:u8 signature[64]}
//
// Each signature is Ed25519 over setupwire.CtxTAExitApproval and the
// approval.
package exitapproval

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

const (
	// Magic is "SIGPEXA1" read as a little-endian u64, as in the TA.
	Magic = 0x3141584550474953
	// Len is the approval's size.
	Len = 8 + 32 + 48 + 8*4 + 32
	// MaxLifetime bounds not_after past the runner's clock.
	MaxLifetime = 7 * 86400
)

// Approval is one exit approval.
type Approval struct {
	GenesisValidatorsRoot backend.Root
	Pubkey                backend.Pubkey
	ValidatorIndex        uint64
	ExitEpoch             uint64
	EffectiveBalance      uint64 // Gwei, as the approvers read it from the chain
	NotAfter              uint64 // unix seconds
	Nonce                 [32]byte
}

// Signed is an approval with its approver signatures.
type Signed struct {
	Approval  Approval
	Approvals []setupwire.Approval // ascending positions
}

// Encode is the approval in the TA's layout.
func (a *Approval) Encode() []byte {
	p := binary.LittleEndian.AppendUint64(make([]byte, 0, Len), Magic)
	p = append(p, a.GenesisValidatorsRoot[:]...)
	p = append(p, a.Pubkey[:]...)
	p = binary.LittleEndian.AppendUint64(p, a.ValidatorIndex)
	p = binary.LittleEndian.AppendUint64(p, a.ExitEpoch)
	p = binary.LittleEndian.AppendUint64(p, a.EffectiveBalance)
	p = binary.LittleEndian.AppendUint64(p, a.NotAfter)
	return append(p, a.Nonce[:]...)
}

// Sign is one approver's signature over the approval.
func Sign(key ed25519.PrivateKey, a *Approval) [64]byte {
	var sig [64]byte
	copy(sig[:], ed25519.Sign(key, setupwire.CtxTAExitApproval.Message(a.Encode())))
	return sig
}

// SignHashed is Sign in the hash-then-sign form
// (CtxTAExitApprovalHash). The runner takes it; the TA does not yet.
func SignHashed(key ed25519.PrivateKey, a *Approval) [64]byte {
	return setupwire.SignApproval(key, setupwire.CtxTAExitApproval, true, a.Encode())
}

// Encode returns the signed approval.
func (s *Signed) Encode() ([]byte, error) {
	if n := len(s.Approvals); n < 1 || n > setupwire.MaxApprovers {
		return nil, fmt.Errorf("exit approval: %d signatures, want 1 to %d", n, setupwire.MaxApprovers)
	}
	p := s.Approval.Encode()
	p = append(p, uint8(len(s.Approvals)))
	for _, a := range s.Approvals {
		p = append(p, a.Position)
		p = append(p, a.Signature[:]...)
	}
	return p, nil
}

// Decode reads a signed approval strictly: the TA's magic, 1 to
// MaxApprovers signatures in ascending positions, no trailing bytes.
func Decode(p []byte) (*Signed, error) {
	if len(p) < Len+1 {
		return nil, errors.New("exit approval: too short")
	}
	if binary.LittleEndian.Uint64(p) != Magic {
		return nil, errors.New("exit approval: not an exit approval (magic)")
	}
	s := &Signed{}
	a := &s.Approval
	copy(a.GenesisValidatorsRoot[:], p[8:40])
	copy(a.Pubkey[:], p[40:88])
	a.ValidatorIndex = binary.LittleEndian.Uint64(p[88:])
	a.ExitEpoch = binary.LittleEndian.Uint64(p[96:])
	a.EffectiveBalance = binary.LittleEndian.Uint64(p[104:])
	a.NotAfter = binary.LittleEndian.Uint64(p[112:])
	copy(a.Nonce[:], p[120:152])
	n := int(p[Len])
	rest := p[Len+1:]
	if n < 1 || n > setupwire.MaxApprovers || len(rest) != n*65 {
		return nil, fmt.Errorf("exit approval: %d signatures in %d bytes", n, len(rest))
	}
	for i := range n {
		e := setupwire.Approval{Position: rest[i*65]}
		copy(e.Signature[:], rest[i*65+1:])
		if i > 0 && e.Position <= s.Approvals[i-1].Position {
			return nil, errors.New("exit approval: signatures must be in ascending position order, one per approver")
		}
		s.Approvals = append(s.Approvals, e)
	}
	return s, nil
}

// Verify checks that every signature verifies under the set in force and
// that at least needed approvers signed (exit_approvals_needed).
func (s *Signed) Verify(active *setupwire.ApproverSet, needed uint8) error {
	msg := s.Approval.Encode()
	for _, a := range s.Approvals {
		if int(a.Position) >= len(active.Keys) {
			return fmt.Errorf("exit approval: signature by approver %d, the set in force has %d", a.Position, len(active.Keys))
		}
		if !setupwire.VerifyApproval(active.Keys[a.Position], setupwire.CtxTAExitApproval, a.Signature, msg) {
			return fmt.Errorf("exit approval: the signature of approver %d does not verify under the set in force", a.Position)
		}
	}
	if needed < setupwire.MinThreshold || len(s.Approvals) < int(needed) {
		return fmt.Errorf("exit approval: %d approver signatures, exit_approvals_needed is %d", len(s.Approvals), needed)
	}
	return nil
}
