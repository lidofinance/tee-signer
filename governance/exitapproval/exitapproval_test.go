package exitapproval

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

func approver(id byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{id}, 32))
}

// The approval has the TA's 152-byte layout (signer_ta.h, struct
// signer_ta_exit_approval), reads back, and verifies under k approvers.
func TestLayoutAndVerify(t *testing.T) {
	a := Approval{GenesisValidatorsRoot: backend.Root{1}, Pubkey: backend.Pubkey{2}, ValidatorIndex: 3, ExitEpoch: 4,
		EffectiveBalance: 5, NotAfter: 6, Nonce: [32]byte{7}}
	enc := a.Encode()
	if len(enc) != Len || Len != 152 || string(enc[:8]) != "SIGPEXA1" || binary.LittleEndian.Uint64(enc[88:]) != 3 || enc[120] != 7 {
		t.Fatalf("layout: %x", enc)
	}
	s := Signed{Approval: a}
	for _, id := range []byte{1, 3} {
		s.Approvals = append(s.Approvals, setupwire.Approval{Position: id - 1, Signature: Sign(approver(id), &a)})
	}
	raw, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := Decode(raw)
	if err != nil || back.Approval != a {
		t.Fatalf("decode: %+v %v", back, err)
	}
	set := setupwire.ApproverSet{ApprovalsNeeded: 2}
	for _, id := range []byte{1, 2, 3} {
		set.Keys = append(set.Keys, [32]byte(approver(id).Public().(ed25519.PublicKey)))
	}
	if err := back.Verify(&set, 2); err != nil {
		t.Fatal(err)
	}
	if err := back.Verify(&set, 3); err == nil {
		t.Fatal("two signatures passed with three needed")
	}
	back.Approval.ExitEpoch++
	if err := back.Verify(&set, 2); err == nil {
		t.Fatal("a changed epoch verified")
	}
	for name, r := range map[string][]byte{"trailing": append(append([]byte{}, raw...), 0), "short": raw[:Len], "magic": append([]byte{0}, raw[1:]...)} {
		if _, err := Decode(r); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
}

// A hash-then-sign signature counts like a direct one; one made under
// another kind's hashed context does not.
func TestHashedSignature(t *testing.T) {
	a := Approval{GenesisValidatorsRoot: backend.Root{1}, Pubkey: backend.Pubkey{2}, ValidatorIndex: 3, ExitEpoch: 4,
		EffectiveBalance: 5, NotAfter: 6, Nonce: [32]byte{7}}
	s := Signed{Approval: a, Approvals: []setupwire.Approval{
		{Position: 0, Signature: Sign(approver(1), &a)}, {Position: 2, Signature: SignHashed(approver(3), &a)}}}
	set := setupwire.ApproverSet{ApprovalsNeeded: 2}
	for _, id := range []byte{1, 2, 3} {
		set.Keys = append(set.Keys, [32]byte(approver(id).Public().(ed25519.PublicKey)))
	}
	if err := s.Verify(&set, 2); err != nil {
		t.Fatalf("direct and hashed: %v", err)
	}
	s.Approvals[1].Signature = setupwire.SignApproval(approver(3), setupwire.CtxConfigUpdate, true, a.Encode())
	if err := s.Verify(&set, 2); err == nil {
		t.Fatal("a signature under the config update's hashed context verified")
	}
}
