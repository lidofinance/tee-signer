package keygen

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	"github.com/lidofinance/tee-signer/platform/dev"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/dkgmsg"
)

// The DKG_OPERATOR answer must not be IDENTITY evidence. IDENTITY attests
// IdentityUserData over any nonce a signing or attest-only client sends, so
// a client that computes OperatorInfo.AttestNonce for a key of its choice
// gets an IDENTITY answer that passes for an operator key with that key.
// The answer binds a context of its own.
func TestOperatorAnswerIsNotIdentityEvidence(t *testing.T) {
	st, _ := newStore(t)
	ops, err := LoadOperatorKeys(dev.NewDevSealer(), st, dev.Attester{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := ops.Answer(context.Background(), &dkgmsg.OperatorRequest{Nonce: bytes.Repeat([]byte{7}, 16)}, backend.SetupState{}, []byte("tls"))
	if err != nil {
		t.Fatal(err)
	}
	info, err := dkgmsg.DecodeOperatorInfo(b)
	if err != nil {
		t.Fatal(err)
	}
	nonce := info.AttestNonce()
	if bytes.Equal(info.Identity.Attestation.UserData, backend.IdentityUserData(nonce, info.Identity)) {
		t.Fatal("the DKG_OPERATOR answer binds IDENTITY's user data: an IDENTITY answer for its nonce passes for it")
	}
	att := runnerclient.Attestation{Verifier: runnerclient.VerifierDev}
	verify, err := att.NewDKGOperatorVerifier()
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(context.Background(), nonce, info.Identity); err != nil {
		t.Fatalf("the runner's answer: %v", err)
	}
	// What IDENTITY answers for the same nonce, a key of the client's choice
	// in the answer: refused.
	forged := *info.Identity
	var devAtt dev.Attester
	if forged.Attestation, err = devAtt.Attest(context.Background(), nonce, backend.IdentityUserData(nonce, &forged)); err != nil {
		t.Fatal(err)
	}
	if err := verify(context.Background(), nonce, &forged); err == nil || !strings.Contains(err.Error(), "DKG_OPERATOR") {
		t.Fatalf("IDENTITY evidence as a DKG_OPERATOR answer: %v", err)
	}
}
