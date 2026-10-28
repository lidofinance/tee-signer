package keygen

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/dkgmsg"
)

// TKGPEER-01: IDENTITY evidence must not stand in for a DKG hello. A
// coordinator that knows a runner's hello fields can ask that runner's
// IDENTITY for the hello's attestation nonce with its own SignKey in the
// hello. The hello's user data has a context of its own
// (backend.DKGHelloContext), so the peers refuse such a hello.
func TestHelloFromIdentityRefused(t *testing.T) {
	ctx := context.Background()
	rs := newRunners(t, 3, 2, "")
	q := &dkgmsg.HelloRequest{Nonce: []byte("0123456789abcdef"), Count: 1}
	var hellos [][]byte
	for _, r := range rs {
		b, err := r.DKGHello(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		hellos = append(hellos, b)
	}
	h, err := dkgmsg.DecodeHello(hellos[1])
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	copy(h.SignKey[:], pub)
	// What runner 2's IDENTITY answers for that nonce: its identity under
	// the IDENTITY context.
	nonce := h.AttestNonce()
	if h.Identity.Attestation, err = rs[1].m.env.Attester.Attest(ctx, nonce, backend.IdentityUserData(nonce, h.Identity)); err != nil {
		t.Fatal(err)
	}
	forged, err := h.Encode()
	if err != nil {
		t.Fatal(err)
	}
	_, err = rs[0].DKGDeal(ctx, [][]byte{hellos[0], forged, hellos[2]})
	if err == nil || !strings.Contains(err.Error(), "participant 2") {
		t.Fatalf("a hello with IDENTITY evidence: %v", err)
	}
}
