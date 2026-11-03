package verify

import (
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// A runner on the flag path has no approvers, no allowed images and a
// client CA its host chose. A cloud verifier without setup_sha256 refuses
// it: only the dev verifier, for tests and local runners, connects to one
// unpinned. A pin to the hash of its -config file still works.
func TestFlagPathUnpinnedOnlyOnDev(t *testing.T) {
	flag := backend.SetupState{SetupHash: fakeConfigHash}
	now := time.Unix(effectiveAt, 0)
	for _, v := range []string{VerifierAzureMAA, VerifierAWSNitro, VerifierGCPCS} {
		p, err := (&Attestation{Verifier: v}).setupPins()
		if err != nil {
			t.Fatalf("%s: %v", v, err)
		}
		wantErr(t, p.check(&flag, now), "the runner has no setup and no setup_sha256 is pinned")
		p, err = (&Attestation{Verifier: v, SetupSHA256: pinOf(flag.SetupHash)}).setupPins()
		if err != nil {
			t.Fatalf("%s pinned: %v", v, err)
		}
		if err := p.check(&flag, now); err != nil {
			t.Fatalf("%s pinned to the config hash: %v", v, err)
		}
	}
	p, err := (&Attestation{Verifier: VerifierDev}).setupPins()
	if err != nil {
		t.Fatal(err)
	}
	if err := p.check(&flag, now); err != nil {
		t.Fatalf("dev, unpinned: %v", err)
	}
}
