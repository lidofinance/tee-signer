//go:build !verifierselect

package runnerclient

import (
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
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

// The same against a fake runner with an MAA token: refused before the
// client sends a request.
func TestFlagPathRunnerRefusedByUnpinnedMAAClient(t *testing.T) {
	ca := newTestCA(t)
	env := newMAAEnv(t, mainKeySet(t))
	f := startFakeRunner(t, ca, env.attest(tokenSpec{}))
	c := maaConn(t, ca, f, env)
	c.Attestation.SetupSHA256 = ""
	wantErr(t, health(t, c, WithHTTPClient(env.srv.Client())), "the runner has no setup and no setup_sha256 is pinned")
	if n := f.seen(wire.TypeHealth); n != 0 {
		t.Fatalf("the client sent %d HEALTH requests to an unpinned flag path runner", n)
	}
	c.Attestation.SetupSHA256 = pinOf(fakeConfigHash)
	if err := health(t, c, WithHTTPClient(env.srv.Client())); err != nil {
		t.Fatalf("pinned to its config hash: %v", err)
	}
}

// On mainnet a gcp-cs client names the operator's project and the runner's
// service account. GCP has no key rule hash to pin, so these two are what
// ties the runner to the operator's account: without them a token for the
// same image from any project passes.
func TestGCPMainnetNeedsProjectAndServiceAccount(t *testing.T) {
	good := gcpGood("")
	good.SetupSHA256 = pinOf(testSetupHash)
	good.Mainnet = true
	good.GCPProjectID = "signer-project"
	good.GCPServiceAccount = gcpAccount
	if err := good.Validate(); err != nil {
		t.Fatalf("mainnet with project and service account: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(a *Attestation)
		want   string
	}{
		{"no project", func(a *Attestation) { a.GCPProjectID = "" }, "mainnet: a gcp-cs runner needs gcp_project_id"},
		{"no service account", func(a *Attestation) { a.GCPServiceAccount = "" }, "mainnet: a gcp-cs runner needs gcp_service_account"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := good
			tc.mutate(&a)
			wantErr(t, a.Validate(), tc.want)
			_, err := a.NewVerifier()
			wantErr(t, err, tc.want)
			a.Mainnet = false
			if err := a.Validate(); err != nil {
				t.Fatalf("not mainnet: %v", err)
			}
		})
	}
}
