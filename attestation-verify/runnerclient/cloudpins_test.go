//go:build !verifierselect

package runnerclient

import (
	"testing"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient/verify"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

// A flag path runner with an MAA token and a client without setup_sha256
// (verify.TestFlagPathUnpinnedOnlyOnDev): refused before the client sends
// a request.
func TestFlagPathRunnerRefusedByUnpinnedMAAClient(t *testing.T) {
	ca := newTestCA(t)
	env := newMAAEnv(t, mainKeySet(t))
	f := startFakeRunner(t, ca, env.attest(tokenSpec{}))
	c := maaConn(t, ca, f, env)
	c.Attestation.SetupSHA256 = ""
	wantErr(t, health(t, c, verify.WithHTTPClient(env.srv.Client())), "the runner has no setup and no setup_sha256 is pinned")
	if n := f.seen(wire.TypeHealth); n != 0 {
		t.Fatalf("the client sent %d HEALTH requests to an unpinned flag path runner", n)
	}
	c.Attestation.SetupSHA256 = pinOf(fakeConfigHash)
	if err := health(t, c, verify.WithHTTPClient(env.srv.Client())); err != nil {
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
