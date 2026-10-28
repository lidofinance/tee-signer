//go:build !peerselect

package runnerclient

import (
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// T-125: key_release_sha256 pins the key_release_hash a runner read of the
// rule of the key that releases its sealing key. A runner whose hash
// differs, or is zero (the rule unread, or GCP, which has none), is
// refused before the client sends a request.
func TestKeyReleasePin(t *testing.T) {
	ca := newTestCA(t)
	f := startFakeRunner(t, ca, devAttest)
	st := setupState(effectiveAt)
	st.KeyReleaseHash = backend.Root{0x4b, 0x52}
	f.setState(st)
	c := pinnedConn(t, ca, f)
	c.Attestation.KeyReleaseSHA256 = pinOf(st.KeyReleaseHash)
	if err := health(t, c); err != nil {
		t.Fatalf("the pinned key_release_hash: %v", err)
	}
	c.Attestation.KeyReleaseSHA256 = pinOf(backend.Root{0x99})
	wantErr(t, health(t, c), "the runner's key_release_hash 4b52"+strings.Repeat("0", 60)+" is not the pinned key_release_sha256 99")
	st.KeyReleaseHash = backend.Root{}
	f.setState(st)
	c.Attestation.KeyReleaseSHA256 = pinOf(backend.Root{0x4b, 0x52})
	wantErr(t, health(t, c), "is not the pinned key_release_sha256")
	if n := f.seen(0x01); n != 1 {
		t.Fatalf("%d HEALTH requests, want 1 (the pinned one)", n)
	}
}

func TestKeyReleasePinConfig(t *testing.T) {
	ca := newTestCA(t)
	cert, key := ca.issue(t, t.TempDir(), "client", time.Time{})
	good := Connection{Address: "tcp:signer-1:7100", ClientCert: cert, ClientKey: key,
		Attestation: Attestation{Verifier: VerifierDev, SetupSHA256: pinOf(testSetupHash), KeyReleaseSHA256: "0x" + pinOf(backend.Root{7})}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(a *Attestation)
		want   string
	}{
		{"short", func(a *Attestation) { a.KeyReleaseSHA256 = pinOf(backend.Root{7})[:62] }, "key_release_sha256: want 64 hex digits"},
		{"zero", func(a *Attestation) { a.KeyReleaseSHA256 = pinOf(backend.Root{}) }, "key_release_sha256: zero"},
		{"without setup_sha256", func(a *Attestation) { a.SetupSHA256 = "" }, "key_release_sha256: needs setup_sha256"},
	} {
		c := good
		tc.mutate(&c.Attestation)
		wantErr(t, c.Validate(), tc.want)
	}
}
