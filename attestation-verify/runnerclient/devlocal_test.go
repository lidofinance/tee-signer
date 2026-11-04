package runnerclient

import (
	"strings"
	"testing"
	"time"
)

// The dev verifier takes an unsigned document from whoever answers, so it
// reaches a runner on this machine only: tcp to a loopback address
// (127.0.0.0/8, ::1) or the name localhost. Any other tcp address is
// refused in the settings, before the dial, whatever else the settings
// say, so one wrong address cannot seal a share to a fake on the network
// path. The other verifiers reach any address.
func TestDevVerifierLocalOnly(t *testing.T) {
	ca := newTestCA(t)
	cert, key := ca.issue(t, t.TempDir(), "client", time.Time{})
	const want = "is not local"
	dev := func(addr string) Connection {
		return Connection{Address: addr, ClientCert: cert, ClientKey: key, Attestation: Attestation{Verifier: VerifierDev}}
	}

	for _, addr := range []string{"tcp:192.0.2.10:7100", "tcp:signer-1:7100", "tcp:[2001:db8::1]:7100",
		"tcp:0.0.0.0:7100", "tcp:[::]:7100", "tcp:10.0.0.1:7100", "tcp:127.0.0.1.example.com:7100"} {
		c := dev(addr)
		wantErr(t, c.Validate(), want)
		if _, err := c.New(); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: New: %v, want an error containing %q", addr, err, want)
		}
		pinned := dev(addr)
		pinned.Attestation.SetupSHA256 = pinOf(testSetupHash)
		wantErr(t, pinned.Validate(), want)
		unpinned := dev(addr)
		unpinned.Attestation.AllowUnpinnedSetup = true
		wantErr(t, unpinned.Validate(), want)
	}

	for _, addr := range []string{"tcp:127.0.0.1:7100", "tcp:127.1.2.3:7100", "tcp:[::1]:7100", "tcp:localhost:7100", "tcp:LocalHost:7100"} {
		c := dev(addr)
		if err := c.Validate(); err != nil {
			t.Fatalf("%s with the dev verifier: %v", addr, err)
		}
	}

	maa := dev("tcp:signer-1:7100")
	maa.Attestation = Attestation{Verifier: VerifierAzureMAA, MAAHost: "sharedweu.weu.attest.azure.net", CCEPolicySHA256: goodHostData}
	if err := maa.Validate(); err != nil {
		t.Fatalf("azure-maa to a remote address: %v", err)
	}

	// A dev runner on loopback, end to end.
	f := startFakeRunner(t, ca, devAttest)
	if err := health(t, devConn(t, ca, f)); err != nil {
		t.Fatalf("dev runner on loopback: %v", err)
	}

	// DevLocalOnly, which share-import runs on its plain transport: a unix
	// socket and vsock CID 1 (loopback) are this machine, other CIDs are
	// not; a bad address is an address error for every verifier.
	devAtt := &Attestation{Verifier: VerifierDev}
	for _, addr := range []string{"tcp:127.0.0.1:7100", "tcp:[::1]:7100", "tcp:localhost:7100", "unix:/run/signer/runner.sock", "vsock:1:7100"} {
		if err := DevLocalOnly(devAtt, addr); err != nil {
			t.Fatalf("DevLocalOnly(dev, %s): %v", addr, err)
		}
	}
	for _, addr := range []string{"tcp:192.0.2.10:7100", "tcp:signer-1:7100", "vsock:16:7100", "vsock:2:7100", "vsock:0:7100", "vsock:any:7100"} {
		wantErr(t, DevLocalOnly(devAtt, addr), want)
	}
	for _, addr := range []string{"tcp:signer-1:7100", "unix:/run/signer/runner.sock", "vsock:16:7100"} {
		if err := DevLocalOnly(&maa.Attestation, addr); err != nil {
			t.Fatalf("DevLocalOnly(azure-maa, %s): %v", addr, err)
		}
	}
	wantErr(t, DevLocalOnly(devAtt, "tcp:7100"), "address")
	wantErr(t, DevLocalOnly(&maa.Attestation, "nope"), "address")
}
