//go:build platform_aws

package transport

import "testing"

// The AWS build has vsock. Listening on every CID works on kernels with
// vsock support even without loopback; it is skipped where it does not.
func TestVsockInTheAWSBuild(t *testing.T) {
	if !HasVsock() {
		t.Fatal("no vsock in a build with platform_aws")
	}
	a, err := Parse("vsock:any:7191")
	if err != nil {
		t.Fatal(err)
	}
	l, err := Listen(a)
	if err != nil {
		t.Skipf("vsock listen failed here: %v", err)
	}
	l.Close()
}
