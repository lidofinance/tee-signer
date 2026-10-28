//go:build !platform_aws

package transport

import (
	"context"
	"errors"
	"testing"
)

// Without the platform_aws tag a vsock address parses, and dialing or
// listening on it fails with ErrNoVsock.
func TestNoVsockOutsideTheAWSBuild(t *testing.T) {
	if HasVsock() {
		t.Fatal("HasVsock in a build without platform_aws")
	}
	for _, s := range []string{"vsock:16:7100", "vsock:any:7100"} {
		a, err := Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		if a.CID != AnyCID {
			if _, err := Dial(context.Background(), a); !errors.Is(err, ErrNoVsock) {
				t.Fatalf("Dial %s: %v", s, err)
			}
		}
		if _, err := Listen(a); !errors.Is(err, ErrNoVsock) {
			t.Fatalf("Listen %s: %v", s, err)
		}
	}
}
