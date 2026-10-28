//go:build peerselect

package runnerclient

import (
	"strings"
	"testing"
)

// In a build with peerselect, only the verifiers of the peer_* tags exist,
// and asking for another one says which tag it needs.
func TestPeerSelect(t *testing.T) {
	all := map[string]string{VerifierDev: "peer_dev", VerifierAzureMAA: "peer_azure", VerifierAWSNitro: "peer_aws", VerifierGCPCS: "peer_gcp"}
	n := 0
	for v, tag := range all {
		if Available(v) {
			n++
			continue
		}
		a := &Attestation{Verifier: v}
		err := a.Validate()
		if err == nil || !strings.Contains(err.Error(), "is not built into this program (build tag "+tag+")") {
			t.Fatalf("%s: %v", v, err)
		}
		t.Logf("%s not built in: %v", v, err)
	}
	if n == 0 {
		t.Fatal("no verifier built in; build with a peer_* tag")
	}
}
