//go:build verifierselect

package verify

import (
	"strings"
	"testing"
)

// In a build with verifierselect, only the verifiers of the platform_*
// tags exist, and asking for another one says which tag it needs.
func TestVerifierSelect(t *testing.T) {
	all := map[string]string{VerifierDev: "platform_dev", VerifierAzureMAA: "platform_azure", VerifierAWSNitro: "platform_aws", VerifierGCPCS: "platform_gcp"}
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
		t.Fatal("no verifier built in; build with a platform_* tag")
	}
}
