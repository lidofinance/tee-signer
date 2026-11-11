package gcp

import (
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/platform"
)

func TestCheckSetupProject(t *testing.T) {
	const (
		prov = "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/signer/providers/runner"
		key  = "projects/123456789/locations/europe-west4/keyRings/signer/cryptoKeys/sealing"
	)
	for _, c := range []struct {
		name, provider, key, number, err string
	}{
		{"no project_number", "anything", "anything", "", ""},
		{"no project_number, domain-scoped project ID", prov, "projects/example.com:signer/locations/l/keyRings/r/cryptoKeys/k", "", ""},
		{"same project, key by number", prov, key, "123456789", ""},
		// rv-nsd.9: a key by project ID could be of any project.
		{"key by project ID", prov, "projects/signer-prod/locations/europe-west4/keyRings/signer/cryptoKeys/sealing", "123456789", "by project number"},
		{"key by domain-scoped project ID", prov, "projects/example.com:signer/locations/l/keyRings/r/cryptoKeys/k", "123456789", "by project number"},
		{"provider of another project", strings.Replace(prov, "123456789", "987654321", 1), key, "123456789", "wif_provider"},
		{"key of another project number", prov, "projects/987654321/locations/europe-west4/keyRings/signer/cryptoKeys/sealing", "123456789", "KMS key of project 987654321"},
		{"key with more segments", prov, "projects/123456789/locations/l/keyRings/r/cryptoKeys/k/../../../../projects/9/locations/l/keyRings/r/cryptoKeys/k", "123456789", "not a KMS key name"},
		{"bad number", prov, key, "12x", "not a project number"},
	} {
		err := checkSetupProject(c.provider, c.key, c.number)
		switch {
		case c.err == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
			t.Errorf("%s: %v, want an error with %q", c.name, err, c.err)
		}
	}
}

// New refuses a setup whose WIF provider is outside its project_number
// before it talks to anything.
func TestNewChecksTheSetupProject(t *testing.T) {
	_, err := New(platform.Options{StateDir: t.TempDir(), Params: map[string]string{
		"wif_provider":   "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/q",
		"kms_key":        testKey,
		"project_number": "2",
	}})
	if err == nil || !strings.Contains(err.Error(), "wif_provider") {
		t.Fatalf("New with a provider of another project: %v", err)
	}
}
