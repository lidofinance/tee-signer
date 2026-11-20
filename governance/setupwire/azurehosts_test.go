package setupwire

import (
	"strings"
	"testing"
)

// sealing_key_release.akv_endpoint takes
// any host name, so the setup's author can name a server of his own: it
// answers the key rule as locked and releases a sealing key he knows. The
// fix holds the host to <name>.vault.azure.net, as AWS and GCP derive
// their KMS hosts. Whether the setup's author counts as an attacker is a
// product decision: if he is trusted, this test can go. A debug-build exception for the e2e tests is not this
// package's concern.
func TestAzureKeyVaultHostIsAzure(t *testing.T) {
	refused := []string{
		"kv.attacker.example",                        // any domain with a public CA certificate
		"signer-kv.vault.azure.net.attacker.example", // the Azure name as a prefix of another domain
		"vault.azure.net",                            // no vault name
		"signer-kv.vault.azure.net:8443",             // another port on the vault's host
		"169.254.169.254",                            // an IP literal
	}
	for _, host := range refused {
		checkAzureHostRefused(t, "akv_endpoint", host, func(k *KeyRelease) { k.AKVEndpoint = host })
	}
}

// maa_endpoint takes a host outside attest.azure.net; the same host rule as
// akv_endpoint applies, and is product-dependent in the same way.
func TestAzureAttestationHostIsAzure(t *testing.T) {
	for _, host := range []string{"maa.attacker.example", "sharedeus.eus.attest.azure.net.attacker.example"} {
		checkAzureHostRefused(t, "maa_endpoint", host, func(k *KeyRelease) { k.MAAEndpoint = host })
	}
}

// checkAzureHostRefused sets one endpoint of the Azure sample and wants
// both the encoder (setup-tool, signer-admin setup) and the decoder (the
// runner reading its pinned setup) to refuse it, naming the field.
func checkAzureHostRefused(t *testing.T, field, host string, set func(*KeyRelease)) {
	t.Helper()
	s := samples(t)["setup-azure"]
	if _, err := s.Encode(); err != nil {
		t.Fatalf("the Azure sample does not encode: %v", err)
	}
	set(&s.Platform.SealingKeyRelease)
	if _, err := s.Encode(); err == nil || !strings.Contains(err.Error(), field) {
		t.Errorf("%s %q: encode gives %v; want a refusal of a host outside Azure", field, host, err)
	}
	if _, err := DecodeSetup(rawSetup(s)); err == nil || !strings.Contains(err.Error(), field) {
		t.Errorf("%s %q: decode gives %v; want a refusal of a host outside Azure", field, host, err)
	}
}
