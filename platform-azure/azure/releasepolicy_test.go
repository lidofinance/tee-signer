package azure

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// An immutable release policy with a second authority whose only claim
// any SEV-SNP VM meets is not a lock: whoever wrote it before setting
// immutable can still get the key. The runner must read the content, not
// only the flag.
func TestImmutablePolicyWithASecondAuthorityIsNotLocked(t *testing.T) {
	f := newKVFixture(t)
	f.kv.immutable = true
	f.kv.policy = `{"version":"1.0.0","anyOf":[
	  {"authority":"https://` + f.maa.client.Endpoint + `","allOf":[{"claim":"x-ms-sevsnpvm-hostdata","equals":"` + testHostData + `"}]},
	  {"authority":"https://attacker.eus.attest.azure.net","allOf":[{"claim":"x-ms-attestation-type","equals":"sevsnpvm"}]}]}`
	r, err := f.releaser.KV.KeyRule(context.Background(), "signer-kek-1")
	if err != nil {
		t.Fatal(err)
	}
	if r.Lock != backend.KeyLockNotLocked || !strings.Contains(r.Why, "authorities") {
		t.Fatalf("lock %s (%q), want not locked", r.Lock, r.Why)
	}
	// The same key with the deploy template's policy is locked.
	f.kv.policy = ""
	if r, err := f.releaser.KV.KeyRule(context.Background(), "signer-kek-1"); err != nil || r.Lock != backend.KeyLockLocked {
		t.Fatalf("template policy: %s %q %v", r.Lock, r.Why, err)
	}
}

// The rendered deploy template is the one policy shape the runner calls
// locked. Every change that lets in another image, another provider or a
// debuggable guest, or that a JSON parser could read two ways, is refused.
func TestReleasePolicyContent(t *testing.T) {
	const maa = "sharedweu.weu.attest.azure.net"
	hd := testHostData
	tmpl := renderSKRPolicy(t, maa, hd)
	got, err := checkReleasePolicy([]byte(tmpl), maa)
	if err != nil || hex.EncodeToString(got) != hd {
		t.Fatalf("rendered template: %x %v", got, err)
	}
	if _, err := checkReleasePolicy([]byte(tmpl), ""); err == nil {
		t.Fatal("no maa_endpoint to compare with, but the policy passed")
	}
	if _, err := checkReleasePolicy([]byte(tmpl), "attacker.eus.attest.azure.net"); err == nil {
		t.Fatal("another provider than the setup's passed")
	}

	claim := func(c, v string) string { return `{"claim":"` + c + `","equals":"` + v + `"}` }
	base := []string{
		claim("x-ms-compliance-status", "azure-compliant-uvm"),
		claim("x-ms-sevsnpvm-hostdata", hd),
		claim("x-ms-sevsnpvm-is-debuggable", "false"),
	}
	auth := func(host string, claims ...string) string {
		return `{"authority":"https://` + host + `","allOf":[` + strings.Join(claims, ",") + `]}`
	}
	pol := func(anyOf ...string) string {
		return `{"version":"1.0.0","anyOf":[` + strings.Join(anyOf, ",") + `]}`
	}
	with := func(extra ...string) []string { return append(append([]string{}, base...), extra...) }
	good := auth(maa, base...)

	for _, c := range []struct {
		name, policy, why string
	}{
		{"second authority (review proof)", pol(auth(maa, claim("x-ms-sevsnpvm-hostdata", hd)),
			auth("attacker.eus.attest.azure.net", claim("x-ms-attestation-type", "sevsnpvm"))), "authorities"},
		{"same authority twice", pol(good, auth(maa, claim("x-ms-attestation-type", "sevsnpvm"))), "authorities"},
		{"no authority", pol(), "authorities"},
		{"other authority", pol(auth("attacker.eus.attest.azure.net", base...)), "authority is"},
		{"authority without scheme", strings.Replace(pol(good), "https://", "", 1), "authority is"},
		{"version", strings.Replace(pol(good), "1.0.0", "1.0.1", 1), "version"},
		{"no hostdata", pol(auth(maa, base[0], base[2])), "x-ms-sevsnpvm-hostdata"},
		{"no compliance", pol(auth(maa, base[1], base[2])), "x-ms-compliance-status"},
		{"no debuggable", pol(auth(maa, base[0], base[1])), "is-debuggable"},
		{"debuggable", pol(auth(maa, base[0], base[1], claim("x-ms-sevsnpvm-is-debuggable", "true"))), "is-debuggable"},
		{"not compliant", pol(auth(maa, claim("x-ms-compliance-status", "x"), base[1], base[2])), "compliance"},
		{"vmpl 1", pol(auth(maa, with(claim("x-ms-sevsnpvm-vmpl", "1"))...)), "vmpl"},
		{"unknown claim", pol(auth(maa, with(claim("x-ms-attestation-type", "sevsnpvm"))...)), "does not know"},
		{"claim twice", pol(auth(maa, with(claim("x-ms-sevsnpvm-hostdata", strings.Repeat("6b", 32)))...)), "twice"},
		{"short hostdata", pol(auth(maa, base[0], claim("x-ms-sevsnpvm-hostdata", "5a5a"), base[2])), "32 bytes"},
		{"zero hostdata", pol(auth(maa, base[0], claim("x-ms-sevsnpvm-hostdata", strings.Repeat("00", 32)), base[2])), "all zero"},
		{"empty hostdata", pol(auth(maa, base[0], claim("x-ms-sevsnpvm-hostdata", ""), base[2])), "32 bytes"},
		{"other operator", pol(auth(maa, with(`{"claim":"x-ms-sevsnpvm-vmpl","notEquals":"1"}`)...)), "not allowed"},
		{"bool value", pol(auth(maa, base[0], base[1], `{"claim":"x-ms-sevsnpvm-is-debuggable","equals":false}`)), "not a string"},
		{"nested anyOf", pol(auth(maa, with(`{"anyOf":[`+claim("x-ms-sevsnpvm-vmpl", "0")+`]}`)...)), "not allowed"},
		{"anyOf beside allOf", pol(`{"authority":"https://` + maa + `","allOf":[` + strings.Join(base, ",") + `],"anyOf":[]}`), "not allowed"},
		{"top-level allOf", `{"version":"1.0.0","allOf":[` + good + `]}`, "not allowed"},
		{"duplicate authority member", pol(`{"authority":"https://` + maa + `","authority":"https://attacker.eus.attest.azure.net","allOf":[` + strings.Join(base, ",") + `]}`), "twice"},
		{"duplicate equals member", pol(auth(maa, base[0], `{"claim":"x-ms-sevsnpvm-hostdata","equals":"`+hd+`","equals":"`+strings.Repeat("6b", 32)+`"}`, base[2])), "twice"},
		{"duplicate anyOf member", `{"version":"1.0.0","anyOf":[` + good + `],"anyOf":[]}`, "twice"},
		{"data after the object", pol(good) + `{}`, "after"},
		{"not an object", `[]`, "not a JSON object"},
	} {
		_, err := checkReleasePolicy([]byte(c.policy), maa)
		if err == nil || !strings.Contains(err.Error(), c.why) {
			t.Errorf("%s: %v, want an error with %q", c.name, err, c.why)
		}
	}

	// Locked variants: vmpl 0 present or absent, members in another order,
	// the authority in upper case.
	for _, p := range []string{
		pol(good),
		pol(auth(maa, with(claim("x-ms-sevsnpvm-vmpl", "0"))...)),
		pol(auth(maa, base[2], base[1], base[0])),
		`{"anyOf":[{"allOf":[` + strings.Join(base, ",") + `],"authority":"HTTPS://SHAREDWEU.WEU.ATTEST.AZURE.NET"}],"version":"1.0.0"}`,
	} {
		if _, err := checkReleasePolicy([]byte(p), maa); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
}

// A release policy for another image than the runner's stops the release
// before the token goes to Key Vault, with an error that names both.
func TestReleaseRefusesAPolicyForAnotherImage(t *testing.T) {
	ctx := context.Background()
	f := newKVFixture(t)
	f.kv.immutable = true
	if _, _, err := f.releaser.releaseKid(ctx, "signer-kek-1", mustHex(t, testHostData)); err != nil {
		t.Fatalf("own image: %v", err)
	}
	n := len(f.kv.targets)
	other := strings.Repeat("6b", 32)
	_, _, err := f.releaser.releaseKid(ctx, "signer-kek-1", mustHex(t, other))
	if err == nil || !strings.Contains(err.Error(), "names image "+other) {
		t.Fatalf("another image: %v", err)
	}
	if len(f.kv.targets) != n {
		t.Fatal("the token went to Key Vault")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
