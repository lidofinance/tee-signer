package setuptext

import (
	"bytes"
	"strings"
	"testing"
)

// FormatPolicy writes the public lines of FormatSetup, in the same order
// and with the same values, and nothing of the private part or the salts.
func TestFormatPolicy(t *testing.T) {
	for name, s := range setups(t) {
		full := string(must(FormatSetup(s)))
		pol := string(must(FormatPolicy(s.Policy())))
		for _, line := range strings.Split(pol, "\n") {
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if !strings.Contains(full, line+"\n") {
				t.Errorf("%s: %q is not a line of the setup's form", name, line)
			}
		}
		for _, key := range []string{"cluster_id", "handover_generation", "max_keys", "slashing_log_min_lock_days", "approvers", "approvals_needed"} {
			if !strings.Contains(pol, "\n"+key+" = ") {
				t.Errorf("%s: no %s line", name, key)
			}
		}
		for _, key := range []string{"signer_name", "platform", "salt.", "slashing_log_store.", "sealing_key_release.", "allowed_client_ca"} {
			if strings.Contains(pol, "\n"+key) {
				t.Errorf("%s: the public form has %s", name, key)
			}
		}
	}
}

// ParsePlatform reads the private lines of FormatSetup back to the setup's
// platform part, and refuses a key of the public part.
func TestParsePlatform(t *testing.T) {
	for name, s := range setups(t) {
		var priv []string
		inPlatform := false
		for _, line := range strings.Split(string(must(FormatSetup(s))), "\n") {
			switch {
			case strings.HasPrefix(line, "# platform: private"):
				inPlatform = true
			case line == "":
				inPlatform = false
			case inPlatform:
				priv = append(priv, line)
			}
		}
		c, err := ParsePlatform(name, []byte(strings.Join(priv, "\n")))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got := *s
		got.Platform = *c
		if !bytes.Equal(must(got.Encode()), must(s.Encode())) {
			t.Errorf("%s: the platform part read back differs", name)
		}
		_, err = ParsePlatform(name, []byte(strings.Join(append(priv, "max_keys = 3"), "\n")))
		if err == nil || !strings.Contains(err.Error(), `unknown key "max_keys"`) {
			t.Errorf("%s: a public key: %v", name, err)
		}
	}
	if _, err := ParsePlatform("x", []byte("slashing_log_store.dir = /x\n")); err == nil {
		t.Error("no platform line: accepted")
	}
}
