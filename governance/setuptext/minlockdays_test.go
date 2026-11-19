package setuptext

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// withLines replaces the value of each key's line in text.
func withLines(t *testing.T, text string, values map[string]string) string {
	t.Helper()
	lines := strings.Split(text, "\n")
	for k, v := range values {
		found := false
		for i, l := range lines {
			if key, _, ok := strings.Cut(l, "="); ok && strings.TrimSpace(key) == k {
				lines[i], found = k+" = "+v, true
			}
		}
		if !found {
			t.Fatalf("the setup text has no %s line", k)
		}
	}
	return strings.Join(lines, "\n")
}

// A new setup of a prod chain (mainnet, or genesis values no row of the
// chain table matches) takes slashing_log_min_lock_days of 7 or more: half
// of it bounds how long a store, lock read or clock outage may last before
// the mark log stops. A non-prod chain (Hoodi, devnet, ci-test) takes 1.
// The decoder does not apply the floor, so a stored setup from before it
// still reads.
func TestParseSetupProdChainMinLockDays(t *testing.T) {
	text, err := os.ReadFile("testdata/setup-dev-threshold.conf")
	if err != nil {
		t.Fatal(err)
	}
	mainnet := map[string]string{
		"genesis_fork_version": "0x00000000", "genesis_validators_root": "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
		"genesis_time": fmt.Sprint(setupwire.MainnetGenesisTime), "seconds_per_slot": fmt.Sprint(setupwire.MainnetSecondsPerSlot),
		"slots_per_epoch": fmt.Sprint(setupwire.MainnetSlotsPerEpoch), "preset": "mainnet",
	}
	unknown := map[string]string{"genesis_fork_version": "0x12345678"}
	hoodi := map[string]string{"genesis_fork_version": "0x10000910", "genesis_validators_root": "0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f"}
	for _, c := range []struct {
		name  string
		chain map[string]string
		days  int
		ok    bool
	}{
		{"mainnet 1", mainnet, 1, false},
		{"mainnet 6", mainnet, 6, false},
		{"mainnet 7", mainnet, 7, true},
		{"unknown chain 6", unknown, 6, false},
		{"unknown chain 7", unknown, 7, true},
		{"hoodi 1", hoodi, 1, true},
		{"ci-test 1", map[string]string{}, 1, true},
	} {
		values := map[string]string{"slashing_log_min_lock_days": fmt.Sprint(c.days)}
		for k, v := range c.chain {
			values[k] = v
		}
		_, err := ParseSetup(c.name, []byte(withLines(t, string(text), values)))
		if c.ok {
			if err != nil {
				t.Errorf("%s: %v", c.name, err)
			}
			continue
		}
		want := fmt.Sprintf("slashing_log_min_lock_days %d on a prod chain", c.days)
		if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "at least 7") {
			t.Errorf("%s: %v, want the refusal naming %q and the floor 7", c.name, err, want)
		}
	}

	// A stored mainnet setup with 1 day, as a tool before the floor wrote
	// it, still decodes: a runner pinned to it keeps starting.
	s, err := ParseSetup("mainnet 7", []byte(withLines(t, string(text), mainnet)))
	if err != nil {
		t.Fatal(err)
	}
	s.SlashingLogMinLockDays = 1
	raw, err := s.Encode()
	if err != nil {
		t.Fatalf("a mainnet setup with 1 day does not encode: %v", err)
	}
	if _, err := setupwire.DecodeSetup(raw); err != nil {
		t.Fatalf("a stored mainnet setup with 1 day does not decode: %v", err)
	}
}
