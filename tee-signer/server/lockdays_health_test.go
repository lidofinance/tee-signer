//go:build !debugimport

package server

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// HEALTH warns of a prod chain setup with slashing_log_min_lock_days below
// 7 (lock_days_warning), which a tool before that rule could encode, and
// stays ready: the runner keeps serving it. A non-prod setup with 1 day
// gets no warning.
func TestHealthWarnsOfProdSetupBelowMinLockDays(t *testing.T) {
	hoodiRoot, err := hex.DecodeString("212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		fork [4]byte
		root []byte
		days uint32
		warn bool
	}{
		{"unknown chain (prod), 1 day", [4]byte{0x12, 0x34, 0x56, 0x78}, nil, 1, true},
		{"unknown chain (prod), 7 days", [4]byte{0x12, 0x34, 0x56, 0x78}, nil, 7, false},
		{"hoodi, 1 day", [4]byte{0x10, 0x00, 0x09, 0x10}, hoodiRoot, 1, false},
	} {
		e := newTgtEnv(t, "dev", func(s *setupwire.Setup) {
			s.Chain.GenesisForkVersion = c.fork
			if c.root != nil {
				copy(s.Chain.GenesisValidatorsRoot[:], c.root)
			}
			s.SlashingLogMinLockDays = c.days
		})
		if got := e.setup.Chain.Prod(); got != (c.fork != [4]byte{0x10, 0x00, 0x09, 0x10}) {
			t.Fatalf("%s: prod %v", c.name, got)
		}
		h, err := e.srv.health()
		if err != nil {
			t.Fatal(err)
		}
		js, err := json.Marshal(h)
		if err != nil {
			t.Fatal(err)
		}
		has := strings.Contains(string(js), `"lock_days_warning":"`)
		if has != c.warn || (c.warn && !strings.Contains(string(js), "slashing_log_min_lock_days 1 on a prod chain")) {
			t.Errorf("%s: HEALTH %s, want lock_days_warning %v", c.name, js, c.warn)
		}
		if c.warn && !h.Ready {
			t.Errorf("%s: not ready with the warning: %s", c.name, js)
		}
	}
}
