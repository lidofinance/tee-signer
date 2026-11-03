package handoverorder

import (
	"slices"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// CheckTarget: a target with the source's values in force and its own
// salts passes; a target that differs in a copied leaf names it; a target
// whose mark log lock is shorter than the source's is refused; a longer
// lock and another max_keys pass.
func TestCheckTarget(t *testing.T) {
	src := sampleSetup(t)
	target := func(change func(p *setupwire.Policy)) error {
		t.Helper()
		p := src.Policy()
		p.HandoverGeneration++
		p.Salts.Public = slices.Clone(p.Salts.Public)
		for i := range p.Salts.Public {
			p.Salts.Public[i][0] ^= 0x5a
		}
		if change != nil {
			change(p)
		}
		return CheckTarget(src, &src.Locked, &src.Open, p)
	}
	if err := target(nil); err != nil {
		t.Fatalf("the source's values: %v", err)
	}
	for name, c := range map[string]struct {
		change func(p *setupwire.Policy)
		want   string
	}{
		"generation two higher": {func(p *setupwire.Policy) { p.HandoverGeneration++ }, "public.handover_generation"},
		"another safety value":  {func(p *setupwire.Policy) { p.Safety.MaxSignEpochsAheadOfClock++ }, "public.max_sign_epochs_ahead_of_clock"},
		"another locked value":  {func(p *setupwire.Policy) { p.Locked.BuilderGasLimitMax++ }, "locked.builder_gas_limit_max"},
		"a shorter lock": {func(p *setupwire.Policy) { p.SlashingLogMinLockDays = src.SlashingLogMinLockDays - 1 },
			"slashing_log_min_lock_days is"},
	} {
		if err := target(c.change); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, change := range map[string]func(p *setupwire.Policy){
		"a longer lock":    func(p *setupwire.Policy) { p.SlashingLogMinLockDays = src.SlashingLogMinLockDays + 1 },
		"another max_keys": func(p *setupwire.Policy) { p.MaxKeys = src.MaxKeys / 2 },
	} {
		if err := target(change); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
