package handoverorder

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// CheckTarget checks a handover target's public part against its source:
// the source's setup src and its locked and open groups in force. The
// target must have the source's cluster_id, chain and safety values,
// handover_generation one higher, and version 0 of both groups equal to the
// values in force, leaf by leaf. Its salts and max_keys are its own (the
// source checks max_keys against the shares it holds). Its
// slashing_log_min_lock_days may be higher than the source's, never lower:
// the lock is how long the host cannot delete a mark log record, so a
// shorter lock would let the host roll back the marks the target takes
// over sooner.
//
// The source runner applies it before the handover; signer-admin applies it
// when it drafts and shows an order, so approvers see what the runner would
// refuse.
func CheckTarget(src *setupwire.Setup, locked *setupwire.Locked, open *setupwire.Open, target *setupwire.Policy) error {
	if src.HandoverGeneration == ^uint64(0) {
		return errors.New("handover: the source's handover_generation has no successor")
	}
	want := &setupwire.Policy{ClusterID: src.ClusterID, HandoverGeneration: src.HandoverGeneration + 1, Chain: src.Chain, Safety: src.Safety,
		MaxKeys: target.MaxKeys, SlashingLogMinLockDays: target.SlashingLogMinLockDays, Locked: *locked, Open: *open, Salts: target.Salts}
	wp, wl, wo, err := want.Leaves()
	if err != nil {
		return fmt.Errorf("handover: the source's values do not make a target policy: %w", err)
	}
	gp, gl, gor, err := target.Leaves()
	if err != nil {
		return fmt.Errorf("handover: target policy: %w", err)
	}
	var diff []string
	for _, g := range []struct {
		what      string
		want, got []setupwire.Leaf
	}{{"public", wp, gp}, {"locked", wl, gl}, {"open", wo, gor}} {
		for i := range g.want {
			if !bytes.Equal(g.want[i].Value, g.got[i].Value) {
				diff = append(diff, g.what+"."+g.want[i].Name)
			}
		}
	}
	if len(diff) > 0 {
		return fmt.Errorf("handover: the target's setup differs from the source's in %s (want the same cluster_id, chain and safety, "+
			"handover_generation %d, and version 0 of both groups equal to the values in force at the source)", strings.Join(diff, ", "), want.HandoverGeneration)
	}
	if target.SlashingLogMinLockDays < src.SlashingLogMinLockDays {
		return fmt.Errorf("handover: the target's slashing_log_min_lock_days is %d, below the source's %d "+
			"(the target's mark log must stay locked at least as long)", target.SlashingLogMinLockDays, src.SlashingLogMinLockDays)
	}
	return nil
}
