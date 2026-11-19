package setupwire

import "fmt"

// MinLockDaysProd is the lowest slashing_log_min_lock_days a new setup of
// a prod chain takes. Half of it is the longest outage a running signer
// survives: when the store, the read of its lock or the trusted clock
// fails for that long, the mark log writes no more records and the signer
// needs a new setup (slashing-log/docs/marklog.md, "Write age check").
// 7 days leaves 3.5. A non-prod chain takes 1.
const MinLockDaysProd = 7

// CheckMinLockDays refuses a setup of a prod chain (mainnet, or genesis
// values no row of the chain table matches) whose
// slashing_log_min_lock_days is below MinLockDaysProd. It is the check of
// a new setup only: setuptext.ParseSetup applies it, so setup-tool encode
// and signer-admin setup refuse such a setup. The decoder does not, so a
// setup encoded before the rule keeps starting; setup-tool check and the
// runner (the start log, HEALTH lock_days_warning) only warn with the
// error.
func (s *Setup) CheckMinLockDays() error {
	if s.Chain.Prod() && s.SlashingLogMinLockDays < MinLockDaysProd {
		return fmt.Errorf("setup: slashing_log_min_lock_days %d on a prod chain (mainnet, or genesis values no row of the chain table matches), at least %d: half of it is the longest store, lock read or clock outage a running signer survives",
			s.SlashingLogMinLockDays, MinLockDaysProd)
	}
	return nil
}
