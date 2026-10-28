package main

import (
	"encoding/hex"
	"log/slog"
	"time"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/setup"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/tee-signer/server"
)

// How often the config updates check for an update that came into force,
// and how often the mark log refreshes its update bodies and keep-alive
// record.
const (
	configSyncEvery  = time.Second
	markRefreshEvery = time.Hour
)

// newConfigUpdates returns the config updates of a runner with a setup
// (research/setup-phase.md in the threshold-signer-poc repo, sections 4 and 6):
// they take CONFIG_UPDATE, give the core the config in force and report the
// setup state that IDENTITY, ATTEST and HEALTH carry. That state is
// setup_hash, per group the update in force (the newest record's state with
// every pending update past its effective time made active, whether or not a
// record says so) and the pending one, and the hash of the approver set in
// force. The server adds key_release_hash and the key origin. Only the dev
// platform, which protects nothing, takes an update on an untrusted clock.
func newConfigUpdates(st *setup.Setup, l server.UpdateLog, clk platform.Clock, platformName string, log *slog.Logger) (*server.Updates, error) {
	return server.NewUpdates(server.UpdatesOptions{Setup: st.Wire, SetupHash: st.SHA256, Log: l, Clock: clk,
		AnyClock: platformName == "dev", Logger: log})
}

// keyRule is the key release self-check (research/setup-phase.md, section
// 4, and docs/protocol.md, "Key rule lock"): the platform constructor read
// the rule of the key that releases the sealing key before it released
// anything (platform.Options.ReadKeyRule), and on mainnet already refused
// a rule that is not locked or not readable. AWS and Azure read the key's
// policy; GCP and dev have no lock (KeyLockNone, zero hash), and on
// mainnet GCP passes only with the setup's no_lock_accepted. Off mainnet a
// failed read gives a zero key_release_hash, which no verifier's pin
// matches, and KeyLockUnread; the log says why and the runner still
// starts, so a key policy without the read grant does not stop a test
// signer. The mainnet rule runs here once more for a platform that read
// nothing (nil KeyRule), so no image starts on mainnet without the check.
// The flag path (no setup) reads nothing and gives the zero rule.
func keyRule(hasSetup, mainnet, noLockAccepted bool, plat *platform.Platform, log *slog.Logger) (platform.KeyRule, error) {
	if !hasSetup {
		return platform.KeyRule{}, nil
	}
	if err := (platform.Options{Mainnet: mainnet, NoLockAccepted: noLockAccepted}).CheckKeyRule(plat.KeyRule); err != nil {
		return platform.KeyRule{}, err
	}
	r := plat.KeyRule
	if r == nil {
		r = &platform.KeyRule{Lock: backend.KeyLockUnread, Why: "the platform read no key rule"}
	}
	if r.Lock == backend.KeyLockNone && !r.NoService && noLockAccepted {
		c := *r
		c.Why += "; the setup accepts a key rule without a lock (sealing_key_release.no_lock_accepted)"
		r = &c
	}
	switch r.Lock {
	case backend.KeyLockUnread:
		log.Warn("key release self-check failed: key_release_hash stays zero", "key_lock", r.Lock.String(), "err", r.Why)
	case backend.KeyLockNotLocked:
		log.Warn("key release self-check: the key rule is not locked", "key_release_sha256", hex.EncodeToString(r.Hash[:]),
			"key_lock", r.Lock.String(), "why", r.Why)
	case backend.KeyLockNone:
		log.Warn("key release self-check: the platform has no key-rule lock", "key_lock", r.Lock.String(), "why", r.Why,
			"mainnet", mainnet)
	default:
		log.Info("key release self-check", "key_release_sha256", hex.EncodeToString(r.Hash[:]), "key_lock", r.Lock.String(),
			"mainnet", mainnet)
	}
	return *r, nil
}

// flagState is the setup state of a runner without a setup (the flag
// path): the SHA-256 of its chain config file in place of setup_hash, the
// rest zero.
func flagState(configHash [32]byte) func() backend.SetupState {
	return func() backend.SetupState { return backend.SetupState{SetupHash: configHash} }
}
