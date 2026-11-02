package main

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/setup"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/transport"
)

// The setup path (-setup). The image is the same for every operator
// and its command fixes only what is the same for all of them. The values
// that were flags (the chain config, the client CA, max_keys, the
// slashing log and the encrypted state store, the signer name and the platform options) come from the setup, which the host hands over at every
// start. The start order:
//
//  1. read the setup from the platform's channel, decode it strictly, check
//     that it is for this platform, compute setup_hash;
//  2. derive the platform options (on Nitro the proxy routes over the fixed
//     port map) and the chain config, run the start hooks (hooks.go);
//  3. build the platform: key release with setup_hash in every call
//     (platform.Options.SetupHash), then the state copy restore (the copy's
//     names and AADs carry setup_hash).
//
// Nothing in steps 1 and 2 calls key release. After step 3 main.go claims
// the setup's mark log (setup_hash in its names and records, the store's
// lock checked outside dev) and loads only the shares listed before the
// claim, sealed under setup_hash and the log's log_id. IDENTITY, ATTEST and
// HEALTH then carry setup_hash and the mark log's config state
// (setupstate.go). The flag path (no -setup) stays for the tests and the
// stack's local runners until they move.

// setupWait bounds step 1: the host agent or the metadata server may not
// answer at once.
const setupWait = 2 * time.Minute

// setupRefuses are the flags a runner with -setup refuses, with the reason:
// the values the setup carries, and the flags that let a host weaken the
// signer or that a phase 1 image does not have. -record is allowed as
// "none" only; -platform-opt only for options the setup does not set.
var setupRefuses = map[string]string{
	"config":         "the setup carries the chain, safety and first config values",
	"tls-client-ca":  "the setup carries allowed_client_ca",
	"max-validators": "the setup carries max_keys",
	"mark-store":     "the setup carries slashing_log_store",
	"mark-signer":    "the setup carries signer_name",
	"state-store":    "the setup carries encrypted_state_store",
	"floor-margin":   "the floor margin is max_sign_epochs_ahead_of_clock + 1",
	"mark-create":    "a signer that lost its mark log gets a new setup and a share re-import",
	"state-create":   "a signer that lost its key release gets a new setup and a share re-import",
	"record-create":  "an image with a setup has no DynamoDB clone guard",
	"record-key":     "an image with a setup has no DynamoDB clone guard",
	"record-ahead":   "an image with a setup has no DynamoDB clone guard",
}

// checkSetupFlags refuses the flags of setupRefuses among given (the flags
// on the command line, name to value).
func checkSetupFlags(given map[string]string) error {
	names := make([]string, 0, len(given))
	for n := range given {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if why, ok := setupRefuses[n]; ok {
			return fmt.Errorf("-%s cannot be used with -setup: %s", n, why)
		}
	}
	if r, ok := given["record"]; ok && r != "none" {
		return fmt.Errorf("-record %s cannot be used with -setup: the mark log of the setup is the clone protection (-record none)", r)
	}
	return nil
}

// startArgs are the flags the first steps of the start read.
type startArgs struct {
	platformName string
	setupSrc     string            // -setup; "" is the flag path
	given        map[string]string // every flag on the command line
	params       map[string]string // -platform-opt
	listens      []transport.Addr
	stateDir     string
	clockCheck   bool

	// The flag path's values; the setup path fills them from the setup.
	tlsCA, recordSpec, markSpec, stateSpec, signerID string
	stateCreate                                      bool
	maxValidators                                    uint32
}

// start is what the first steps decide.
type start struct {
	setup  *setup.Setup // nil on the flag path
	cfg    core.Config  // the setup's chain config (the flag path loads -config later)
	params map[string]string
	caPEM  []byte // the setup's client CA (the flag path reads -tls-client-ca later)
	// mainnet: the setup's chain has mainnet's genesis fork version
	// (setupwire.IsMainnet), the same test as the threshold rule. The
	// platform then refuses a key rule that is not locked.
	mainnet bool
	// noLockAccepted is the setup's sealing_key_release.no_lock_accepted:
	// on mainnet a key rule without a lock (GCP) passes.
	noLockAccepted bool

	recordSpec, markSpec, stateSpec, signerID string
	stateCreate                               bool
	maxValidators                             uint32
}

// setupChannelFor returns the channel of -setup src on the platform.
func setupChannelFor(platformName, src string) (setup.Channel, error) {
	file, err := setup.ParseSource(src)
	if err != nil {
		return nil, err
	}
	if file != "" {
		if platformName != "dev" {
			return nil, fmt.Errorf("-setup file: is for the dev platform; platform %s reads its setup from its own channel (-setup platform)", platformName)
		}
		return setup.File{Path: file}, nil
	}
	f, ok := setupChannels[platformName]
	if !ok {
		return nil, fmt.Errorf("platform %s has no setup channel in this binary", platformName)
	}
	return f(), nil
}

// readSetup is step 1: it reads the setup from ch and checks it for the
// image's platform.
func readSetup(ctx context.Context, ch setup.Channel, platformName string) (*setup.Setup, error) {
	ctx, cancel := context.WithTimeout(ctx, setupWait)
	defer cancel()
	raw, err := ch.Read(ctx)
	if err != nil {
		return nil, fmt.Errorf("setup from %s: %w", ch, err)
	}
	return setup.Load(raw, platformName)
}

// fromSetup is steps 1 and 2 on the setup path. A failure goes to the
// channel's host too, if it takes one (Nitro: the enclave has no console,
// and the platform that would report it does not exist yet).
func fromSetup(ctx context.Context, a *startArgs, log *slog.Logger) (_ *start, err error) {
	ch, err := setupChannelFor(a.platformName, a.setupSrc)
	if err != nil {
		return nil, err
	}
	if r, ok := ch.(setup.Reporter); ok {
		defer func() {
			if err != nil {
				r.ReportExit("runner: " + err.Error())
			}
		}()
	}
	if err := checkSetupFlags(a.given); err != nil {
		return nil, err
	}
	st, err := readSetup(ctx, ch, a.platformName)
	if err != nil {
		return nil, err
	}
	params, err := setup.MergeOptions(st.Options(), a.params)
	if err != nil {
		return nil, err
	}
	cfg, err := chainConfig(st.Wire)
	if err != nil {
		return nil, fmt.Errorf("setup: chain config: %w", err)
	}
	if err := runStartHooks(st, log); err != nil {
		return nil, err
	}
	log.Info("setup", "channel", ch.String(), "setup_sha256", st.HashHex(), "signer", st.SignerID(),
		"handover_generation", st.Wire.HandoverGeneration, "slashing_log_store", st.SlashingLogStore(),
		"encrypted_state_store", st.EncryptedStateStore(), "signing_mode", st.Wire.SigningMode.String())
	if st.Wire.Platform.SealingKeyRelease.UnsafeSingleKeyAccepted {
		log.Warn("UNSAFE: the setup accepts a key held alone on GCP (sealing_key_release.unsafe_single_key_accepted); a 1 of 1 import order is taken", "why", setupwire.UnsafeSingleKeyWarning)
	}
	return &start{setup: st, cfg: cfg, params: params, caPEM: st.ClientCAPEM(), mainnet: setupwire.IsMainnet(cfg.GenesisForkVersion), recordSpec: "none",
		noLockAccepted: st.Wire.Platform.SealingKeyRelease.NoLockAccepted,
		markSpec:       st.SlashingLogStore(), stateSpec: st.EncryptedStateStore(), signerID: st.SignerID(),
		maxValidators: st.MaxKeys()}, nil
}

// fromFlags is the flag path: the values as the flags give them.
func fromFlags(a *startArgs) (*start, error) {
	if err := runStartHooks(nil, nil); err != nil {
		return nil, err
	}
	return &start{params: a.params, recordSpec: a.recordSpec, markSpec: a.markSpec, stateSpec: a.stateSpec,
		signerID: a.signerID, stateCreate: a.stateCreate, maxValidators: a.maxValidators}, nil
}

// startPlatform runs the first steps of the start, up to a built platform:
// the setup (or the flags), the image rules of checkFlags, then the
// platform with its state copy. On the setup path the platform's options
// come from the setup, so no key release happens before the setup passed.
func startPlatform(ctx context.Context, a *startArgs, newPlatform platformFunc, log *slog.Logger) (*start, *platform.Platform, *durableCopy, error) {
	var s *start
	var err error
	if a.setupSrc != "" {
		s, err = fromSetup(ctx, a, log)
	} else {
		s, err = fromFlags(a)
	}
	if err != nil {
		return nil, nil, nil, err
	}
	if !a.clockCheck {
		if err := checkFlags(a.platformName, a.listens, a.tlsCA != "" || s.caPEM != nil, s.recordSpec, s.markSpec); err != nil {
			return nil, nil, nil, err
		}
	}
	opts := platform.Options{StateDir: a.stateDir, Params: s.params, Mainnet: s.mainnet, NoLockAccepted: s.noLockAccepted}
	if s.setup != nil {
		// Every key-release call carries setup_hash.
		opts.SetupHash = s.setup.SHA256
	}
	var copyStore *durableCopy
	if s.stateSpec != "" && s.stateSpec != "none" && !a.clockCheck {
		if copyStore, err = newDurableCopy(s.stateSpec, s.signerID, s.stateCreate, log); err != nil {
			return nil, nil, nil, err
		}
		if s.setup != nil {
			copyStore.setupHash = s.setup.SHA256
		}
		opts.Durable = copyStore.open
	}
	plat, err := newPlatform(opts)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("platform %s: %w", a.platformName, err)
	}
	return s, plat, copyStore, nil
}

// chainConfig turns the setup's chain, safety and first config values
// (version 0 of the locked and open groups) into the core's chain config:
// what chain.json held on the flag path, with the slot time changes of
// version 0. The floor margin follows from max_sign_epochs_ahead_of_clock
// (state.DefaultFloorMargin). The cloud runner does not use the board-only
// values of locked yet (exit_stake_cap_per_day, exit_stake_counting,
// exit_approvals_needed, balances, withdrawal credentials, deposit amounts,
// bare_root_domains), nor the approvers, change delay and allowed images,
// which config updates use.
func chainConfig(s *setupwire.Setup) (core.Config, error) {
	ch, sf, l, o := &s.Chain, &s.Safety, &s.Locked, &s.Open
	c := core.Config{
		GenesisValidatorsRoot:    ch.GenesisValidatorsRoot,
		GenesisForkVersion:       ch.GenesisForkVersion,
		VoluntaryExitForkVersion: ch.VoluntaryExitForkVersion,
		GenesisTime:              ch.GenesisTime,
		SecondsPerSlot:           ch.SecondsPerSlot,
		SlotsPerEpoch:            ch.SlotsPerEpoch,
		Preset:                   ch.Preset.String(),
		MaxEpochsAhead:           sf.MaxSignEpochsAheadOfClock,
		CommitAhead: core.CommitAhead{BlockSlots: sf.SlashingMarkPrewrite.BlockSlots, SourceEpochs: sf.SlashingMarkPrewrite.SourceEpochs,
			TargetEpochs: sf.SlashingMarkPrewrite.TargetEpochs},
		ExitAllowlist:                append([]uint64(nil), l.ExitAllowedValidators...),
		FeeRecipients:                append([]backend.Address(nil), l.AllowedFeeRecipients...),
		BuilderRequestAuthRoots:      append([]backend.Root(nil), l.AllowedBuilderRequestAuthDataRoots...),
		GasLimitMin:                  l.BuilderGasLimitMin,
		GasLimitMax:                  l.BuilderGasLimitMax,
		RegistrationMaxFutureSeconds: l.BuilderRegistrationMaxFutureSeconds,
		AllowUnverifiedNonslashable:  l.AllowUnverifiedNonslashableSigning,
	}
	for _, ch := range l.SlotTimeChanges {
		c.SlotTimeChanges = append(c.SlotTimeChanges, core.SlotTimeChange{Epoch: ch.Epoch, SecondsPerSlot: ch.SecondsPerSlot})
	}
	for _, f := range o.ForkSchedule {
		c.Forks = append(c.Forks, core.Fork{Epoch: f.Epoch, Version: f.Version})
	}
	if o.GloasForkEpoch != nil {
		e := *o.GloasForkEpoch
		c.GloasForkEpoch = &e
	}
	return c, c.Validate()
}
