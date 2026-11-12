package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/slashing-log"
	"github.com/lidofinance/tee-signer/slashing-log/statestore"
)

// durableCopy is -state-store: the platform calls open once its key release
// works, before it reads its sealing key (platform.Options.Durable).
type durableCopy struct {
	spec, signer string
	create       bool
	// setupHash is the setup's setup_hash (zero on the flag path): the
	// copy's names and AADs carry it.
	setupHash [32]byte
	// retainDays is markstore.Env.RetainDays: set when the copy is in the
	// mark log's store (the same spec), so its objects get the log's
	// retention by themselves too.
	retainDays uint32
	// checkVersions: refuse a store that keeps overwritten objects as hidden
	// versions (markstore.CheckVersions). Set on the setup path, where the
	// mark log gets its lock check.
	checkVersions bool
	// lockDays: run the mark log's lock check on the copy's store too
	// (markstore.CheckLock), where the mark log gets it. On some platforms
	// the copy is the only lasting copy of the sealed shares, and an admin
	// who can delete it loses them. requireLock (mainnet) refuses a store
	// that fails the check; else the runner logs a warning.
	lockDays    uint32
	requireLock bool
	log         *slog.Logger
	store       *statestore.Store
}

func newDurableCopy(spec, signer string, create bool, log *slog.Logger) (*durableCopy, error) {
	if signer == "" {
		return nil, errors.New("-state-store needs -mark-signer: the copy is kept per signer")
	}
	if err := markstore.CheckSigner(signer); err != nil {
		return nil, err
	}
	return &durableCopy{spec: spec, signer: signer, create: create, log: log}, nil
}

func (d *durableCopy) open(ctx context.Context, p *platform.Platform) (platform.Store, error) {
	if p.Keys == nil {
		return nil, fmt.Errorf("platform %s has no key release for the state copy", p.Name)
	}
	env := storeEnv(p, p.Name, d.retainDays)
	env.Logger = d.log
	l, err := markstore.Open(d.spec, env)
	if err != nil {
		return nil, fmt.Errorf("-state-store: %w", err)
	}
	if l == nil {
		return p.Store, nil
	}
	if err := d.checkStore(ctx, l, true); err != nil {
		return nil, err
	}
	opt := statestore.Options{SetupHash: d.setupHash, AllowCreate: d.create, Log: d.log}
	if d.setupHash != ([32]byte{}) {
		// The copy ages on the clock the mark log ages on. The NTS clock
		// replaces p.Clock after open returns, so read it at each call.
		opt.Clock = func() (time.Time, error) { return p.Clock.Now() }
	}
	s, err := statestore.Open(ctx, p.Store, l, d.signer, p.Keys, opt)
	if err != nil {
		return nil, err
	}
	// The store can change between the first check and the read: on Azure
	// a migration to version-level immutability that completes there lets
	// an admin hide the newest commits from the read. Check again.
	if err := d.checkStore(ctx, l, false); err != nil {
		return nil, err
	}
	d.store = s
	return s, nil
}

// checkStore runs the version check and the lock check on the copy's
// store, where they are set. A version check error, and on mainnet a lock
// check error, stops the start. Off mainnet a failed lock check logs a
// warning when warn is set.
func (d *durableCopy) checkStore(ctx context.Context, l markstore.Log, warn bool) error {
	if d.checkVersions {
		vctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		err := markstore.CheckVersions(vctx, l)
		cancel()
		if err != nil {
			return fmt.Errorf("-state-store: %w", err)
		}
	}
	if d.lockDays == 0 || !d.requireLock && !warn {
		return nil
	}
	lctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	err := markstore.CheckLock(lctx, l, d.lockDays)
	cancel()
	switch {
	case err != nil && d.requireLock:
		return fmt.Errorf("-state-store: prod chain: %w", err)
	case err != nil:
		d.log.Warn("state copy: the store is not locked; its admin can delete the copy, and with it the sealed shares where the local store does not last",
			"err", err)
	}
	return nil
}

// refreshAge is how old the oldest object the newest commit needs may get
// before the whole state is written again. With a setup it is at most half
// of slashing_log_min_lock_days less two refresh ticks: a restart may come
// half the retention after the last mark record, so the copy at the stop
// must be younger than the other half. flagAge (-state-refresh) can only
// make it shorter. Without a setup (lockDays 0) it is flagAge, and 0 means
// never.
func refreshAge(flagAge time.Duration, lockDays uint32) time.Duration {
	if lockDays == 0 {
		return flagAge
	}
	half := time.Duration(lockDays)*24*time.Hour/2 - 2*time.Hour
	if flagAge > 0 && flagAge < half {
		return flagAge
	}
	return half
}

// refreshTick is how often refresh checks the age: four times per age, at
// least every hour.
func refreshTick(age time.Duration) time.Duration { return min(age/4, time.Hour) }

// refresh writes the whole state again whenever the oldest object the
// newest commit needs is older than every, checking every refreshTick.
// report gets each check's result (HEALTH state_copy_failed).
func (d *durableCopy) refresh(ctx context.Context, every time.Duration, report func(error)) {
	refreshLoop(ctx, every, func(c context.Context) error { return d.store.Refresh(c, every) }, d.log, report)
}

func refreshLoop(ctx context.Context, every time.Duration, do func(context.Context) error, log *slog.Logger, report func(error)) {
	tick := time.NewTicker(refreshTick(every))
	defer tick.Stop()
	for {
		rctx, cancel := context.WithTimeout(ctx, time.Minute)
		err := do(rctx)
		cancel()
		if err != nil {
			log.Warn("state copy: refresh failed; it will try again", "err", err)
		}
		report(err)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (d *durableCopy) status() string {
	if d == nil || d.store == nil {
		return "none"
	}
	return d.store.Status()
}
