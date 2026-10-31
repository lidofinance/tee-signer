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
	"github.com/lidofinance/tee-signer/tee-signer/record"
)

// durableCopy is -state-store: the platform calls open once its key release
// works, before it reads its sealing key (platform.Options.Durable).
type durableCopy struct {
	spec, signer string
	create       bool
	// setupHash is the setup's setup_hash (zero on the flag path): the
	// copy's names and AADs carry it.
	setupHash [32]byte
	log       *slog.Logger
	store     *statestore.Store
}

func newDurableCopy(spec, signer string, create bool, log *slog.Logger) (*durableCopy, error) {
	if signer == "" {
		return nil, errors.New("-state-store needs -mark-signer (or -record-key): the copy is kept per signer")
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
	env := markstore.Env{HTTP: p.HTTPClient, AWSCreds: p.RecordCredentials}
	if p.StorageToken != nil {
		c := markstore.NewTokenCache(p.StorageToken, markstore.TokenRefreshAfter, markstore.TokenMaxAge)
		env.Token, env.TokenRefused = c.Token, c.Invalidate
	}
	if p.Name == "dev" && env.AWSCreds == nil {
		env.AWSCreds = record.EnvCredentials()
	}
	l, err := markstore.Open(d.spec, env)
	if err != nil {
		return nil, fmt.Errorf("-state-store: %w", err)
	}
	if l == nil {
		return p.Store, nil
	}
	s, err := statestore.Open(ctx, p.Store, l, d.signer, p.Keys, statestore.Options{SetupHash: d.setupHash, AllowCreate: d.create, Log: d.log})
	if err != nil {
		return nil, err
	}
	d.store = s
	return s, nil
}

// refreshAge is how old the oldest object the newest commit needs may get
// before the whole state is written again. With a setup it is at most half
// of slashing_log_min_lock_days, so the newest copy never outlives the
// store's retention; flagAge (-state-refresh) can only make it shorter.
// Without a setup (lockDays 0) it is flagAge, and 0 means never.
func refreshAge(flagAge time.Duration, lockDays uint32) time.Duration {
	if lockDays == 0 {
		return flagAge
	}
	half := time.Duration(lockDays) * 24 * time.Hour / 2
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
func (d *durableCopy) refresh(ctx context.Context, every time.Duration) {
	tick := time.NewTicker(refreshTick(every))
	defer tick.Stop()
	for {
		rctx, cancel := context.WithTimeout(ctx, time.Minute)
		if err := d.store.Refresh(rctx, every); err != nil {
			d.log.Warn("state copy: refresh failed; it will try again", "err", err)
		}
		cancel()
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
