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

// refresh writes the whole state again whenever the oldest object the
// newest commit needs is older than every.
func (d *durableCopy) refresh(ctx context.Context, every time.Duration) {
	tick := time.NewTicker(min(every/4, time.Hour))
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
