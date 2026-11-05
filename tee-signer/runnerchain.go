//go:build nonprod

package main

// A non-prod build (signer-protocol/buildchain, governance times in
// minutes) runs on the chain it is built for only (governance/runnerchain
// chains.go), so it never holds keys of mainnet or another public chain. It
// checks the chain of the setup before the platform starts, so before any
// key release and any store, and refuses to start on any other chain. The
// mainnet build runs on mainnet only, on its cloud platforms
// (prodchain.go).
//
// The check hooks into the two registries the platform files fill
// (platforms.go), so the mainnet build's code stays as it is:
//
//   - each platform's setup channel (-setup platform) checks the setup it
//     reads and remembers its setup_hash;
//   - each platform's constructor starts only with a setup_hash that passed:
//     one from the channel, or, for -setup file: on dev, the file's setup,
//     read again and checked here. The flag path (no -setup) has no setup
//     to check and is refused, except -clock-check, which signs nothing.
//
// This file's init runs after the platform files' (Go runs init functions
// in file name order), as platforms_nts.go's does.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"sync"

	"github.com/lidofinance/tee-signer/governance/runnerchain"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/setup"
)

func init() {
	for name, f := range setupChannels {
		setupChannels[name] = chainChannel(f)
	}
	for name, f := range platforms {
		platforms[name] = chainPlatform(f)
	}
}

// chainPassed holds the setup_hash of each setup whose chain passed.
var chainPassed sync.Map

// checkChainSetup refuses a setup whose chain this build must not
// run on, and remembers the setup_hash of one that passes. A setup that does
// not decode is left to setup.Load, which says why.
func checkChainSetup(raw []byte) error {
	s, err := setupwire.DecodeSetup(raw)
	if err != nil {
		return nil
	}
	if err := runnerchain.Build.CheckChain(&s.Chain); err != nil {
		return fmt.Errorf("setup refused by this %s build: %w", runnerchain.Build, err)
	}
	h, err := s.Hash()
	if err != nil {
		return nil
	}
	chainPassed.Store(h, true)
	return nil
}

// chainStart is the check before the platform: the setup_hash of the
// start must belong to a setup whose chain passed. src is -setup's value.
func chainStart(setupHash [32]byte, src string, clockCheck bool) error {
	if setupHash == ([32]byte{}) {
		if clockCheck {
			return nil
		}
		return errors.New("a non-prod build starts with a setup only (-setup), so it can check the chain; the flag path has none")
	}
	if _, ok := chainPassed.Load(setupHash); ok {
		return nil
	}
	// -setup file: (dev) does not go through a channel: read the file
	// again, and take it only if it is the setup the start loaded.
	if path, err := setup.ParseSource(src); err == nil && path != "" {
		raw, err := (setup.File{Path: path}).Read(context.Background())
		if err != nil {
			return fmt.Errorf("non-prod build: read the setup again: %w", err)
		}
		if h, err := setupwire.SetupHash(raw); err != nil || h != setupHash {
			return fmt.Errorf("non-prod build: %s changed during the start", path)
		}
		if err := checkChainSetup(raw); err != nil {
			return err
		}
		if _, ok := chainPassed.Load(setupHash); ok {
			return nil
		}
	}
	return fmt.Errorf("non-prod build: the chain of setup %x was not checked", setupHash[:8])
}

// flagValue is the value of a flag of the command line, or "".
func flagValue(name string) string {
	if f := flag.Lookup(name); f != nil {
		return f.Value.String()
	}
	return ""
}

func chainPlatform(f platformFunc) platformFunc {
	return func(o platform.Options) (*platform.Platform, error) {
		if err := chainStart(o.SetupHash, flagValue("setup"), flagValue("clock-check") == "true"); err != nil {
			return nil, err
		}
		return f(o)
	}
}

// chainChannel wraps a setup channel with the chain check. The Nitro
// channel also takes the runner's exit line; the wrapper keeps that.
func chainChannel(f func() setup.Channel) func() setup.Channel {
	return func() setup.Channel {
		ch := f()
		if r, ok := ch.(setup.Reporter); ok {
			return checkedReporter{checked{ch}, r}
		}
		return checked{ch}
	}
}

type checked struct{ setup.Channel }

func (c checked) Read(ctx context.Context) ([]byte, error) {
	raw, err := c.Channel.Read(ctx)
	if err != nil {
		return nil, err
	}
	if err := checkChainSetup(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

type checkedReporter struct {
	checked
	r setup.Reporter
}

func (c checkedReporter) ReportExit(text string) { c.r.ReportExit(text) }
