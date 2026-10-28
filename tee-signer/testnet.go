//go:build testnet

package main

// A testnet build (backend/setupwire flavors.go, governance times in
// minutes) runs on devnets and on the test networks of backend/flavor only,
// so it never holds keys of mainnet or another public chain. It checks the
// chain of the setup before the platform starts, so before any key release
// and any store, and refuses to start on any other chain. The default
// build has none of this and runs on any chain.
//
// The check hooks into the two registries the platform files fill
// (platforms.go), so the default build's code stays as it is:
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

	"github.com/lidofinance/tee-signer/governance/flavor"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/setup"
)

func init() {
	for name, f := range setupChannels {
		setupChannels[name] = testnetChannel(f)
	}
	for name, f := range platforms {
		platforms[name] = testnetPlatform(f)
	}
}

// testnetPassed holds the setup_hash of each setup whose chain passed.
var testnetPassed sync.Map

// checkTestnetSetup refuses a setup whose chain a testnet build must not
// run on, and remembers the setup_hash of one that passes. A setup that does
// not decode is left to setup.Load, which says why.
func checkTestnetSetup(raw []byte) error {
	s, err := setupwire.DecodeSetup(raw)
	if err != nil {
		return nil
	}
	ch := &s.Chain
	if err := flavor.CheckChain([4]byte(ch.GenesisForkVersion), [32]byte(ch.GenesisValidatorsRoot)); err != nil {
		return fmt.Errorf("setup refused by this testnet build: %w", err)
	}
	h, err := s.Hash()
	if err != nil {
		return nil
	}
	testnetPassed.Store(h, true)
	return nil
}

// testnetStart is the check before the platform: the setup_hash of the
// start must belong to a setup whose chain passed. src is -setup's value.
func testnetStart(setupHash [32]byte, src string, clockCheck bool) error {
	if setupHash == ([32]byte{}) {
		if clockCheck {
			return nil
		}
		return errors.New("a testnet build starts with a setup only (-setup), so it can check the chain; the flag path has none")
	}
	if _, ok := testnetPassed.Load(setupHash); ok {
		return nil
	}
	// -setup file: (dev) does not go through a channel: read the file
	// again, and take it only if it is the setup the start loaded.
	if path, err := setup.ParseSource(src); err == nil && path != "" {
		raw, err := (setup.File{Path: path}).Read(context.Background())
		if err != nil {
			return fmt.Errorf("testnet build: read the setup again: %w", err)
		}
		if h, err := setupwire.SetupHash(raw); err != nil || h != setupHash {
			return fmt.Errorf("testnet build: %s changed during the start", path)
		}
		if err := checkTestnetSetup(raw); err != nil {
			return err
		}
		if _, ok := testnetPassed.Load(setupHash); ok {
			return nil
		}
	}
	return fmt.Errorf("testnet build: the chain of setup %x was not checked", setupHash[:8])
}

// flagValue is the value of a flag of the command line, or "".
func flagValue(name string) string {
	if f := flag.Lookup(name); f != nil {
		return f.Value.String()
	}
	return ""
}

func testnetPlatform(f platformFunc) platformFunc {
	return func(o platform.Options) (*platform.Platform, error) {
		if err := testnetStart(o.SetupHash, flagValue("setup"), flagValue("clock-check") == "true"); err != nil {
			return nil, err
		}
		return f(o)
	}
}

// testnetChannel wraps a setup channel with the chain check. The Nitro
// channel also takes the runner's exit line; the wrapper keeps that.
func testnetChannel(f func() setup.Channel) func() setup.Channel {
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
	if err := checkTestnetSetup(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

type checkedReporter struct {
	checked
	r setup.Reporter
}

func (c checkedReporter) ReportExit(text string) { c.r.ReportExit(text) }
