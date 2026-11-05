//go:build !nonprod

package main

// The mainnet build runs on mainnet only (governance/runnerchain
// chains.go). A setup with another chain's genesis fork version would
// start it without the prod rules while it signs for mainnet, so on a
// cloud platform it checks the chain of the setup as the setup channel
// reads it, before any key release and any store. It refuses every chain
// but mainnet with mainnet's exact genesis fork version, genesis
// validators root, genesis time, seconds per slot, slots per epoch and
// preset.
//
// A cloud platform reads its setup from its own channel only (-setup file:
// is for dev), so wrapping those channels covers every setup it takes. The
// flag path has no setup; a release build refuses it off dev
// (checkFlagPath). The dev platform protects nothing and keeps any chain:
// the tests run it on the ci-test chain.
//
// This file's init runs after the platform files' (Go runs init functions
// in file name order).

import (
	"context"
	"fmt"

	"github.com/lidofinance/tee-signer/governance/runnerchain"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform/setup"
)

func init() {
	for name, f := range setupChannels {
		if name != "dev" {
			setupChannels[name] = mainnetChannel(f)
		}
	}
}

// checkMainnetSetup refuses a setup whose chain is not mainnet. A setup
// that does not decode is left to setup.Load, which says why.
func checkMainnetSetup(raw []byte) error {
	s, err := setupwire.DecodeSetup(raw)
	if err != nil {
		return nil
	}
	if err := runnerchain.Build.CheckChain(&s.Chain); err != nil {
		return fmt.Errorf("setup refused by this %s build: %w", runnerchain.Build, err)
	}
	return nil
}

// mainnetChannel wraps a setup channel with the chain check. The Nitro
// channel also takes the runner's exit line; the wrapper keeps that.
func mainnetChannel(f func() setup.Channel) func() setup.Channel {
	return func() setup.Channel {
		ch := f()
		if r, ok := ch.(setup.Reporter); ok {
			return mainnetReporter{mainnetChecked{ch}, r}
		}
		return mainnetChecked{ch}
	}
}

type mainnetChecked struct{ setup.Channel }

func (c mainnetChecked) Read(ctx context.Context) ([]byte, error) {
	raw, err := c.Channel.Read(ctx)
	if err != nil {
		return nil, err
	}
	if err := checkMainnetSetup(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

type mainnetReporter struct {
	mainnetChecked
	r setup.Reporter
}

func (c mainnetReporter) ReportExit(text string) { c.r.ReportExit(text) }
