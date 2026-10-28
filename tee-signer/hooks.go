package main

import (
	"context"
	"log/slog"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/setup"
)

// Build hooks. Files a build adds to package main (go build -overlay) may
// register hooks here; this tree registers none. scripts/build-runner.sh
// adds such files only to a testnet build, from SIGNER_BUILD_OVERLAY_DIR,
// and the release gate (scripts/release-gate.sh) refuses a default build
// that has them.

// startHooks run after the setup check and before the platform is built
// (start.go): st is the checked setup, nil on the flag path.
var startHooks []func(st *setup.Setup, log *slog.Logger) error

// platformHookArgs is what a platform hook gets.
type platformHookArgs struct {
	plat       *platform.Platform
	setup      *setup.Setup // nil on the flag path
	stateCopy  bool         // the platform store is the durable state copy
	clockCheck bool         // -clock-check: the runner only prints clock readings
	log        *slog.Logger
}

// platformHooks run once the platform and its key rule are checked, before
// any share is loaded (main.go).
var platformHooks []func(ctx context.Context, a *platformHookArgs) error

func runStartHooks(st *setup.Setup, log *slog.Logger) error {
	for _, h := range startHooks {
		if err := h(st, log); err != nil {
			return err
		}
	}
	return nil
}
