package main

import (
	"context"
	"log/slog"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/tee-signer/server"
)

// startImageCheck builds the image check of a runner with a setup
// (server/imagegate.go, docs/protocol.md "Image check") and runs it once.
// It says whether the stored shares may load.
//
// The order at start:
//
//  1. key release (the platform constructor): the evidence it sends to the
//     key service names this runner's image, and the platform records it
//     (platform.ImageSeen). The sealing key opens nothing by itself.
//  2. the mark log claim and the config updates: the allowed list in force
//     is the log's locked group with every update past its effective time,
//     and only the key release opens the log's records. The setup's
//     version 0 alone is not the list in force.
//  3. this check, before any share is unsealed. When it refuses, the shares
//     stay sealed in the store: no key material enters the core, and the
//     runner serves HEALTH, PUBLIC_KEYS, ATTEST, IDENTITY and CONFIG_UPDATE
//     only. A restart loads them once the list in force names the image.
//  4. every request that signs, hands over or imports runs the check again
//     (server.Server.dispatch), so a locked update that drops the image
//     stops the runner at its effective time.
//
// The runner stays up instead of exiting: an exit would bring a restart
// loop, each pass a key release and a mark log claim record, and a watchdog
// would see nothing but a gap. Up, it shows the reason in HEALTH and its
// attested image in ATTEST, and takes the locked update that lists it.
func startImageCheck(ctx context.Context, plat *platform.Platform, updates *server.Updates, log *slog.Logger) (*server.ImageGate, bool, error) {
	override := imageOverride()
	g, err := server.NewImageGate(ctx, server.ImageGateOptions{Platform: plat.Name, SelfImage: plat.SelfImage, Override: override, Log: log})
	if err != nil {
		return nil, false, err
	}
	if override {
		log.Warn("image check override on (testnet build): this runner serves even when allowed_image_measurements in force does not name its image")
	}
	if err := g.Check(updates); err != nil {
		g.Withhold()
		log.Error("image check failed at start: the stored shares stay sealed and are not loaded; a restart loads them once allowed_image_measurements in force names this image", "err", err)
		return g, false, nil
	}
	return g, true, nil
}
