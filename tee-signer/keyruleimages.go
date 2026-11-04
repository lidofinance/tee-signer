package main

import (
	"encoding/hex"
	"errors"
	"log/slog"
	"strings"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/tee-signer/server"
)

// checkKeyRuleImages is the image rule of the key rule lock
// (docs/protocol.md, "Key rule lock"): every image the locked key rule
// releases the sealing key to (platform.KeyRule.Images, on Nitro the PCR0
// values of the key policy) must be on allowed_image_measurements in
// force. The lock check only asks that each release is bound to some
// image; a policy with two images (a rollback image, prev_pcrs in
// platform-aws/deploy/main.tf) or two bound statements passes it with an
// image the approvers never listed, and an enclave of that image opens
// every sealed share without running the image check, which only the
// listed runner runs on itself.
//
// It runs once at start, after the config updates know the list in force
// and before any share is unsealed, as part of startImageCheck. On a prod
// chain an unlisted image, or a list the runner cannot read, leaves the
// shares sealed, the way the image check does when it refuses: the gate
// records it (server.ImageGate.WithholdKeyRule), the runner stays up,
// HEALTH says key_rule_unlisted (or unknown) and why, and CONFIG_UPDATE is
// served, so a locked update that lists the image can reach this runner.
// Once the list in force names every image HEALTH says restart_needed, and
// a restart loads the shares. An exit here would close that path: a locked
// update reaches the log only through a serving runner. Off prod the rule
// logs a warning. A platform that reports no image set (Azure, GCP, dev, a
// rule that is not locked) runs no check.
func checkKeyRuleImages(prod bool, rule platform.KeyRule, updates *server.Updates, g *server.ImageGate, log *slog.Logger) {
	if len(rule.Images) == 0 {
		return
	}
	var (
		unlisted [][]byte
		version  uint64
		err      error
	)
	if updates == nil {
		err = errors.New("no mark log, so no allowed list in force")
	} else {
		unlisted, version, err = updates.UnlistedKeyRuleImages(rule.Images)
	}
	if err != nil {
		if prod {
			log.Error("key rule images: the runner cannot compare them with allowed_image_measurements in force; the stored shares stay sealed", "images", hexList(rule.Images), "err", err)
			g.WithholdKeyRule(rule.Images)
			return
		}
		log.Warn("key rule images: cannot compare them with allowed_image_measurements in force; a prod chain would keep the shares sealed", "images", hexList(rule.Images), "err", err)
		return
	}
	if len(unlisted) == 0 {
		log.Info("key rule images: every image the key rule releases the sealing key to is on allowed_image_measurements in force",
			"images", hexList(rule.Images), "locked_version", version)
		return
	}
	if prod {
		// The gate's verdict logs the refusal with the unlisted ids.
		g.WithholdKeyRule(rule.Images)
		return
	}
	log.Warn("key rule images: the key rule releases the sealing key to image(s) that allowed_image_measurements in force does not name; a prod chain would keep the shares sealed",
		"images", hexList(rule.Images), "unlisted", hexList(unlisted), "locked_version", version)
}

// hexList is ids in hex, comma-separated.
func hexList(ids [][]byte) string {
	s := make([]string, len(ids))
	for i, id := range ids {
		s[i] = hex.EncodeToString(id)
	}
	return strings.Join(s, ",")
}
