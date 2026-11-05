package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/runnerchain"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-admin/fakerunner"
)

// draft -group locked refuses an update whose allowed_image_measurements
// lists no image of a signer's platform, and names the signer and the
// kind; with an image of every platform kept it drafts. sign refuses such
// a body too, for the signer of the active file.
func TestDraftRefusesLockedWithoutOwnImage(t *testing.T) {
	full := cloudSetupText(t, 4, "threshold", "", "")
	dir := t.TempDir()
	conf := writeFile(t, filepath.Join(dir, "setup.conf"), full)
	mustTool(t, "setup", "-out", filepath.Join(dir, "setups"), conf)
	var signers []map[string]string
	for _, n := range []string{"gsigner-1", "gsigner-2", "gsigner-3"} {
		r := fakerunner.StartSetupAs(t, mustRead(t, filepath.Join(dir, "setups", n+".setup")), runnerchain.Mainnet)
		cert, key := r.ClientFiles(t, t.TempDir())
		writeJSONFile(t, filepath.Join(dir, n, "cloud.json"), map[string]any{
			"address": r.Addr(), "client_cert": cert, "client_key": key, "accounts": "accounts.json", "slots_per_epoch": 2,
			"attestation": map[string]any{"verifier": "dev"},
		})
		signers = append(signers, map[string]string{"name": n, "cloud": n + "/cloud.json", "setup": "setups/" + n + ".setup"})
	}
	cl := writeJSONFile(t, filepath.Join(dir, "cluster.json"), map[string]any{"signers": signers})
	mustTool(t, "pin", "-cluster", cl)

	// The same approvers as the setup, so the update is no rotation.
	var approverLines string
	for _, l := range strings.Split(full, "\n") {
		if strings.HasPrefix(l, "approvers = ") {
			approverLines += l + "\n"
		}
	}
	locked := approverLines + lockedText(nil, 2, 0, fee1, fee2)
	without := func(kind string) string {
		var keep []string
		for _, l := range strings.Split(cloudImages, "\n") {
			if !strings.HasPrefix(l, "allowed_image_measurements = "+kind+" ") {
				keep = append(keep, l)
			}
		}
		return strings.Join(keep, "\n")
	}
	for kind, signer := range map[string]string{"azure": "gsigner-1", "nitro": "gsigner-2", "gcp": "gsigner-3"} {
		file := writeFile(t, filepath.Join(dir, "no-"+kind+".conf"), locked+without(kind))
		body := filepath.Join(dir, "no-"+kind+".bin")
		wantIn(t, failTool(t, "draft", "-cluster", cl, "-group", "locked", "-margin", "0s", "-out", body, file),
			"signer "+signer, "platform is "+kind, "lists no "+kind+" image")
		if _, err := os.Stat(body); !os.IsNotExist(err) {
			t.Fatalf("no %s image: the refused draft wrote %s (stat: %v)", kind, body, err)
		}
	}
	file := writeFile(t, filepath.Join(dir, "all.conf"), locked+cloudImages)
	body := filepath.Join(dir, "all.bin")
	wantIn(t, mustTool(t, "draft", "-cluster", cl, "-group", "locked", "-margin", "0s", "-out", body, file),
		"locked update version 1 for 3 signers", "wrote "+body)

	// sign: the drafted body without one image kind, next to the same active
	// file (gsigner-1's setup, an Azure signer).
	b, err := setupwire.DecodeUpdateBody(mustRead(t, body))
	if err != nil {
		t.Fatal(err)
	}
	keys := approvers(t, dir, 1)
	for kind, refused := range map[setupwire.ImageKind]bool{setupwire.ImageAzure: true, setupwire.ImageNitro: false} {
		c := *b
		lc := *b.Locked
		lc.AllowedImageMeasurements = nil
		for _, im := range b.Locked.AllowedImageMeasurements {
			if im.Kind != kind {
				lc.AllowedImageMeasurements = append(lc.AllowedImageMeasurements, im)
			}
		}
		c.Locked = &lc
		raw, err := c.Encode()
		if err != nil {
			t.Fatal(err)
		}
		edited := writeFile(t, filepath.Join(dir, "no-"+kind.String()+"-edited.bin"), string(raw))
		writeFile(t, edited+".active", string(mustRead(t, body+".active")))
		args := []string{"sign", "-key", keys[0].file, "-expect-sha256", expectOf(t, edited), edited}
		if refused {
			wantIn(t, failTool(t, args...), "signer gsigner-1", "lists no azure image", "nothing signed")
		} else {
			wantIn(t, mustTool(t, args...), "wrote ")
		}
	}
}
