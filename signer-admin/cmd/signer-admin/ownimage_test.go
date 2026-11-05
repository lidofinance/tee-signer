package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setuptext"
	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// draft -group locked and sign refuse an update whose
// allowed_image_measurements lists no image of a signer's platform, and
// name the signer and the kind; with an image of every platform kept it
// passes. Both commands call checkOwnImages: draft for every member, sign
// for the signer of the active file. The check is tested here directly:
// draft reads every member's state first, and a cloud platform setup
// refuses the dev verifier that a fake runner would need.
func TestDraftRefusesLockedWithoutOwnImage(t *testing.T) {
	full := cloudSetupText(t, 4, "threshold", "", "")
	dir := t.TempDir()
	conf := writeFile(t, filepath.Join(dir, "setup.conf"), full)
	mustTool(t, "setup", "-out", filepath.Join(dir, "setups"), conf)
	var members []*member
	for _, n := range []string{"gsigner-1", "gsigner-2", "gsigner-3"} {
		s, err := setupwire.DecodeSetup(mustRead(t, filepath.Join(dir, "setups", n+".setup")))
		if err != nil {
			t.Fatal(err)
		}
		members = append(members, &member{name: n, setup: s})
	}

	var approverLines string
	for _, l := range strings.Split(full, "\n") {
		if strings.HasPrefix(l, "approvers = ") {
			approverLines += l + "\n"
		}
	}
	locked := func(images string) *setupwire.Locked {
		t.Helper()
		l, err := setuptext.ParseLocked("locked.conf", []byte(approverLines+lockedText(nil, 2, 0, fee1, fee2)+images))
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	without := func(kind string) string {
		var keep []string
		for _, l := range strings.Split(cloudImages, "\n") {
			if !strings.HasPrefix(l, "allowed_image_measurements = "+kind+" ") {
				keep = append(keep, l)
			}
		}
		return strings.Join(keep, "\n")
	}
	if err := checkOwnImages(members, locked(cloudImages)); err != nil {
		t.Fatalf("every image kind kept: %v", err)
	}
	for kind, signer := range map[string]string{"azure": "gsigner-1", "nitro": "gsigner-2", "gcp": "gsigner-3"} {
		l := locked(without(kind))
		err := checkOwnImages(members, l)
		if err == nil {
			t.Fatalf("no %s image: passed", kind)
		}
		wantIn(t, err.Error(), "signer "+signer, "platform is "+kind, "lists no "+kind+" image")
		// sign checks only the signer of its active file.
		for _, m := range members {
			err := checkOwnImages([]*member{m}, l)
			if (m.name == signer) != (err != nil) {
				t.Fatalf("no %s image, %s alone: %v", kind, m.name, err)
			}
		}
	}
}
