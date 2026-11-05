package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/runnerchain"
	"github.com/lidofinance/tee-signer/governance/setuptext"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

// ownImageCluster returns the members of a cluster of an azure, a nitro and
// a gcp signer, a parser of locked values with the cluster's approvers and
// the given images, and cloudImages without the images of one kind.
func ownImageCluster(t *testing.T) ([]*member, func(images string) *setupwire.Locked, func(kind string) string) {
	t.Helper()
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
		members = append(members, &member{name: n, setup: s, setupRaw: mustRead(t, filepath.Join(dir, "setups", n+".setup"))})
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
	return members, locked, without
}

// draft -group locked and sign refuse an update whose
// allowed_image_measurements lists no image of a signer's platform, and
// name the signer and the kind; with an image of every platform kept it
// passes. Both commands call checkOwnImages: draft for every member, sign
// for the signer of the active file. The check is tested here directly:
// draft reads every member's state first, and a cloud platform setup
// refuses the dev verifier that a fake runner would need.
// TestWriteDraftRefusesLockedWithoutOwnImage checks that draft calls it.
func TestDraftRefusesLockedWithoutOwnImage(t *testing.T) {
	members, locked, without := ownImageCluster(t)
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

// draft refuses a locked update without an image of a signer's own
// platform before it writes anything, and writes the body when every image
// kind is kept. writeDraft is draft after it reads the signers' states, so
// the states here are built in memory: a cloud platform setup refuses the
// dev verifier that a fake runner would need.
func TestWriteDraftRefusesLockedWithoutOwnImage(t *testing.T) {
	members, locked, without := ownImageCluster(t)
	var states []*signerState
	for _, m := range members {
		st := &cloud.SetupState{}
		for _, g := range groups {
			h, err := m.setup.GroupHash(g)
			if err != nil {
				t.Fatal(err)
			}
			if g == setupwire.GroupLocked {
				st.Locked.Hash = h
			} else {
				st.Open.Hash = h
			}
		}
		states = append(states, &signerState{state: st, chain: runnerchain.Devnet})
	}
	dir := t.TempDir()
	c := &cluster{updates: filepath.Join(dir, "updates"), members: members}
	draft := func(name, images string) (string, error) {
		path := filepath.Join(dir, name)
		body := &setupwire.UpdateBody{Group: setupwire.GroupLocked, Locked: locked(images)}
		return path, writeDraft(c, states, body, 0, path, io.Discard)
	}

	path, err := draft("all.bin", cloudImages)
	if err != nil {
		t.Fatalf("every image kind kept: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("every image kind kept: %v", err)
	}
	for kind, signer := range map[string]string{"azure": "gsigner-1", "nitro": "gsigner-2", "gcp": "gsigner-3"} {
		path, err := draft("no-"+kind+".bin", without(kind))
		if err == nil {
			t.Fatalf("no %s image: draft passed", kind)
		}
		wantIn(t, err.Error(), "signer "+signer, "platform is "+kind, "lists no "+kind+" image")
		for _, f := range []string{path, path + ".active"} {
			if _, err := os.Stat(f); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("no %s image: draft wrote %s (%v)", kind, f, err)
			}
		}
	}
}
