package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/runnerchain"
	"github.com/lidofinance/tee-signer/governance/setuptext"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

// ownImageFixture is a cluster of an azure, a nitro and a gcp signer with
// the setups signer-admin setup built in dir/setups, its approvers, a
// parser of locked values with the cluster's approvers and the given
// images, and cloudImages without the images of one kind.
type ownImageFixture struct {
	dir     string
	members []*member
	keys    []approver
	locked  func(images string) *setupwire.Locked
	without func(kind string) string
}

func ownImageCluster(t *testing.T) *ownImageFixture {
	t.Helper()
	dir := t.TempDir()
	f := &ownImageFixture{dir: dir, keys: approvers(t, dir, 3)}
	full := cloudSetupTextKeys(t, 4, "threshold", "", "", f.keys)
	conf := writeFile(t, filepath.Join(dir, "setup.conf"), full)
	mustTool(t, "setup", "-out", filepath.Join(dir, "setups"), conf)
	for _, n := range []string{"gsigner-1", "gsigner-2", "gsigner-3"} {
		raw := mustRead(t, filepath.Join(dir, "setups", n+".setup"))
		s, err := setupwire.DecodeSetup(raw)
		if err != nil {
			t.Fatal(err)
		}
		h, err := s.Hash()
		if err != nil {
			t.Fatal(err)
		}
		f.members = append(f.members, &member{name: n, cloudPath: filepath.Join(dir, n, "cloud.json"), setup: s, setupRaw: raw, setupHash: h})
	}

	var approverLines string
	for _, l := range strings.Split(full, "\n") {
		if strings.HasPrefix(l, "approvers = ") {
			approverLines += l + "\n"
		}
	}
	f.locked = func(images string) *setupwire.Locked {
		t.Helper()
		l, err := setuptext.ParseLocked("locked.conf", []byte(approverLines+lockedText(nil, 2, 0, fee1, fee2)+images))
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	f.without = func(kind string) string {
		var keep []string
		for _, l := range strings.Split(cloudImages, "\n") {
			if !strings.HasPrefix(l, "allowed_image_measurements = "+kind+" ") {
				keep = append(keep, l)
			}
		}
		return strings.Join(keep, "\n")
	}
	return f
}

// clusterJSON writes a cluster.json of the members. No runner answers at
// their cloud.json: the tests here stop before any connection.
func (f *ownImageFixture) clusterJSON(t *testing.T, members []*member) string {
	t.Helper()
	var signers []map[string]string
	for _, m := range members {
		signers = append(signers, map[string]string{"name": m.name, "cloud": m.name + "/cloud.json", "setup": "setups/" + m.name + ".setup"})
	}
	return writeJSONFile(t, filepath.Join(f.dir, "cluster.json"), map[string]any{"signers": signers})
}

// states builds in-memory states at version 0 for members, as draft reads
// them, with no image check in HEALTH.
func (f *ownImageFixture) states(t *testing.T, members []*member) []*signerState {
	t.Helper()
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
		states = append(states, &signerState{state: st, health: &cloud.Health{}, chain: runnerchain.Devnet})
	}
	return states
}

// draft writes a locked draft of images for members to dir/name, as
// draft does after it read their states.
func (f *ownImageFixture) draft(t *testing.T, members []*member, name, images string) string {
	t.Helper()
	path := filepath.Join(f.dir, name)
	c := &cluster{updates: filepath.Join(f.dir, "updates"), members: members}
	body := &setupwire.UpdateBody{Group: setupwire.GroupLocked, Locked: f.locked(images)}
	if err := writeDraft(c, f.states(t, members), body, 0, path, nil, io.Discard); err != nil {
		t.Fatalf("draft %s: %v", name, err)
	}
	return path
}

// dropKind writes the body at path again without its images of kind, as
// someone with write access edits a draft after draft checked it.
func dropKind(t *testing.T, path, name string, kind setupwire.ImageKind) string {
	t.Helper()
	b, err := setupwire.DecodeUpdateBody(mustRead(t, path))
	if err != nil {
		t.Fatal(err)
	}
	lc := *b.Locked
	lc.AllowedImageMeasurements = nil
	for _, im := range b.Locked.AllowedImageMeasurements {
		if im.Kind != kind {
			lc.AllowedImageMeasurements = append(lc.AllowedImageMeasurements, im)
		}
	}
	b.Locked = &lc
	raw, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(filepath.Dir(path), name)
	writeFile(t, out, string(raw))
	writeFile(t, out+".active", string(mustRead(t, path+".active")))
	return out
}

// handSign signs the body at path with the approver's key outside the
// tool and writes the signature file sign would, so assemble gets a valid
// signature over a body sign refuses.
func handSign(t *testing.T, path string, a approver) string {
	t.Helper()
	b, err := setupwire.DecodeUpdateBody(mustRead(t, path))
	if err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(mustRead(t, a.file))))
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(seed)
	sig, err := b.Sign(key)
	if err != nil {
		t.Fatal(err)
	}
	h, err := b.Hash()
	if err != nil {
		t.Fatal(err)
	}
	s := &sigFile{bodyHash: h, key: [32]byte(key.Public().(ed25519.PublicKey)), sig: sig}
	return writeFile(t, fmt.Sprintf("%s.%s.sig", path, a.pub[2:10]), string(s.format()))
}

// draft -group locked and sign refuse an update whose
// allowed_image_measurements lists no image of a signer's platform, and
// name the signer and the kind; with an image of every platform kept it
// passes. The check is tested here directly: draft reads every member's
// state first, and a cloud platform setup refuses the dev verifier that a
// fake runner would need. TestWriteDraftRefusesLockedWithoutOwnImage
// checks that draft calls it.
func TestDraftRefusesLockedWithoutOwnImage(t *testing.T) {
	f := ownImageCluster(t)
	if err := checkOwnImages(f.members, f.locked(cloudImages)); err != nil {
		t.Fatalf("every image kind kept: %v", err)
	}
	for kind, signer := range map[string]string{"azure": "gsigner-1", "nitro": "gsigner-2", "gcp": "gsigner-3"} {
		l := f.locked(f.without(kind))
		err := checkOwnImages(f.members, l)
		if err == nil {
			t.Fatalf("no %s image: passed", kind)
		}
		wantIn(t, err.Error(), "signer "+signer, "platform is "+kind, "lists no "+kind+" image")
		// sign and assemble check only the signer of their active file.
		for _, m := range f.members {
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
	f := ownImageCluster(t)
	c := &cluster{updates: filepath.Join(f.dir, "updates"), members: f.members}
	states := f.states(t, f.members)
	draft := func(name, images string) (string, error) {
		path := filepath.Join(f.dir, name)
		body := &setupwire.UpdateBody{Group: setupwire.GroupLocked, Locked: f.locked(images)}
		return path, writeDraft(c, states, body, 0, path, nil, io.Discard)
	}

	path, err := draft("all.bin", cloudImages)
	if err != nil {
		t.Fatalf("every image kind kept: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("every image kind kept: %v", err)
	}
	for kind, signer := range map[string]string{"azure": "gsigner-1", "nitro": "gsigner-2", "gcp": "gsigner-3"} {
		path, err := draft("no-"+kind+".bin", f.without(kind))
		if err == nil {
			t.Fatalf("no %s image: draft passed", kind)
		}
		wantIn(t, err.Error(), "signer "+signer, "platform is "+kind, "lists no "+kind+" image")
		for _, p := range []string{path, path + ".active"} {
			if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("no %s image: draft wrote %s (%v)", kind, p, err)
			}
		}
	}
}

// push refuses a locked update whose list has no image of a signer's
// platform before it sends anything: a draft made with -signers for the
// azure and nitro signers, without the gcp image, passes draft, sign and
// assemble (the active file is the azure signer's), and push to the whole
// cluster refuses it for the gcp signer.
func TestPushRefusesLockedWithoutOwnImage(t *testing.T) {
	f := ownImageCluster(t)
	body := f.draft(t, f.members[:2], "no-gcp.bin", f.without("gcp"))
	var sigs []string
	for _, k := range f.keys[:2] {
		mustTool(t, "sign", "-key", k.file, "-expect-sha256", expectOf(t, body), body)
		sigs = append(sigs, fmt.Sprintf("%s.%s.sig", body, k.pub[2:10]))
	}
	signed := filepath.Join(f.dir, "no-gcp.signed")
	mustTool(t, append([]string{"assemble", "-out", signed, body}, sigs...)...)

	out := failTool(t, "push", "-cluster", f.clusterJSON(t, f.members), signed)
	wantIn(t, out, "signer gsigner-3", "platform is gcp", "lists no gcp image")
	if strings.Contains(out, "refused:") {
		t.Fatalf("push went on to the signers:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(f.dir, "updates")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("push kept the update (%v)", err)
	}
	// To the two signers it was drafted for, the rule by kind passes; the
	// push then needs their states, and fails at their connection files,
	// which do not exist here.
	out = failTool(t, "push", "-cluster", f.clusterJSON(t, f.members[:2]), signed)
	wantIn(t, out, "gsigner-1 error:", "gsigner-2 error:", "needs the state of every signer")
	if strings.Contains(out, "lists no") {
		t.Fatalf("push to the drafted signers refused the list:\n%s", out)
	}
}

// assemble refuses a body whose list has no image of the active file's
// signer, with signatures made outside the tool over that body.
func TestAssembleRefusesLockedWithoutOwnImage(t *testing.T) {
	f := ownImageCluster(t)
	all := f.draft(t, f.members, "all.bin", cloudImages)
	// The active file is gsigner-1's, azure.
	edited := dropKind(t, all, "no-azure.bin", setupwire.ImageAzure)
	sigs := []string{handSign(t, edited, f.keys[0]), handSign(t, edited, f.keys[1])}
	signed := filepath.Join(f.dir, "no-azure.signed")
	out := failTool(t, append([]string{"assemble", "-out", signed, edited}, sigs...)...)
	wantIn(t, out, "signer gsigner-1", "platform is azure", "lists no azure image")
	if _, err := os.Stat(signed); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("assemble wrote %s (%v)", signed, err)
	}
	// The same signatures over a body that keeps every kind assemble.
	kept := dropKind(t, all, "kept.bin", setupwire.ImageTA)
	sigs = []string{handSign(t, kept, f.keys[0]), handSign(t, kept, f.keys[1])}
	mustTool(t, append([]string{"assemble", "-out", filepath.Join(f.dir, "kept.signed"), kept}, sigs...)...)
}

// sign refuses a locked body whose active file does not load, and says so:
// it cannot run the own-image check for that signer. With the active file
// of the azure signer it refuses a body that drops the azure image and
// signs one that keeps it; without an active file it signs and says that
// the check did not run.
func TestSignOwnImageActiveFile(t *testing.T) {
	f := ownImageCluster(t)
	all := f.draft(t, f.members, "all.bin", cloudImages)
	key := f.keys[0].file

	bad := dropKind(t, all, "bad-active.bin", setupwire.ImageTA)
	writeFile(t, bad+".active", "{\"setup\":\"zz\"}\n")
	out := failTool(t, "sign", "-key", key, "-expect-sha256", expectOf(t, bad), bad)
	wantIn(t, out, bad+".active", "not hex", "nothing signed")
	if _, err := os.Stat(fmt.Sprintf("%s.%s.sig", bad, f.keys[0].pub[2:10])); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("sign wrote a signature (%v)", err)
	}

	noAzure := dropKind(t, all, "no-azure.bin", setupwire.ImageAzure)
	wantIn(t, failTool(t, "sign", "-key", key, "-expect-sha256", expectOf(t, noAzure), noAzure), "signer gsigner-1", "lists no azure image", "nothing signed")

	none := dropKind(t, all, "no-active.bin", setupwire.ImageTA)
	if err := os.Remove(none + ".active"); err != nil {
		t.Fatal(err)
	}
	wantIn(t, mustTool(t, "sign", "-key", key, "-expect-sha256", expectOf(t, none), none), "no active values", "wrote ")

	wantIn(t, mustTool(t, "sign", "-key", key, "-expect-sha256", expectOf(t, all), all), "wrote ")
}

// otherNitro is cloudImages with the nitro measurement replaced: the
// common rollout mistake, the new image listed and the running one dropped
// in one step.
func otherNitro(t *testing.T) string {
	t.Helper()
	s := strings.ReplaceAll(cloudImages, strings.Repeat("1", 96), strings.Repeat("2", 96))
	if s == cloudImages {
		t.Fatal("no nitro measurement to replace")
	}
	return s
}

// draft refuses a locked list that drops the image a signer runs, by the
// measurement HEALTH reports, not by kind only: a list that swaps the
// nitro measurement is refused with the signer's name and the measurement
// it runs. A signer whose running image HEALTH does not report falls back
// to the rule by kind.
func TestWriteDraftRefusesDroppingRunningImage(t *testing.T) {
	f := ownImageCluster(t)
	c := &cluster{updates: filepath.Join(f.dir, "updates"), members: f.members}
	states := f.states(t, f.members)
	nitro := strings.Repeat("11", 3*48)
	states[1].health.Image = &cloud.ImageCheck{State: cloud.ImageAllowed, Kind: "nitro", Measurement: nitro}
	draft := func(name, images string, drop ...string) error {
		body := &setupwire.UpdateBody{Group: setupwire.GroupLocked, Locked: f.locked(images)}
		return writeDraft(c, states, body, 0, filepath.Join(f.dir, name), drop, io.Discard)
	}
	if err := draft("same.bin", cloudImages); err != nil {
		t.Fatalf("the running image kept: %v", err)
	}
	err := draft("swap.bin", otherNitro(t))
	if err == nil {
		t.Fatal("the running nitro image dropped: draft passed")
	}
	wantIn(t, err.Error(), "signer gsigner-2", "runs the nitro image", nitro, "not list", "-drop-running-image gsigner-2")
	if _, err := os.Stat(filepath.Join(f.dir, "swap.bin")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("draft wrote swap.bin (%v)", err)
	}

	// The flag names the signer whose image the update drops on purpose.
	if err := draft("retire.bin", otherNitro(t), "gsigner-2"); err != nil {
		t.Fatalf("-drop-running-image gsigner-2: %v", err)
	}
	// It is refused for a signer whose image the list keeps, or that
	// reports none.
	for _, n := range []string{"gsigner-1", "gsigner-9"} {
		err := draft("wrong-"+n+".bin", otherNitro(t), "gsigner-2", n)
		if err == nil {
			t.Fatalf("-drop-running-image %s: passed", n)
		}
		wantIn(t, err.Error(), "-drop-running-image "+n)
	}
	wantIn(t, failTool(t, "draft", "-cluster", "x", "-group", "open", "-drop-running-image", "gsigner-2", "x.conf"), "an open update changes no image")

	// A list that keeps the running image needs no flag, and refuses it.
	wantIn(t, draft("kept-flag.bin", cloudImages, "gsigner-2").Error(), "-drop-running-image gsigner-2")
	// Without the running image in HEALTH, the kind is all the tool knows.
	states[1].health.Image = nil
	if err := draft("swap-unknown.bin", otherNitro(t)); err != nil {
		t.Fatalf("running image unknown, a nitro image listed: %v", err)
	}
	// A runner whose image the list in force does not name is not held
	// by this rule either: dropping it changes nothing for it.
	states[1].health.Image = &cloud.ImageCheck{State: cloud.ImageNotAllowed, Kind: "nitro", Measurement: nitro}
	if err := draft("swap-unlisted.bin", otherNitro(t)); err != nil {
		t.Fatalf("running image not allowed: %v", err)
	}
}

// draft and push against fake runners refuse a locked list that drops
// the image one of them reports it runs, and take it with
// -drop-running-image NAME.
func TestDropRunningImageFlow(t *testing.T) {
	fc := newFakeClusterWith(t, runnerchain.Mainnet, 0, cloudImages)
	nitro := strings.Repeat("11", 3*48)
	fc.runners["s2"].SetImage(cloud.ImageCheck{State: cloud.ImageAllowed, Kind: "nitro", Measurement: nitro})
	mustTool(t, "pin", "-cluster", fc.cluster)

	swap := writeFile(t, fc.path("swap.conf"), lockedText(fc.keys[:3], 2, 0, fee1)+otherNitro(t))
	out := failTool(t, "draft", "-cluster", fc.cluster, "-group", "locked", "-margin", "0s", "-out", fc.path("swap.bin"), swap)
	wantIn(t, out, "signer s2", "runs the nitro image", nitro)

	// The same list signed outside draft, as a script would make it.
	l, err := setuptext.ParseLocked("swap.conf", []byte(lockedText(fc.keys[:3], 2, 0, fee1)+otherNitro(t)))
	if err != nil {
		t.Fatal(err)
	}
	signed := craft(t, craftSpec{setup: fc.path("setups/s1.setup"), group: setupwire.GroupLocked, version: 1, locked: l, set: fc.keys[:3], signers: []int{0, 1}})
	seen := fc.runners["s2"].Seen(wireadmin.TypeConfigUpdate)
	out = failTool(t, "push", "-cluster", fc.cluster, signed)
	wantIn(t, out, "signer s2", "runs the nitro image", nitro)
	if fc.runners["s2"].Seen(wireadmin.TypeConfigUpdate) != seen {
		t.Fatalf("push sent the update:\n%s", out)
	}
	wantIn(t, failTool(t, "push", "-cluster", fc.cluster, "-drop-running-image", "s2,s1", signed), "-drop-running-image s1")

	// The retirement step: the flag names the signer.
	out = mustTool(t, "draft", "-cluster", fc.cluster, "-group", "locked", "-margin", "0s", "-drop-running-image", "s2", "-out", fc.path("retire.bin"), swap)
	wantIn(t, out, "drops the image s2 runs", "wrote "+fc.path("retire.bin"))
	out = mustTool(t, "push", "-cluster", fc.cluster, "-drop-running-image", "s2", signed)
	if count(out, `accepted: locked v1/[0-9a-f]{8} pending`) != 3 {
		t.Fatalf("push with -drop-running-image:\n%s", out)
	}
	// An open update takes no such flag.
	wantIn(t, failTool(t, "push", "-cluster", fc.cluster, "-drop-running-image", "s2", craft(t, craftSpec{setup: fc.path("setups/s1.setup"), group: setupwire.GroupOpen, version: 1, set: fc.keys[:3], signers: []int{0, 1}})), "an open update changes no image")
}
