package main

import (
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/flavor"
	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// setup draws the policy salts once for the cluster and a platform salt for
// each signer: the signers share policy_root and their group roots, each
// has a platform_commitment of its own, and a second run draws other salts.
// A file that names a salt is refused.
func TestSetupSalts(t *testing.T) {
	dir := t.TempDir()
	keys := approvers(t, dir, 3)
	good := setupText(dir, caDER(t), genesisTime(), lockedText(keys, 2, 0, fee1), "a", "b", "c")
	p := writeFile(t, filepath.Join(dir, "setup.conf"), good)
	read := func(dir, name string) *setupwire.Setup {
		s, err := setupwire.DecodeSetup(mustRead(t, filepath.Join(dir, name+".setup")))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	out := mustTool(t, "setup", "-out", filepath.Join(dir, "out"), p)
	var roots, commitments, locked [][32]byte
	for _, n := range []string{"a", "b", "c"} {
		s := read(filepath.Join(dir, "out"), n)
		pr, _ := s.PolicyRoot()
		pc, _ := s.PlatformCommitment()
		lh, _ := s.GroupHash(setupwire.GroupLocked)
		wantIn(t, out, n+" policy_root "+hex.EncodeToString(pr[:]))
		roots, commitments, locked = append(roots, pr), append(commitments, pc), append(locked, lh)
	}
	if roots[0] != roots[1] || roots[1] != roots[2] || locked[0] != locked[1] || locked[1] != locked[2] {
		t.Fatal("the signers of one cluster have different policy roots or locked roots")
	}
	if commitments[0] == commitments[1] || commitments[1] == commitments[2] {
		t.Fatal("two signers have the same platform_commitment")
	}
	mustTool(t, "setup", "-out", filepath.Join(dir, "again"), p)
	if pr, _ := read(filepath.Join(dir, "again"), "a").PolicyRoot(); pr == roots[0] {
		t.Fatal("a second run drew the same policy salts")
	}
	for _, line := range []string{"salt.genesis_time = 0x" + strings.Repeat("01", 32), "platform_salt = 0x" + strings.Repeat("02", 32)} {
		bad := writeFile(t, filepath.Join(t.TempDir(), "setup.conf"), line+"\n"+good)
		key, _, _ := strings.Cut(line, " ")
		wantIn(t, failTool(t, "setup", "-out", filepath.Join(t.TempDir(), "out"), bad), "line 1: "+key+": signer-admin setup draws the salts")
	}
}

// draft gives each update fresh salts for the leaves of its group, so two
// drafts of the same values have other group roots, and it refuses slot
// time changes that the runner's slot time rule refuses: with the clock in
// epoch 1000, max_sign_epochs_ahead_of_clock 2 and no change delay, the
// first epoch a change may touch is 1004.
func TestDraftSaltsAndSlotTimes(t *testing.T) {
	fc := newFakeCluster(t)
	mustTool(t, "pin", "-cluster", fc.cluster)
	file := writeFile(t, fc.path("fees.conf"), lockedText(fc.keys[:3], 2, 0, fee1, fee2))
	var bodies []*setupwire.UpdateBody
	for _, out := range []string{"one.bin", "two.bin"} {
		mustTool(t, "draft", "-cluster", fc.cluster, "-group", "locked", "-margin", "0s", "-out", fc.path(out), file)
		b, err := setupwire.DecodeUpdateBody(mustRead(t, fc.path(out)))
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, b)
	}
	r1, _ := bodies[0].GroupRoot()
	r2, _ := bodies[1].GroupRoot()
	if len(bodies[0].Salts) != setupwire.NumLockedLeaves || r1 == r2 {
		t.Fatal("two drafts share their salts")
	}

	soon := writeFile(t, fc.path("soon.conf"), lockedText(fc.keys[:3], 2, 0, fee1)+"slot_time_changes = 1003 2\n")
	wantIn(t, failTool(t, "draft", "-cluster", fc.cluster, "-group", "locked", "-margin", "0s", "-out", fc.path("soon.bin"), soon),
		"the slot time rule refuses this update", "epoch 1003")
	later := writeFile(t, fc.path("later.conf"), lockedText(fc.keys[:3], 2, 0, fee1)+"slot_time_changes = 1010 2\n")
	out := mustTool(t, "draft", "-cluster", fc.cluster, "-group", "locked", "-margin", "0s", "-out", fc.path("later.bin"), later)
	wantIn(t, out, "+ slot_time_changes = 1010 2")
	genesis := writeFile(t, fc.path("genesis.conf"), lockedText(fc.keys[:3], 2, 0, fee1)+"slot_time_changes = 1010 4\n")
	wantIn(t, failTool(t, "draft", "-cluster", fc.cluster, "-group", "locked", "-margin", "0s", "-out", fc.path("genesis.bin"), genesis),
		"keeps the genesis slot time")
}

// The test chain has 8 s epochs; with a change delay of 3600 s a locked
// update is in force from epoch 1450, so a slot time change may start at
// epoch 1454. An open update with -margin 2h is in force at epoch 1900 under
// the slot times in force, at epoch 3238 if 1 s slots start at epoch 1454,
// or at epoch 1677 if 8 s slots do.

// A slot time change pending, then a fork: draft counts epochs under the
// pending slot times too, from the copy push kept.
func TestDraftForkCountsPendingSlotTimes(t *testing.T) {
	fc := newFakeClusterAs(t, flavor.Default, 3600)
	mustTool(t, "pin", "-cluster", fc.cluster)
	_, signed := fc.update(t, "slots", "locked", lockedText(fc.keys[:3], 2, 3600, fee1)+"slot_time_changes = 1454 1\n", "0s", 0, 1)
	if out := mustTool(t, "push", "-cluster", fc.cluster, signed); count(out, `accepted: locked v1/[0-9a-f]{8} pending`) != 3 {
		t.Fatalf("push:\n%s", out)
	}
	near := writeFile(t, fc.path("near.conf"), openText(2000))
	wantIn(t, failTool(t, "draft", "-cluster", fc.cluster, "-group", "open", "-margin", "2h", "-out", fc.path("near.bin"), near),
		"the fork rule refuses this update: it changes epoch 2000, and a signer may sign up to epoch 3241")
	far := writeFile(t, fc.path("far.conf"), openText(3242))
	mustTool(t, "draft", "-cluster", fc.cluster, "-group", "open", "-margin", "2h", "-out", fc.path("far.bin"), far)
}

// The same with the slot time change pending on one signer only, not the
// first: its runner would refuse the fork, so draft does.
func TestDraftForkCountsPendingSlotTimesOfAnySigner(t *testing.T) {
	fc := newFakeClusterAs(t, flavor.Default, 3600)
	mustTool(t, "pin", "-cluster", fc.cluster)
	_, signed := fc.update(t, "slots", "locked", lockedText(fc.keys[:3], 2, 3600, fee1)+"slot_time_changes = 1454 1\n", "0s", 0, 1)
	if out := mustTool(t, "push", "-cluster", fc.cluster, "-signers", "s3", signed); count(out, `accepted: locked v1/[0-9a-f]{8} pending`) != 1 {
		t.Fatalf("push:\n%s", out)
	}
	near := writeFile(t, fc.path("near.conf"), openText(2000))
	wantIn(t, failTool(t, "draft", "-cluster", fc.cluster, "-group", "open", "-margin", "2h", "-out", fc.path("near.bin"), near),
		"the fork rule refuses this update: it changes epoch 2000")
}

// A fork pending, then a slot time change: draft refuses slot times under
// which the pending fork at epoch 2000 comes within reach before its
// effective time, and takes slower ones.
func TestDraftSlotTimesCountPendingFork(t *testing.T) {
	fc := newFakeClusterAs(t, flavor.Default, 3600)
	mustTool(t, "pin", "-cluster", fc.cluster)
	_, signed := fc.update(t, "fork", "open", openText(2000), "2h", 0, 1)
	if out := mustTool(t, "push", "-cluster", fc.cluster, signed); count(out, `accepted: open v1/[0-9a-f]{8} pending`) != 3 {
		t.Fatalf("push:\n%s", out)
	}
	fast := writeFile(t, fc.path("fast.conf"), lockedText(fc.keys[:3], 2, 3600, fee1)+"slot_time_changes = 1454 1\n")
	wantIn(t, failTool(t, "draft", "-cluster", fc.cluster, "-group", "locked", "-margin", "0s", "-out", fc.path("fast.bin"), fast),
		"the fork rule refuses these slot times: the pending open version 1 changes epoch 2000, and under them a signer may sign up to epoch 3241")
	slow := writeFile(t, fc.path("slow.conf"), lockedText(fc.keys[:3], 2, 3600, fee1)+"slot_time_changes = 1454 8\n")
	mustTool(t, "draft", "-cluster", fc.cluster, "-group", "locked", "-margin", "0s", "-out", fc.path("slow.bin"), slow)
}

// setup and draft -group locked take allowed_builder_request_auth_data_roots
// in the human form: the setup and the update body carry the roots, sorted.
func TestBuilderRequestAuthRoots(t *testing.T) {
	r1, r2 := "0x"+strings.Repeat("52", 32), "0x"+strings.Repeat("51", 32)
	lines := "allowed_builder_request_auth_data_roots = " + r1 + "\nallowed_builder_request_auth_data_roots = " + r2 + "\n"
	dir := t.TempDir()
	keys := approvers(t, dir, 3)
	p := writeFile(t, filepath.Join(dir, "setup.conf"), setupText(dir, caDER(t), genesisTime(), lockedText(keys, 2, 0, fee1)+lines, "a"))
	mustTool(t, "setup", "-out", filepath.Join(dir, "out"), p)
	s, err := setupwire.DecodeSetup(mustRead(t, filepath.Join(dir, "out", "a.setup")))
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Locked.AllowedBuilderRequestAuthDataRoots; len(got) != 2 || "0x"+hex.EncodeToString(got[0][:]) != r2 || "0x"+hex.EncodeToString(got[1][:]) != r1 {
		t.Fatalf("setup roots %x", got)
	}

	fc := newFakeCluster(t)
	mustTool(t, "pin", "-cluster", fc.cluster)
	file := writeFile(t, fc.path("auth.conf"), lockedText(fc.keys[:3], 2, 0, fee1)+"allowed_builder_request_auth_data_roots = "+r1+"\n")
	out := mustTool(t, "draft", "-cluster", fc.cluster, "-group", "locked", "-margin", "0s", "-out", fc.path("auth.bin"), file)
	wantIn(t, out, "+ allowed_builder_request_auth_data_roots = "+r1)
	b, err := setupwire.DecodeUpdateBody(mustRead(t, fc.path("auth.bin")))
	if err != nil {
		t.Fatal(err)
	}
	if got := b.Locked.AllowedBuilderRequestAuthDataRoots; len(got) != 1 || "0x"+hex.EncodeToString(got[0][:]) != r1 {
		t.Fatalf("update roots %x", got)
	}
	twice := writeFile(t, fc.path("twice.conf"), lockedText(fc.keys[:3], 2, 0, fee1)+lines+"allowed_builder_request_auth_data_roots = "+r1+"\n")
	wantIn(t, failTool(t, "draft", "-cluster", fc.cluster, "-group", "locked", "-margin", "0s", "-out", fc.path("twice.bin"), twice),
		"allowed_builder_request_auth_data_roots: repeats the entry of line")
}
