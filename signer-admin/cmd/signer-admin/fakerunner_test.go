package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/flavor"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-admin/fakerunner"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

// fakeCluster is three fake runners (internal/fakerunner, mutual TLS, the
// dev document) with the setups signer-admin setup built, and the
// cluster.json and cloud.json files that name them.
type fakeCluster struct {
	dir     string
	cluster string
	keys    []approver
	runners map[string]*fakerunner.Runner
	hashes  map[string]string
}

var names = []string{"s1", "s2", "s3"}

func newFakeCluster(t *testing.T) *fakeCluster {
	t.Helper()
	return newFakeClusterAs(t, flavor.Default, 0)
}

// newFakeClusterAs is newFakeCluster with runners of build flavour f and
// setups with the time lock timeLock.
func newFakeClusterAs(t *testing.T, f flavor.Flavor, timeLock int) *fakeCluster {
	t.Helper()
	dir := t.TempDir()
	fc := &fakeCluster{dir: dir, keys: approvers(t, dir, 4), runners: map[string]*fakerunner.Runner{}}
	conf := writeFile(t, filepath.Join(dir, "setup.conf"),
		setupText(dir, caDER(t), genesisTime(), lockedText(fc.keys[:3], 2, timeLock, fee1), names...))
	out := mustTool(t, "setup", "-out", filepath.Join(dir, "setups"), conf)
	fc.hashes = setupHashes(out)
	if len(fc.hashes) != 3 || count(out, `^cluster_id 0x[0-9a-f]{64}$`) != 1 {
		t.Fatalf("setup:\n%s", out)
	}
	var signers []map[string]string
	for _, n := range names {
		raw, err := os.ReadFile(filepath.Join(dir, "setups", n+".setup"))
		if err != nil {
			t.Fatal(err)
		}
		r := fakerunner.StartSetupAs(t, raw, f)
		fc.runners[n] = r
		cert, key := r.ClientFiles(t, t.TempDir())
		writeJSONFile(t, filepath.Join(dir, n, "cloud.json"), map[string]any{
			"address": r.Addr(), "client_cert": cert, "client_key": key, "accounts": "accounts.json", "slots_per_epoch": 2,
			"attestation": map[string]any{"verifier": "dev"},
		})
		signers = append(signers, map[string]string{"name": n, "cloud": n + "/cloud.json", "setup": "setups/" + n + ".setup"})
	}
	fc.cluster = writeJSONFile(t, filepath.Join(dir, "cluster.json"), map[string]any{"signers": signers})
	return fc
}

func (fc *fakeCluster) path(name string) string { return filepath.Join(fc.dir, name) }

// signAll signs body with the approvers at the indexes of fc.keys and
// returns the signature files.
func (fc *fakeCluster) signAll(t *testing.T, body string, idx ...int) []string {
	t.Helper()
	var sigs []string
	for _, i := range idx {
		out := mustTool(t, "sign", "-key", fc.keys[i].file, body)
		wantIn(t, out, "wrote ")
		sigs = append(sigs, fmt.Sprintf("%s.%s.sig", body, fc.keys[i].pub[2:10]))
	}
	return sigs
}

// update drafts group from text, signs it with the approvers idx, assembles
// and returns the paths of the body and the signed update.
func (fc *fakeCluster) update(t *testing.T, name, group, text, margin string, idx ...int) (string, string) {
	t.Helper()
	file := writeFile(t, fc.path(name+".conf"), text)
	body := fc.path(name + ".bin")
	mustTool(t, "draft", "-cluster", fc.cluster, "-group", group, "-margin", margin, "-out", body, file)
	signed := fc.path(name + ".signed")
	mustTool(t, append([]string{"assemble", "-out", signed, body}, fc.signAll(t, body, idx...)...)...)
	return body, signed
}

// The whole track against three fake runners: setup, pin, draft, show,
// sign, assemble, push, status; then a rotation, a time lock with a
// supersede, an open update and -raise-min, and the refusals.
func TestFlowFakeRunners(t *testing.T) {
	fc := newFakeCluster(t)
	cl := fc.cluster

	// Before pin, the runners report a setup that no cloud.json pins.
	wantIn(t, failTool(t, "status", "-cluster", cl), "no setup_sha256 is pinned")
	out := mustTool(t, "pin", "-cluster", cl)
	if count(out, `^s[123] pinned: setup_sha256 [0-9a-f]{64} in .*locked=v0/`) != 3 {
		t.Fatalf("pin:\n%s", out)
	}
	for _, n := range names {
		if got := readAttestation(t, fc.path(n+"/cloud.json"))["setup_sha256"]; got != fc.hashes[n] {
			t.Fatalf("%s pins %v, want %s", n, got, fc.hashes[n])
		}
	}
	out = mustTool(t, "pin", "-cluster", cl)
	if count(out, `pinned already`) != 3 {
		t.Fatalf("pin again:\n%s", out)
	}
	out = mustTool(t, "status", "-cluster", cl)
	if count(out, `^s[123] setup=[0-9a-f]{8} locked=v0/[0-9a-f]{8} open=v0/[0-9a-f]{8} approvers=[0-9a-f]{8} clock=trusted\(fake\) build=default$`) != 3 {
		t.Fatalf("status:\n%s", out)
	}

	// A locked update: a second fee recipient, in force at once (time lock 0).
	file := writeFile(t, fc.path("fees.conf"), lockedText(fc.keys[:3], 2, 0, fee1, fee2))
	body := fc.path("update.bin")
	out = mustTool(t, "draft", "-cluster", cl, "-group", "locked", "-margin", "0s", "-out", body, file)
	wantIn(t, out, "locked update version 1 for 3 signers", "+ allowed_fee_recipients = "+fee2, "wrote "+body)
	drafted := bodyHash(t, out)
	out = mustTool(t, "show", body)
	wantIn(t, out, "version = 1", "body_sha256 "+drafted, "active values from "+body+".active: locked version 0", "+ allowed_fee_recipients = "+fee2)

	// A key file others can read is refused.
	loose := fc.path("loose.key")
	key, _ := os.ReadFile(fc.keys[0].file)
	if err := os.WriteFile(loose, key, 0o644); err != nil {
		t.Fatal(err)
	}
	wantIn(t, failTool(t, "sign", "-key", loose, body), "mode 0644")

	sigs := fc.signAll(t, body, 0, 1)
	signed := fc.path("update.signed")
	wantIn(t, failTool(t, "assemble", "-out", signed, body, sigs[0]), "1 of the active approvers signed, approvals_needed is 2")
	wantIn(t, failTool(t, "assemble", "-out", signed, body, sigs[0], fc.signAll(t, body, 3)[0]), "is not an active approver")
	out = mustTool(t, append([]string{"assemble", "-out", signed, body}, sigs...)...)
	wantIn(t, out, "approvers 0,1 of 3 (k 2)")
	out = mustTool(t, "show", "-active", body+".active", signed)
	wantIn(t, out, "signatures: complete and valid")

	out = mustTool(t, "push", "-cluster", cl, signed)
	if count(out, `^s[123] accepted: locked v1/[0-9a-f]{8} in force$`) != 3 {
		t.Fatalf("push:\n%s", out)
	}
	out = mustTool(t, "push", "-cluster", cl, signed)
	if count(out, `^s[123] known: locked v1/`) != 3 {
		t.Fatalf("push again:\n%s", out)
	}
	if ents, _ := os.ReadDir(fc.path("updates")); len(ents) != 1 || !strings.HasPrefix(ents[0].Name(), "locked-v1-"+drafted[:8]) {
		t.Fatalf("updates folder: %v", ents)
	}
	out = mustTool(t, "status", "-cluster", cl)
	if count(out, `locked=v1/`+drafted[:8]+` open=v0/`) != 3 {
		t.Fatalf("status after the update:\n%s", out)
	}

	// Refused by the runners: a stale prev_hash (the setup's locked group,
	// version 1 is in force).
	stale := craft(t, craftSpec{setup: fc.path("setups/s1.setup"), group: setupwire.GroupLocked, version: 2, set: fc.keys[:3], signers: []int{0, 1}})
	out, err := tool(t, "push", "-cluster", cl, stale)
	if err == nil || count(out, `^s[123] refused: .*prev_hash [0-9a-f]+ is not the locked update in force \(version 1`) != 3 {
		t.Fatalf("stale prev_hash: %v\n%s", err, out)
	}

	// Not sent: an update of another cluster.
	other := newFakeCluster(t)
	wrong := craft(t, craftSpec{setup: other.path("setups/s1.setup"), group: setupwire.GroupLocked, version: 1, set: other.keys[:3], signers: []int{0, 1}})
	seen := fc.runners["s1"].Seen(wireadmin.TypeConfigUpdate)
	out, err = tool(t, "push", "-cluster", cl, wrong)
	if err == nil || count(out, `^s[123] refused: not sent: update: for another cluster_id`) != 3 || fc.runners["s1"].Seen(wireadmin.TypeConfigUpdate) != seen {
		t.Fatalf("wrong cluster: %v\n%s", err, out)
	}

	// Rotation: approver 3 leaves, approver 4 joins. Every new key signs.
	rot := writeFile(t, fc.path("rotation.conf"), lockedText([]approver{fc.keys[0], fc.keys[1], fc.keys[3]}, 2, 0, fee1, fee2))
	rbody := fc.path("rotation.bin")
	out = mustTool(t, "draft", "-cluster", cl, "-group", "locked", "-margin", "0s", "-out", rbody, rot)
	wantIn(t, out, "locked update version 2", "rotation: approvals_needed of the active approvers sign, and every one of the 3 new keys signs too",
		"- approvers = "+fc.keys[2].pub, "+ approvers = "+fc.keys[3].pub)
	rsigs := fc.signAll(t, rbody, 0, 1)
	rsigned := fc.path("rotation.signed")
	wantIn(t, failTool(t, append([]string{"assemble", "-out", rsigned, rbody}, rsigs...)...), "the new keys at positions 2 have not")
	out = mustTool(t, append([]string{"assemble", "-out", rsigned, rbody}, append(rsigs, fc.signAll(t, rbody, 3)...)...)...)
	wantIn(t, out, "and all 3 new keys")
	out = mustTool(t, "push", "-cluster", cl, rsigned)
	if count(out, `accepted: locked v2/[0-9a-f]{8} in force`) != 3 {
		t.Fatalf("rotation push:\n%s", out)
	}
	newSet := setupwire.ApproverSet{ApprovalsNeeded: 2}
	for _, i := range []int{0, 1, 3} {
		b, _ := hex.DecodeString(fc.keys[i].pub[2:])
		newSet.Keys = append(newSet.Keys, [32]byte(b))
	}
	setHash := newSet.Hash()
	out = mustTool(t, "status", "-cluster", cl)
	if count(out, "approvers="+hex.EncodeToString(setHash[:4])) != 3 {
		t.Fatalf("status after the rotation:\n%s", out)
	}

	// A time lock of an hour (in force at once: the active lock is 0), then
	// an update that waits for it, and a second one that supersedes it.
	newKeys := []approver{fc.keys[0], fc.keys[1], fc.keys[3]}
	_, lockSigned := fc.update(t, "lock", "locked", lockedText(newKeys, 2, 3600, fee1, fee2), "0s", 0, 3)
	mustTool(t, "push", "-cluster", cl, lockSigned)
	_, aSigned := fc.update(t, "a", "locked", lockedText(newKeys, 2, 3600, fee1, fee2, fee3), "0s", 0, 1)
	out = mustTool(t, "push", "-cluster", cl, aSigned)
	if count(out, `accepted: locked v4/[0-9a-f]{8} pending, effective .*\(in (59m5[0-9]s|1h0m0s)\)`) != 3 {
		t.Fatalf("push of a waiting update:\n%s", out)
	}
	out = mustTool(t, "status", "-cluster", cl)
	if count(out, `locked=v3/.* pending=locked:v4/`) != 3 {
		t.Fatalf("status with a pending update:\n%s", out)
	}
	file = writeFile(t, fc.path("b.conf"), lockedText(newKeys, 2, 3600, fee1, fee2, fee4))
	out = mustTool(t, "draft", "-cluster", cl, "-group", "locked", "-margin", "0s", "-out", fc.path("b.bin"), file)
	wantIn(t, out, "locked update version 5", "supersedes the pending locked version 4")
	out = mustTool(t, append([]string{"assemble", "-out", fc.path("b.signed"), fc.path("b.bin")}, fc.signAll(t, fc.path("b.bin"), 1, 3)...)...)
	out = mustTool(t, "push", "-cluster", cl, fc.path("b.signed"))
	if count(out, `accepted: locked v5/[0-9a-f]{8} pending`) != 3 {
		t.Fatalf("supersede:\n%s", out)
	}
	out = mustTool(t, "status", "-cluster", cl)
	if count(out, `locked=v3/.* pending=locked:v5/`) != 3 {
		t.Fatalf("status after the supersede:\n%s", out)
	}
	// The pending update was signed for version 4 and can come back no more.
	out, err = tool(t, "push", "-cluster", cl, aSigned)
	if err == nil || count(out, `refused: .*version 4, want above 5`) != 3 {
		t.Fatalf("superseded update again: %v\n%s", err, out)
	}

	// An open update: a fork far ahead is in force at once; one in the next
	// epochs breaks the fork rule and draft refuses it.
	epoch := uint64(time.Now().Unix()-genesisTime()) / (secondsPerSlot * slotsPerEpoch)
	near := writeFile(t, fc.path("near.conf"), openText(epoch+2))
	wantIn(t, failTool(t, "draft", "-cluster", cl, "-group", "open", "-margin", "0s", "-out", fc.path("near.bin"), near), "the fork rule refuses this update")
	_, oSigned := fc.update(t, "fork", "open", openText(epoch+100), "0s", 0, 1)
	out = mustTool(t, "push", "-cluster", cl, "-raise-min", oSigned)
	if count(out, `accepted: open v1/[0-9a-f]{8} in force`) != 3 || count(out, `min_open_version raised from 0 to 1`) != 3 {
		t.Fatalf("open update with -raise-min:\n%s", out)
	}
	if got := readAttestation(t, fc.path("s2/cloud.json"))["min_open_version"]; got != float64(1) {
		t.Fatalf("min_open_version %v", got)
	}
	out = mustTool(t, "push", "-cluster", cl, "-raise-min", fc.path("b.signed"))
	wantIn(t, out, "min_locked_version not raised: s1 does not have locked v5/")
	out = mustTool(t, "status", "-cluster", cl)
	if count(out, `open=v1/`) != 3 {
		t.Fatalf("status after the open update:\n%s", out)
	}
}

// pin refuses a runner whose IDENTITY shows another setup than the one
// built for it, and leaves its cloud.json as it was.
func TestPinMismatch(t *testing.T) {
	fc := newFakeCluster(t)
	other := newFakeCluster(t)
	// cluster.json names fc's setup of s1 for a runner of the other cluster.
	signers := []map[string]string{{"name": "s1", "cloud": filepath.Join(other.dir, "s1", "cloud.json"), "setup": filepath.Join(fc.dir, "setups", "s1.setup")}}
	cl := writeJSONFile(t, filepath.Join(t.TempDir(), "cluster.json"), map[string]any{"signers": signers})
	before, _ := os.ReadFile(filepath.Join(other.dir, "s1", "cloud.json"))
	out := failTool(t, "pin", "-cluster", cl)
	wantIn(t, out, "s1 not pinned: ", "the runner's setup_hash "+other.hashes["s1"]+" is not the pinned setup_sha256 "+fc.hashes["s1"])
	after, _ := os.ReadFile(filepath.Join(other.dir, "s1", "cloud.json"))
	if string(after) != string(before) {
		t.Fatal("pin changed the cloud.json of a runner it refused")
	}

	// A cloud.json that pins another setup already is left alone too.
	mustTool(t, "pin", "-cluster", other.cluster)
	wantIn(t, failTool(t, "pin", "-cluster", cl), "pins setup_sha256 "+other.hashes["s1"]+" already")
}

// show refuses a body with a byte added, shows a changed activate_at as
// another body hash (the approvers' signatures then do not fit), and
// refuses a prev_hash the active values do not give.
func TestShowTampered(t *testing.T) {
	fc := newFakeCluster(t)
	mustTool(t, "pin", "-cluster", fc.cluster)
	file := writeFile(t, fc.path("fees.conf"), lockedText(fc.keys[:3], 2, 0, fee1, fee2))
	body := fc.path("update.bin")
	drafted := bodyHash(t, mustTool(t, "draft", "-cluster", fc.cluster, "-group", "locked", "-out", body, file))
	sigs := fc.signAll(t, body, 0, 1)
	raw, err := os.ReadFile(body)
	if err != nil {
		t.Fatal(err)
	}
	active, _ := os.ReadFile(body + ".active")
	tamper := func(name string, change func([]byte) []byte) string {
		p := fc.path(name)
		if err := os.WriteFile(p, change(append([]byte(nil), raw...)), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p+".active", active, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// Offsets in the body: 'B' version cluster_id[32] chain_hash[32] group
	// config_version:u64 prev_hash[32] activate_at:u64.
	const prevAt, activateAt = 75, 107
	added := tamper("added.bin", func(b []byte) []byte { return append(b, 0) })
	wantIn(t, failTool(t, "show", added), "1 trailing bytes")
	later := tamper("later.bin", func(b []byte) []byte { b[activateAt+7] ^= 1; return b })
	out := mustTool(t, "show", later)
	if h := bodyHash(t, out); h == drafted {
		t.Fatal("a changed activate_at keeps the body hash")
	}
	wantIn(t, failTool(t, append([]string{"assemble", "-out", fc.path("later.signed"), later}, sigs...)...), "signs body "+drafted[:8]+", not this one")
	prev := tamper("prev.bin", func(b []byte) []byte { b[prevAt] ^= 1; return b })
	wantIn(t, failTool(t, "show", prev), "is not the active locked values")
	wantIn(t, failTool(t, "sign", "-key", fc.keys[0].file, fc.path("nothing.bin")), "no such file")
	if err := os.WriteFile(fc.path("setup-as-body.bin"), mustRead(t, filepath.Join(fc.dir, "setups", "s1.setup")), 0o644); err != nil {
		t.Fatal(err)
	}
	wantIn(t, failTool(t, "sign", "-key", fc.keys[0].file, fc.path("setup-as-body.bin")), "not a config update body")
}

// setup refuses a file without sections, with a cluster_id, and with
// signers that start from different config groups, and keeps the file's
// line numbers in its errors.
func TestSetupFileRules(t *testing.T) {
	dir := t.TempDir()
	keys := approvers(t, dir, 3)
	ca := caDER(t)
	good := setupText(dir, ca, genesisTime(), lockedText(keys, 2, 0, fee1), "a", "b")
	cases := []struct{ name, text, want string }{
		{"no sections", strings.Split(good, "\n[signer")[0], "no [signer NAME] section"},
		{"cluster_id", "cluster_id = 0x01\n" + good, "line 1: cluster_id: signer-admin setup draws it"},
		{"signer_name", good + "signer_name = x\n", "signer_name: the [signer NAME] header gives it"},
		{"different groups", good + "allowed_fee_recipients = " + fee2 + "\n", "signers a and b start from different locked groups"},
		{"twice", good + "\n[signer a]\nmark_store.dir = /x\n", "signer a has a second section"},
		{"bad value", strings.Replace(good, "max_keys = 16", "max_keys = lots", 1), ":17: max_keys:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := writeFile(t, filepath.Join(t.TempDir(), "setup.conf"), tc.text)
			wantIn(t, failTool(t, "setup", "-out", filepath.Join(t.TempDir(), "out"), p), tc.want)
		})
	}
	p := writeFile(t, filepath.Join(dir, "setup.conf"), good)
	mustTool(t, "setup", "-out", filepath.Join(dir, "out"), p)
	wantIn(t, failTool(t, "setup", "-out", filepath.Join(dir, "out"), p), "exists; remove the old setups first")
}
