package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// The track against real runners of this repo on the dev platform:
// three runners started with the setups signer-admin builds, then pin,
// draft, sign, assemble, push and status, a rotation, a time lock with a
// supersede that comes into force, an open update, and the refusals of
// the runner itself (too few signatures, a stale prev_hash, the fork rule)
// next to the tool's (another cluster, a pin mismatch).
//
// SIGNER_ADMIN_RUNNER names the runner binary: a build with the dev
// platform (go build -tags platform_dev in this repo's tee-signer/, or its
// runner-dev-debugimport) at cloud commit 26a6df5 or later.
// scripts/cloud-integration.sh sets it; without it the test is skipped.
func TestFlowDevRunners(t *testing.T) {
	bin := os.Getenv("SIGNER_ADMIN_RUNNER")
	if bin == "" {
		t.Skip("SIGNER_ADMIN_RUNNER is not set (a dev runner binary of this repo)")
	}
	dir := t.TempDir()
	ca, cert, key := clientPKI(t, dir)
	keys := approvers(t, dir, 4)
	genesis := genesisTime()

	// Two clusters: ours, and one more runner of another cluster for the
	// pin mismatch and the update of another cluster.
	conf := writeFile(t, filepath.Join(dir, "setup.conf"), setupText(dir, ca, genesis, lockedText(keys[:3], 2, 0, fee1), names...))
	hashes := setupHashes(mustTool(t, "setup", "-out", filepath.Join(dir, "setups"), conf))
	otherConf := writeFile(t, filepath.Join(dir, "other.conf"), setupText(dir, ca, genesis, lockedText(keys[:3], 2, 0, fee1), "x1"))
	otherHashes := setupHashes(mustTool(t, "setup", "-out", filepath.Join(dir, "other-setups"), otherConf))

	var signers []map[string]string
	start := func(name, setupFile string) string {
		addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
		logPath := filepath.Join(dir, name, "runner.log")
		writeFile(t, logPath, "")
		f, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(bin, "-platform", "dev", "-state-dir", filepath.Join(dir, name, "state"), "-listen", "tcp:"+addr,
			"-setup", "file:"+setupFile)
		cmd.Stdout, cmd.Stderr = f, f
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			cmd.Process.Kill()
			cmd.Wait()
			f.Close()
			if t.Failed() {
				t.Logf("---- %s ----\n%s", logPath, mustRead(t, logPath))
			}
		})
		waitTCP(t, addr)
		return writeJSONFile(t, filepath.Join(dir, name, "cloud.json"), map[string]any{
			"address": "tcp:" + addr, "client_cert": cert, "client_key": key, "accounts": "accounts.json", "slots_per_epoch": slotsPerEpoch,
			"attestation": map[string]any{"verifier": "dev"},
		})
	}
	for _, n := range names {
		start(n, filepath.Join(dir, "setups", n+".setup"))
		signers = append(signers, map[string]string{"name": n, "cloud": n + "/cloud.json", "setup": "setups/" + n + ".setup"})
	}
	cl := writeJSONFile(t, filepath.Join(dir, "cluster.json"), map[string]any{"signers": signers})
	xCloud := start("x1", filepath.Join(dir, "other-setups", "x1.setup"))
	step := func(what string, args ...string) string {
		t.Helper()
		out := mustTool(t, args...)
		t.Logf("%s: signer-admin %s\n%s", what, args[0], out)
		return out
	}

	// pin: the runner of the other cluster under our setup's name is refused.
	mixed := writeJSONFile(t, filepath.Join(dir, "mixed.json"), map[string]any{"signers": []map[string]string{
		{"name": "s1", "cloud": xCloud, "setup": filepath.Join(dir, "setups", "s1.setup")}}})
	out := failTool(t, "pin", "-cluster", mixed)
	wantIn(t, out, "the runner's setup_hash "+otherHashes["x1"]+" is not the pinned setup_sha256 "+hashes["s1"])
	out = step("pin", "pin", "-cluster", cl)
	if count(out, `^s[123] pinned: `) != 3 {
		t.Fatalf("pin:\n%s", out)
	}
	out = step("status", "status", "-cluster", cl)
	if count(out, `^s[123] setup=[0-9a-f]{8} locked=v0/[0-9a-f]{8} open=v0/[0-9a-f]{8} approvers=[0-9a-f]{8} clock=`) != 3 {
		t.Fatalf("status:\n%s", out)
	}

	// A locked update, in force at once (time lock 0, margin 0).
	run1 := func(name, group, text, margin string, idx ...int) string {
		t.Helper()
		file := writeFile(t, filepath.Join(dir, name+".conf"), text)
		body := filepath.Join(dir, name+".bin")
		step("draft "+name, "draft", "-cluster", cl, "-group", group, "-margin", margin, "-out", body, file)
		step("show "+name, "show", body)
		var sigs []string
		for _, i := range idx {
			mustTool(t, "sign", "-key", keys[i].file, body)
			sigs = append(sigs, fmt.Sprintf("%s.%s.sig", body, keys[i].pub[2:10]))
		}
		signed := filepath.Join(dir, name+".signed")
		step("assemble "+name, append([]string{"assemble", "-out", signed, body}, sigs...)...)
		return signed
	}
	fees := run1("fees", "locked", lockedText(keys[:3], 2, 0, fee1, fee2), "0s", 0, 2)
	out = step("push", "push", "-cluster", cl, fees)
	if count(out, `^s[123] accepted: locked v1/[0-9a-f]{8} in force$`) != 3 {
		t.Fatalf("push:\n%s", out)
	}
	out = step("push again", "push", "-cluster", cl, fees)
	if count(out, `^s[123] known: locked v1/`) != 3 {
		t.Fatalf("push again:\n%s", out)
	}

	// The runners' own refusals.
	setupS1 := filepath.Join(dir, "setups", "s1.setup")
	stale := craft(t, craftSpec{setup: setupS1, group: setupwire.GroupLocked, version: 2, set: keys[:3], signers: []int{0, 1}})
	out, err := tool(t, "push", "-cluster", cl, stale)
	if err == nil || count(out, `^s[123] refused: .*prev_hash [0-9a-f]+ is not the locked update in force \(version 1`) != 3 {
		t.Fatalf("stale prev_hash: %v\n%s", err, out)
	}
	h1 := mustUpdateHash(t, updateBody(t, fees))
	one := craft(t, craftSpec{setup: setupS1, group: setupwire.GroupLocked, version: 2, prev: h1, set: keys[:3], signers: []int{1}})
	out, err = tool(t, "push", "-cluster", cl, one)
	if err == nil || count(out, `^s[123] refused: .*1 approver signatures, approvals_needed is 2`) != 3 {
		t.Fatalf("one signature: %v\n%s", err, out)
	}
	wrong := craft(t, craftSpec{setup: filepath.Join(dir, "other-setups", "x1.setup"), group: setupwire.GroupLocked, version: 2, prev: h1,
		set: keys[:3], signers: []int{0, 1}})
	out, err = tool(t, "push", "-cluster", cl, wrong)
	if err == nil || count(out, `^s[123] refused: not sent: update: for another cluster_id`) != 3 {
		t.Fatalf("another cluster: %v\n%s", err, out)
	}

	// Rotation: approver 3 leaves, approver 4 joins.
	newKeys := []approver{keys[0], keys[1], keys[3]}
	rot := run1("rotation", "locked", lockedText(newKeys, 2, 0, fee1, fee2), "0s", 0, 1, 3)
	out = step("push rotation", "push", "-cluster", cl, rot)
	if count(out, `accepted: locked v2/[0-9a-f]{8} in force`) != 3 {
		t.Fatalf("rotation:\n%s", out)
	}
	set := setupwire.ApproverSet{ApprovalsNeeded: 2}
	for _, a := range newKeys {
		b, _ := hex.DecodeString(a.pub[2:])
		set.Keys = append(set.Keys, [32]byte(b))
	}
	sh := set.Hash()
	if out = step("status", "status", "-cluster", cl); count(out, "approvers="+hex.EncodeToString(sh[:4])) != 3 {
		t.Fatalf("status after the rotation:\n%s", out)
	}

	// A time lock of 8 s (in force at once), an update that waits for it,
	// and one that supersedes it and comes into force after its own wait.
	lock := run1("lock", "locked", lockedText(newKeys, 2, 8, fee1, fee2), "0s", 0, 3)
	step("push lock", "push", "-cluster", cl, lock)
	a := run1("a", "locked", lockedText(newKeys, 2, 8, fee1, fee2, fee3), "0s", 0, 1)
	out = step("push a", "push", "-cluster", cl, a)
	if count(out, `accepted: locked v4/[0-9a-f]{8} pending`) != 3 {
		t.Fatalf("waiting update:\n%s", out)
	}
	b := run1("b", "locked", lockedText(newKeys, 2, 8, fee1, fee2, fee4), "0s", 1, 3)
	out = step("push b", "push", "-cluster", cl, b)
	if count(out, `accepted: locked v5/[0-9a-f]{8} pending`) != 3 {
		t.Fatalf("supersede:\n%s", out)
	}
	if out = step("status", "status", "-cluster", cl); count(out, `locked=v3/.* pending=locked:v5/`) != 3 {
		t.Fatalf("status with the superseding update pending:\n%s", out)
	}
	if out, err = tool(t, "push", "-cluster", cl, a); err == nil || count(out, `refused: .*version 4, want above 5`) != 3 {
		t.Fatalf("superseded update again: %v\n%s", err, out)
	}
	hb := mustUpdateHash(t, updateBody(t, b))
	deadline := time.Now().Add(20 * time.Second)
	for {
		out, err = tool(t, "status", "-cluster", cl)
		if err == nil && count(out, `locked=v5/`+hex.EncodeToString(hb[:4])+` open=v0/`) == 3 && count(out, `pending=`) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the superseding update did not come into force: %v\n%s", err, out)
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Logf("status after the wait:\n%s", out)

	// Open: a fork in the next epochs is refused by draft and, sent anyway,
	// by the runners' fork rule; one far ahead is in force at once.
	epoch := uint64(time.Now().Unix()-genesis) / (secondsPerSlot * slotsPerEpoch)
	near := writeFile(t, filepath.Join(dir, "near.conf"), openText(epoch+2))
	wantIn(t, failTool(t, "draft", "-cluster", cl, "-group", "open", "-margin", "0s", "-out", filepath.Join(dir, "near.bin"), near),
		"the fork rule refuses this update")
	nearOpen, err := setupwire.ParseOpen("near", mustRead(t, near))
	if err != nil {
		t.Fatal(err)
	}
	forced := craft(t, craftSpec{setup: setupS1, group: setupwire.GroupOpen, version: 1, open: nearOpen, set: newKeys, signers: []int{0, 1}})
	if out, err = tool(t, "push", "-cluster", cl, forced); err == nil || count(out, `^s[123] refused: .*fork rule`) != 3 {
		t.Fatalf("near fork sent anyway: %v\n%s", err, out)
	}
	fork := run1("fork", "open", openText(epoch+100), "0s", 0, 1)
	out = step("push fork", "push", "-cluster", cl, "-raise-min", fork)
	if count(out, `accepted: open v1/[0-9a-f]{8} in force`) != 3 || count(out, `min_open_version raised from 0 to 1`) != 3 {
		t.Fatalf("open update:\n%s", out)
	}
	if out = step("status", "status", "-cluster", cl); count(out, `locked=v5/.* open=v1/`) != 3 {
		t.Fatalf("final status:\n%s", out)
	}
}

// mustUpdateHash is the hash of an encoded update body.
func mustUpdateHash(t *testing.T, body []byte) [32]byte {
	t.Helper()
	h, err := setupwire.UpdateHash(body)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// updateBody is the body of a signed update file.
func updateBody(t *testing.T, path string) []byte {
	t.Helper()
	u, err := setupwire.DecodeUpdate(mustRead(t, path))
	if err != nil {
		t.Fatal(err)
	}
	b, err := u.Body.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// waitTCP waits until addr takes connections: the runner serves only after
// its setup check and its first mark record.
func waitTCP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no runner at %s: %v", addr, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
