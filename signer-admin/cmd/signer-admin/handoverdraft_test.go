package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/handoverorder"
	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// show, sign and assemble take a handover order offline: the human form
// names source and target, the signature files
// are over signer-handover-order-v1, assemble wants k approvers in force,
// and the active file must be the source's.
func TestHandoverOrderOffline(t *testing.T) {
	dir := t.TempDir()
	ca, _, _ := clientPKI(t, dir)
	keys := approvers(t, dir, 3)
	conf := writeFile(t, filepath.Join(dir, "setup.conf"), setupText(dir, ca, genesisTime(), lockedText(keys, 2, 2, fee1), names...))
	hashes := setupHashes(mustTool(t, "setup", "-out", filepath.Join(dir, "setups"), conf))
	raw := mustRead(t, filepath.Join(dir, "setups", "s1.setup"))
	s, err := setupwire.DecodeSetup(raw)
	if err != nil {
		t.Fatal(err)
	}
	sh, err := setupwire.SetupHash(raw)
	if err != nil {
		t.Fatal(err)
	}
	var target [32]byte
	rand.Read(target[:])
	b := &handoverorder.Body{ClusterID: s.ClusterID, ChainHash: s.Chain.Hash(), NotAfter: uint64(time.Now().Unix()) + 12*3600,
		Source: handoverorder.Runner{Name: "s1", SetupHash: sh, Verifier: handoverorder.VerifierDev},
		Target: handoverorder.Runner{Name: "s1b", SetupHash: target, Verifier: handoverorder.VerifierDev}}
	enc, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}
	body := writeFile(t, filepath.Join(dir, "handover.bin"), string(enc))
	writeJSONFile(t, body+".active", activeFile{Setup: hex.EncodeToString(raw)})

	out := mustTool(t, "show", body)
	wantIn(t, out, "source.name = s1", "source.setup_sha256 = 0x"+hashes["s1"], "target.name = s1b", "target.verifier = dev",
		"order_sha256 "+fullHex(handoverorder.Hash(enc)), "image: the target's image is on the allowed list", "wait: 2 s",
		"WARNING target: the active file has no target setup")
	var sigs []string
	for _, i := range []int{0, 2} {
		out := mustTool(t, "sign", "-key", keys[i].file, body)
		wantIn(t, out, "signed handover order s1 to s1b", fmt.Sprintf("the key is approver %d in force", i))
		sigs = append(sigs, fmt.Sprintf("%s.%s.sig", body, keys[i].pub[2:10]))
	}
	wantIn(t, string(mustRead(t, sigs[0])), "over signer-handover-order-v1")
	out = failTool(t, "assemble", "-out", filepath.Join(dir, "one.signed"), body, sigs[0])
	wantIn(t, out, "1 of the approvers in force signed, approvals_needed is 2")
	signed := filepath.Join(dir, "handover.signed")
	out = mustTool(t, "assemble", "-out", signed, body, sigs[0], sigs[1])
	wantIn(t, out, "approvers 0,2 of 3 (k 2)")
	out = mustTool(t, "show", "-active", body+".active", signed)
	wantIn(t, out, "signatures: complete and valid against the approver set", "approver_signature position 2")
	out = failTool(t, "sign", "-key", keys[1].file, signed)
	wantIn(t, out, "signed already")
	// Another order kind's signature is not a handover order's.
	otherSig := writeFile(t, filepath.Join(dir, "other.sig"), string((&sigFile{bodyHash: handoverorder.Hash(enc), key: [32]byte(mustKey(t, keys[1].pub)),
		sig: setupwire.SignApproval(readKeyT(t, keys[1].file), setupwire.CtxImportOrder, false, enc)}).format()))
	out = failTool(t, "assemble", "-out", filepath.Join(dir, "x.signed"), body, sigs[0], otherSig)
	wantIn(t, out, "does not verify")
	// The active values of another signer are not the order's source.
	writeJSONFile(t, filepath.Join(dir, "s2.active"), activeFile{Setup: hex.EncodeToString(mustRead(t, filepath.Join(dir, "setups", "s2.setup")))})
	out = failTool(t, "show", "-active", filepath.Join(dir, "s2.active"), body)
	wantIn(t, out, "not of this order's source")
}

func mustKey(t *testing.T, pub string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(pub, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func readKeyT(t *testing.T, path string) []byte {
	t.Helper()
	k, err := readKey(path)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// The whole approval track against a release runner with a handover
// source side on the dev platform: handover-draft reads the
// source's attested state and the target's cloud.json, the approvers sign,
// push sends the order to the source only, the source holds it pending for
// the time lock, then active. A draft whose not_after comes before the
// source would act is refused, and so is a target image off the list.
//
// SIGNER_ADMIN_HANDOVER_RUNNER names a runner-dev (a dev release build), which serves
// HANDOVER_ORDER as a source (runner/server/handover_source.go). This
// module does not build runners, so the test is skipped without it.
func TestHandoverFlowDevRunner(t *testing.T) {
	bin := os.Getenv("SIGNER_ADMIN_HANDOVER_RUNNER")
	if bin == "" {
		t.Skip("SIGNER_ADMIN_HANDOVER_RUNNER is not set (a dev release runner, runner-dev)")
	}
	dir := t.TempDir()
	ca, cert, key := clientPKI(t, dir)
	keys := approvers(t, dir, 3)
	const lock = 2
	conf := writeFile(t, filepath.Join(dir, "setup.conf"), setupText(dir, ca, genesisTime(), lockedText(keys, 2, lock, fee1), names[:2]...))
	mustTool(t, "setup", "-out", filepath.Join(dir, "setups"), conf)
	var signers []map[string]string
	for _, n := range names[:2] {
		addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
		logPath := writeFile(t, filepath.Join(dir, n, "runner.log"), "")
		f, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(bin, "-platform", "dev", "-state-dir", filepath.Join(dir, n, "state"), "-listen", "tcp:"+addr,
			"-setup", "file:"+filepath.Join(dir, "setups", n+".setup"))
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
		writeJSONFile(t, filepath.Join(dir, n, "cloud.json"), map[string]any{
			"address": "tcp:" + addr, "client_cert": cert, "client_key": key, "attestation": map[string]any{"verifier": "dev"},
		})
		signers = append(signers, map[string]string{"name": n, "cloud": n + "/cloud.json", "setup": "setups/" + n + ".setup"})
	}
	cl := writeJSONFile(t, filepath.Join(dir, "cluster.json"), map[string]any{"signers": signers})
	step := func(what string, args ...string) string {
		t.Helper()
		out := mustTool(t, args...)
		t.Logf("%s: signer-admin %s\n%s", what, args[0], out)
		return out
	}
	step("pin", "pin", "-cluster", cl)

	// The target's setup (handover-setup) and its cloud.json, as the
	// target's build pins it: a runner this test never connects to.
	tconf := writeFile(t, filepath.Join(dir, "targets.conf"), fmt.Sprintf("platform = dev\nallowed_client_ca = %s\n[signer s1]\nslashing_log_store.dir = %s\n",
		base64.StdEncoding.EncodeToString(ca), filepath.Join(dir, "s1b", "marks")))
	tsetup := filepath.Join(dir, "targets", "s1.setup")
	thex := setupHashes(step("handover-setup", "handover-setup", "-cluster", cl, "-signers", "s1", "-out", filepath.Join(dir, "targets"), tconf))["s1"]
	th := [32]byte(mustKey(t, thex))
	tcloud := writeJSONFile(t, filepath.Join(dir, "s1b", "cloud.json"), map[string]any{
		"address": "tcp:127.0.0.1:1", "client_cert": cert, "client_key": key, "identity_version": 3,
		"attestation": map[string]any{"verifier": "dev", "setup_sha256": thex},
	})
	out := failTool(t, "handover-draft", "-cluster", cl, "-signer", "s1", "-target-cloud", tcloud, "-target-setup", tsetup, "-not-after", "1s",
		"-out", filepath.Join(dir, "short.bin"))
	wantIn(t, out, "before the source would act")
	other := writeJSONFile(t, filepath.Join(dir, "s1x", "cloud.json"), map[string]any{
		"address": "tcp:127.0.0.1:1", "client_cert": cert, "client_key": key,
		"attestation": map[string]any{"verifier": "dev", "setup_sha256": strings.Repeat("ab", 32)},
	})
	out = failTool(t, "handover-draft", "-cluster", cl, "-signer", "s1", "-target-cloud", other, "-target-setup", tsetup)
	wantIn(t, out, "is not the setup_sha256")

	body := filepath.Join(dir, "handover.bin")
	out = step("handover-draft", "handover-draft", "-cluster", cl, "-signer", "s1", "-target-cloud", tcloud, "-target-setup", tsetup, "-out", body)
	wantIn(t, out, "handover order: s1 (setup ", "to s1b (setup "+hex.EncodeToString(th[:4])+", dev)", "a dev signer: the time lock")
	b, _, _, err := readHandover(body)
	if err != nil {
		t.Fatal(err)
	}
	if b.NotAfter < uint64(time.Now().Unix())+12*3600-60 {
		t.Fatalf("not_after %d is not 12 hours out", b.NotAfter)
	}
	wantIn(t, step("show", "show", body), "target: the source accepts the target's public values")
	var sigs []string
	for _, i := range []int{1, 2} {
		mustTool(t, "sign", "-key", keys[i].file, body)
		sigs = append(sigs, fmt.Sprintf("%s.%s.sig", body, keys[i].pub[2:10]))
	}
	signed := filepath.Join(dir, "handover.signed")
	step("assemble", "assemble", "-out", signed, body, sigs[0], sigs[1])

	out = step("push", "push", "-cluster", cl, signed)
	if count(out, `^s1 accepted: handover order [0-9a-f]{8} pending, to s1b \(setup [0-9a-f]{8}\), `) != 1 ||
		count(out, `^s2 not sent: the order's source is setup `) != 1 {
		t.Fatalf("push:\n%s", out)
	}
	out = step("status", "status", "-cluster", cl)
	if count(out, `^s1 .* order=handover:[0-9a-f]{8}@`) != 1 {
		t.Fatalf("status shows no pending handover order:\n%s", out)
	}
	time.Sleep((lock + 1) * time.Second)
	out = step("push again", "push", "-cluster", cl, signed)
	if count(out, `^s1 known: handover order [0-9a-f]{8} active, `) != 1 {
		t.Fatalf("push again after the time lock:\n%s", out)
	}
	// A second order while this one is pending: the runner refuses it.
	body2 := filepath.Join(dir, "handover2.bin")
	step("second draft", "handover-draft", "-cluster", cl, "-signer", "s1", "-target-cloud", tcloud, "-target-setup", tsetup, "-not-after", "13h", "-out", body2)
	for _, i := range []int{0, 1} {
		mustTool(t, "sign", "-key", keys[i].file, body2)
	}
	signed2 := filepath.Join(dir, "handover2.signed")
	mustTool(t, "assemble", "-out", signed2, body2, fmt.Sprintf("%s.%s.sig", body2, keys[0].pub[2:10]), fmt.Sprintf("%s.%s.sig", body2, keys[1].pub[2:10]))
	out, err = tool(t, "push", "-cluster", cl, signed2)
	if err == nil || count(out, `^s1 refused: .*one order at a time`) != 1 {
		t.Fatalf("a second order: %v\n%s", err, out)
	}
	// The target's image must be on the source's list: a nitro target is
	// not on the dev setup's.
	ncloud := writeJSONFile(t, filepath.Join(dir, "s1c", "cloud.json"), map[string]any{
		"address": "tcp:127.0.0.1:1", "client_cert": cert, "client_key": key,
		"attestation": map[string]any{"verifier": "aws-nitro", "setup_sha256": hex.EncodeToString(th[:]),
			"nitro_pcrs": map[string]string{"0": strings.Repeat("11", 48), "1": strings.Repeat("12", 48), "2": strings.Repeat("13", 48),
				"3": strings.Repeat("33", 48)}},
	})
	out = failTool(t, "handover-draft", "-cluster", cl, "-signer", "s1", "-target-cloud", ncloud, "-target-setup", tsetup, "-out", filepath.Join(dir, "n.bin"))
	wantIn(t, out, "not on the allowed-images list")
}
