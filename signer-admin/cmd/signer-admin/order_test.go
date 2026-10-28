package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/dkgorder"
	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// DKG orders against real key generation runners of the cloud repo on the
// dev platform: dkg-draft reads each signer's operator key over its
// attested connection, show, sign, assemble and push take the order as they
// take an update, the runners hold it pending for the setups' time lock,
// status shows it, then it is active. Refusals: too few signatures (the
// tool and the runner), a charon order without ENRs.
//
// SIGNER_ADMIN_DKG_RUNNER names the runner: runner-dev-dkg-dev of the
// cloud repo (scripts/build-runner.sh), with DKG orders. Without it the test
// is skipped.
func TestOrderFlowDevRunners(t *testing.T) {
	bin := os.Getenv("SIGNER_ADMIN_DKG_RUNNER")
	if bin == "" {
		t.Skip("SIGNER_ADMIN_DKG_RUNNER is not set (runner-dev-dkg-dev of the cloud repo)")
	}
	dir := t.TempDir()
	ca, cert, key := clientPKI(t, dir)
	keys := approvers(t, dir, 3)
	const lock = 2
	conf := writeFile(t, filepath.Join(dir, "setup.conf"), setupText(dir, ca, genesisTime(), lockedText(keys, 2, lock, fee1), names...))
	setupHashes(mustTool(t, "setup", "-out", filepath.Join(dir, "setups"), conf))
	var signers []map[string]string
	for _, n := range names {
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

	body := filepath.Join(dir, "order.bin")
	out := step("dkg-draft", "dkg-draft", "-cluster", cl, "-path", "dirk", "-label", "dirk-lanes", "-not-after", "30d", "-out", body)
	wantIn(t, out, `dkg order "dirk-lanes", path dirk, 2 of 3`, "participant 1 s1", "participant 3 s3", "a dev signer: the time lock")
	if count(out, `^  participant [123] s[123]: setup [0-9a-f]{8}, operator key [0-9a-f]{8}, dev$`) != 3 {
		t.Fatalf("dkg-draft:\n%s", out)
	}
	out = step("show", "show", body)
	wantIn(t, out, "path = dirk", "participant_2.verifier = dev", "images: every participant's image", fmt.Sprintf("wait: %d s", lock))
	var sigs []string
	for _, i := range []int{0, 2} {
		mustTool(t, "sign", "-key", keys[i].file, body)
		sigs = append(sigs, fmt.Sprintf("%s.%s.sig", body, keys[i].pub[2:10]))
	}
	wantIn(t, string(mustRead(t, sigs[0])), "over signer-dkg-order-v1")
	out = failTool(t, "assemble", "-out", filepath.Join(dir, "one.signed"), body, sigs[0])
	wantIn(t, out, "1 of the approvers in force signed, approvals_needed is 2")
	signed := filepath.Join(dir, "order.signed")
	step("assemble", "assemble", "-out", signed, body, sigs[0], sigs[1])
	out = step("show signed", "show", "-active", body+".active", signed)
	wantIn(t, out, "signatures: complete and valid against the approver set")

	// One approver's order, made by hand: the runners refuse it.
	b, _, _, err := readOrder(body)
	if err != nil {
		t.Fatal(err)
	}
	enc, _ := b.Encode()
	seed, _ := hex.DecodeString(strings.TrimSpace(string(mustRead(t, keys[1].file))))
	lone := &dkgorder.Order{Body: *b, Approvals: []setupwire.Approval{{Position: 1, Signature: dkgorder.SignBody(ed25519.NewKeyFromSeed(seed), enc)}}}
	loneRaw, err := lone.Encode()
	if err != nil {
		t.Fatal(err)
	}
	out, err = tool(t, "push", "-cluster", cl, writeFile(t, filepath.Join(dir, "lone.signed"), string(loneRaw)))
	if err == nil || count(out, `^s[123] refused: .*1 approver signatures, approvals_needed is 2`) != 3 {
		t.Fatalf("one signature: %v\n%s", err, out)
	}

	out = step("push", "push", "-cluster", cl, signed)
	if count(out, `^s[123] accepted: dkg order [0-9a-f]{8} pending as participant [123], `) != 3 {
		t.Fatalf("push:\n%s", out)
	}
	out = step("status", "status", "-cluster", cl)
	if count(out, `^s[123] .* order=dkg:[0-9a-f]{8}@`) != 3 {
		t.Fatalf("status shows no pending order:\n%s", out)
	}
	time.Sleep((lock + 1) * time.Second)
	out = step("push again", "push", "-cluster", cl, signed)
	if count(out, `^s[123] known: dkg order [0-9a-f]{8} active as participant [123], `) != 3 {
		t.Fatalf("push again after the time lock:\n%s", out)
	}

	// The charon path needs one ENR per signer.
	out = failTool(t, "dkg-draft", "-cluster", cl, "-path", "charon", "-out", filepath.Join(dir, "charon.bin"))
	wantIn(t, out, "-enrs is required")
	enrs := writeFile(t, filepath.Join(dir, "enrs.txt"), "enr:-node-1\n# node 2\nenr:-node-2\nenr:-node-3\n")
	out = step("dkg-draft charon", "dkg-draft", "-cluster", cl, "-path", "charon", "-enrs", enrs, "-out", filepath.Join(dir, "charon.bin"))
	wantIn(t, out, `path charon, 2 of 3`)
	out = step("show charon", "show", filepath.Join(dir, "charon.bin"))
	wantIn(t, out, "charon_enrs = enr:-node-2")
}
