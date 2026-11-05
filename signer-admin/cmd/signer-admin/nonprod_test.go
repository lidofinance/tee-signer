package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/lidofinance/tee-signer/governance/runnerchain"
	"github.com/lidofinance/tee-signer/signer-admin/fakerunner"
)

// allowChain sets allow_chain_build to c in the cloud.json of each name.
func (fc *fakeCluster) allowChain(t *testing.T, c runnerchain.Chain, names ...string) {
	t.Helper()
	for _, n := range names {
		p := fc.path(n + "/cloud.json")
		var m map[string]any
		if err := json.Unmarshal(mustRead(t, p), &m); err != nil {
			t.Fatal(err)
		}
		m["allow_chain_build"] = string(c)
		writeJSONFile(t, p, m)
	}
}

// Non-prod runners (governance/runnerchain): signer-admin refuses them
// until cloud.json sets allow_chain_build to their chain; then status names
// the build, and draft and order waits follow the short times. An image
// gained waits the non-prod images minimum, 7 minutes, and the runner takes
// the update with that wait. Offline views name both builds' waits. A
// cluster of two builds is refused.
func TestNonProdFakeRunners(t *testing.T) {
	fc := newFakeClusterAs(t, runnerchain.Hoodi, 60)
	cl := fc.cluster

	out := failTool(t, "status", "-cluster", cl)
	if count(out, `^s[123] error: .*the runner is a hoodi build .*allow_chain_build to "hoodi"`) != 3 {
		t.Fatalf("status without allow_chain_build:\n%s", out)
	}
	fc.allowChain(t, runnerchain.Devnet, names...)
	out = failTool(t, "status", "-cluster", cl)
	if count(out, `^s[123] error: .*the runner is a hoodi build`) != 3 {
		t.Fatalf("status with allow_chain_build devnet:\n%s", out)
	}
	fc.allowChain(t, runnerchain.Hoodi, names...)
	mustTool(t, "pin", "-cluster", cl)
	out = mustTool(t, "status", "-cluster", cl)
	if count(out, `^s[123] setup=.* build=hoodi$`) != 3 {
		t.Fatalf("status:\n%s", out)
	}

	// A margin past the non-prod activation horizon (30 minutes).
	images := lockedText(fc.keys[:3], 2, 60, fee1) + "allowed_image_measurements = azure 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
	file := writeFile(t, fc.path("images.conf"), images)
	wantIn(t, failTool(t, "draft", "-cluster", cl, "-group", "locked", "-margin", "31m", "-out", fc.path("x.bin"), file),
		"the activation horizon of a hoodi build")
	// A time lock above the non-prod cap (30 minutes).
	wantIn(t, failTool(t, "draft", "-cluster", cl, "-group", "locked", "-margin", "0s", "-out", fc.path("x.bin"),
		writeFile(t, fc.path("long.conf"), lockedText(fc.keys[:3], 2, 3600, fee1))), "at most 1800 in a non-prod build")

	// The image: the non-prod images minimum, not the time lock of 60 s.
	body := fc.path("images.bin")
	out = mustTool(t, "draft", "-cluster", cl, "-group", "locked", "-margin", "0s", "-out", body, file)
	wantIn(t, out, "wait 7m0s (hoodi build)", "+ allowed_image_measurements = azure")
	// show sees no runner, so it names both builds' waits.
	out = mustTool(t, "show", body)
	wantIn(t, out, "wait: at least 604800 s after arrival", "; 420 s on signers of a non-prod build (hoodi, devnet, ci-test)")
	signed := fc.path("images.signed")
	mustTool(t, append([]string{"assemble", "-out", signed, body}, fc.signAll(t, body, 0, 1)...)...)
	out = mustTool(t, "push", "-cluster", cl, signed)
	if count(out, `^s[123] accepted: locked v1/[0-9a-f]{8} pending, effective \S+ \(in (6m5[0-9]s|7m0s)\)$`) != 3 {
		t.Fatalf("push:\n%s", out)
	}

	// One mainnet runner among hoodi ones: status flags it, draft refuses.
	raw, err := os.ReadFile(fc.path("setups/s3.setup"))
	if err != nil {
		t.Fatal(err)
	}
	r := fakerunner.StartSetup(t, raw)
	cert, key := r.ClientFiles(t, t.TempDir())
	writeJSONFile(t, filepath.Join(fc.dir, "s3", "cloud.json"), map[string]any{
		"address": r.Addr(), "client_cert": cert, "client_key": key, "allow_chain_build": "hoodi",
		"attestation": map[string]any{"verifier": "dev", "setup_sha256": fc.hashes["s3"]},
	})
	out = failTool(t, "status", "-cluster", cl)
	wantIn(t, out, "build=mainnet DIFFERS:")
	wantIn(t, failTool(t, "draft", "-cluster", cl, "-group", "locked", "-margin", "0s", "-out", fc.path("y.bin"), file),
		"draft for signers of one build")
}

// setup -build hoodi, devnet or ci-test refuses a time lock above the
// non-prod cap, which such a runner would refuse at start; the mainnet
// build takes it. Each file is on the build's own chain (the mainnet build
// takes the test chain on the dev platform).
func TestSetupBuildChain(t *testing.T) {
	dir := t.TempDir()
	keys := approvers(t, dir, 3)
	ca := caDER(t)
	limit := int(runnerchain.Devnet.Limits().MaxTimeLock)
	file := func(build string, timeLock int) string {
		text := setupText(dir, ca, genesisTime(), lockedText(keys, 2, timeLock, fee1), "a", "b")
		switch build {
		case "hoodi":
			text = withChain(t, text, hoodiFork, hoodiRoot)
		case "devnet":
			text = withChain(t, text, devnetFork, testChainRoot)
		case "ci-test":
			text = withChain(t, text, ciTestFork, ciTestRoot)
		}
		return writeFile(t, filepath.Join(t.TempDir(), "setup.conf"), text)
	}
	for _, c := range []string{"hoodi", "devnet", "ci-test"} {
		wantIn(t, failTool(t, "setup", "-build", c, "-out", filepath.Join(t.TempDir(), "out"), file(c, limit+1)),
			fmt.Sprintf("signer a: locked: change_delay_seconds %d, at most %d in a non-prod build", limit+1, limit))
		mustTool(t, "setup", "-build", c, "-out", filepath.Join(t.TempDir(), "out"), file(c, limit))
	}
	// No -build is mainnet.
	over := file("mainnet", limit+1)
	mustTool(t, "setup", "-out", filepath.Join(t.TempDir(), "out"), over)
	mustTool(t, "setup", "-build", "mainnet", "-out", filepath.Join(t.TempDir(), "out"), over)
	for _, bad := range []string{"testnet", "default", "citest"} {
		wantIn(t, failTool(t, "setup", "-build", bad, "-out", filepath.Join(t.TempDir(), "out"), over), "want one of mainnet, hoodi, devnet, ci-test")
	}
}
