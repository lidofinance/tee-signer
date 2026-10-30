package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/lidofinance/tee-signer/governance/flavor"
	"github.com/lidofinance/tee-signer/signer-admin/fakerunner"
)

// allowTestnet sets allow_testnet_build in the cloud.json of each name.
func (fc *fakeCluster) allowTestnet(t *testing.T, names ...string) {
	t.Helper()
	for _, n := range names {
		p := fc.path(n + "/cloud.json")
		var m map[string]any
		if err := json.Unmarshal(mustRead(t, p), &m); err != nil {
			t.Fatal(err)
		}
		m["allow_testnet_build"] = true
		writeJSONFile(t, p, m)
	}
}

// Testnet runners (backend/flavor): signer-admin refuses them until
// cloud.json sets allow_testnet_build; then status names the build, and
// draft and order waits follow the testnet times. An image gained waits the
// testnet images minimum, 7 minutes, and the runner takes the update with
// that wait. Offline views name both builds' waits. A cluster of two
// flavours is refused.
func TestTestnetFakeRunners(t *testing.T) {
	fc := newFakeClusterAs(t, flavor.Testnet, 60)
	cl := fc.cluster

	out := failTool(t, "status", "-cluster", cl)
	if count(out, `^s[123] error: .*the runner is a testnet build .*allow_testnet_build`) != 3 {
		t.Fatalf("status without allow_testnet_build:\n%s", out)
	}
	fc.allowTestnet(t, names...)
	mustTool(t, "pin", "-cluster", cl)
	out = mustTool(t, "status", "-cluster", cl)
	if count(out, `^s[123] setup=.* build=testnet$`) != 3 {
		t.Fatalf("status:\n%s", out)
	}

	// A margin past the testnet activation horizon (30 minutes).
	images := lockedText(fc.keys[:3], 2, 60, fee1) + "allowed_image_measurements = azure 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
	file := writeFile(t, fc.path("images.conf"), images)
	wantIn(t, failTool(t, "draft", "-cluster", cl, "-group", "locked", "-margin", "31m", "-out", fc.path("x.bin"), file),
		"the activation horizon of a testnet build")
	// A time lock above the testnet cap (30 minutes).
	wantIn(t, failTool(t, "draft", "-cluster", cl, "-group", "locked", "-margin", "0s", "-out", fc.path("x.bin"),
		writeFile(t, fc.path("long.conf"), lockedText(fc.keys[:3], 2, 3600, fee1))), "at most 1800 in a testnet build")

	// The image: the testnet images minimum, not the time lock of 60 s.
	body := fc.path("images.bin")
	out = mustTool(t, "draft", "-cluster", cl, "-group", "locked", "-margin", "0s", "-out", body, file)
	wantIn(t, out, "wait 7m0s (testnet build)", "+ allowed_image_measurements = azure")
	// show sees no runner, so it names both builds' waits.
	out = mustTool(t, "show", body)
	wantIn(t, out, "wait: at least 604800 s after arrival", "; 420 s on signers of a testnet build")
	signed := fc.path("images.signed")
	mustTool(t, append([]string{"assemble", "-out", signed, body}, fc.signAll(t, body, 0, 1)...)...)
	out = mustTool(t, "push", "-cluster", cl, signed)
	if count(out, `^s[123] accepted: locked v1/[0-9a-f]{8} pending, effective \S+ \(in (6m5[0-9]s|7m0s)\)$`) != 3 {
		t.Fatalf("push:\n%s", out)
	}

	// One default runner among testnet ones: status flags it, draft refuses.
	raw, err := os.ReadFile(fc.path("setups/s3.setup"))
	if err != nil {
		t.Fatal(err)
	}
	r := fakerunner.StartSetup(t, raw)
	cert, key := r.ClientFiles(t, t.TempDir())
	writeJSONFile(t, filepath.Join(fc.dir, "s3", "cloud.json"), map[string]any{
		"address": r.Addr(), "client_cert": cert, "client_key": key, "allow_testnet_build": true,
		"attestation": map[string]any{"verifier": "dev", "setup_sha256": fc.hashes["s3"]},
	})
	out = failTool(t, "status", "-cluster", cl)
	wantIn(t, out, "build=default DIFFERS:")
	wantIn(t, failTool(t, "draft", "-cluster", cl, "-group", "locked", "-margin", "0s", "-out", fc.path("y.bin"), file),
		"draft for signers of one build flavour")
}

// setup -build testnet refuses a time lock above the testnet cap, which a
// testnet runner would refuse at start; the default build takes it.
func TestSetupBuildTestnet(t *testing.T) {
	dir := t.TempDir()
	keys := approvers(t, dir, 3)
	ca := caDER(t)
	limit := int(flavor.Testnet.Limits().MaxTimeLock)
	file := func(timeLock int) string {
		return writeFile(t, filepath.Join(t.TempDir(), "setup.conf"),
			setupText(dir, ca, genesisTime(), lockedText(keys, 2, timeLock, fee1), "a", "b"))
	}
	over := file(limit + 1)
	wantIn(t, failTool(t, "setup", "-build", "testnet", "-out", filepath.Join(t.TempDir(), "out"), over),
		fmt.Sprintf("signer a: locked: change_delay_seconds %d, at most %d in a testnet build", limit+1, limit))
	mustTool(t, "setup", "-out", filepath.Join(t.TempDir(), "out"), over)
	mustTool(t, "setup", "-build", "default", "-out", filepath.Join(t.TempDir(), "out"), over)
	mustTool(t, "setup", "-build", "testnet", "-out", filepath.Join(t.TempDir(), "out"), file(limit))
	wantIn(t, failTool(t, "setup", "-build", "mainnet", "-out", filepath.Join(t.TempDir(), "out"), over), "default or testnet")
}
