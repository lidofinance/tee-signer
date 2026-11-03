package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/handoverorder"
	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// targetFile is a handover-setup file for the signers names of fc: the
// dev platform and the source's client CA for all, new store folders per
// signer.
func targetFile(t *testing.T, fc *fakeCluster, names ...string) string {
	t.Helper()
	src := readSetup(t, fc.path("setups/s1.setup"))
	var b strings.Builder
	fmt.Fprintf(&b, "# the targets of the test cluster\nplatform = dev\nallowed_client_ca = %s\n",
		base64.StdEncoding.EncodeToString(src.Platform.AllowedClientCA[0]))
	for _, n := range names {
		fmt.Fprintf(&b, "\n[signer %s]\nslashing_log_store.dir = %s\n", n, fc.path(n+"/target-marks"))
	}
	return writeFile(t, fc.path("targets.conf"), b.String())
}

func readSetup(t *testing.T, path string) *setupwire.Setup {
	t.Helper()
	s, err := setupwire.DecodeSetup(mustRead(t, path))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// handover-setup makes one target setup per section from the sources'
// setups and their config in force: the same cluster_id, chain and
// safety, handover_generation one higher, version 0 of both groups equal
// to the values in force, one new set of policy salts for all targets, and
// the platform part of the file. The source runner accepts each target
// (handoverorder.CheckTarget).
func TestHandoverSetup(t *testing.T) {
	fc := newFakeCluster(t)
	mustTool(t, "pin", "-cluster", fc.cluster)
	file := targetFile(t, fc, names...)
	dir := fc.path("targets")
	out := mustTool(t, "handover-setup", "-cluster", fc.cluster, "-out", dir, file)
	hashes := setupHashes(out)
	if len(hashes) != 3 {
		t.Fatalf("handover-setup:\n%s", out)
	}
	var salts []setupwire.PolicySalts
	for _, n := range names {
		src := readSetup(t, fc.path("setups/"+n+".setup"))
		raw := mustRead(t, filepath.Join(dir, n+".setup"))
		tgt, err := setupwire.DecodeSetup(raw)
		if err != nil {
			t.Fatal(err)
		}
		if h, _ := setupwire.SetupHash(raw); hex.EncodeToString(h[:]) != hashes[n] {
			t.Fatalf("%s: printed %s, file hashes to %x", n, hashes[n], h)
		}
		switch {
		case tgt.SignerName != n, tgt.ClusterID != src.ClusterID, tgt.HandoverGeneration != src.HandoverGeneration+1,
			tgt.SlashingLogMinLockDays != src.SlashingLogMinLockDays, tgt.MaxKeys != src.MaxKeys,
			tgt.Platform.SlashingLogStore.Dir != fc.path(n+"/target-marks"):
			t.Fatalf("%s: target %+v", n, tgt)
		}
		if err := handoverorder.CheckTarget(src, &src.Locked, &src.Open, tgt.Policy()); err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		if bytes.Equal(tgt.PolicySalts.Public[0][:], src.PolicySalts.Public[0][:]) {
			t.Fatalf("%s: the target has the source's salts", n)
		}
		salts = append(salts, tgt.PolicySalts)
	}
	for i := 1; i < len(salts); i++ {
		if fmt.Sprint(salts[i]) != fmt.Sprint(salts[0]) {
			t.Fatal("the targets of one cluster have different policy salts")
		}
	}

	// Refusals: a second run over the same folder, a lower lock, a section
	// for no signer of the cluster, a public key in the file.
	wantIn(t, failTool(t, "handover-setup", "-cluster", fc.cluster, "-out", dir, file), "exists")
	wantIn(t, failTool(t, "handover-setup", "-cluster", fc.cluster, "-slashing-log-min-lock-days", "6", "-out", fc.path("t2"), file),
		"below the sources' 7")
	other := writeFile(t, fc.path("other.conf"), "platform = dev\n[signer s9]\nslashing_log_store.dir = /x\n")
	wantIn(t, failTool(t, "handover-setup", "-cluster", fc.cluster, "-out", fc.path("t3"), other), "s9 is not a signer of")
	pub := writeFile(t, fc.path("pub.conf"), "platform = dev\nmax_keys = 3\n[signer s1]\nslashing_log_store.dir = /x\n")
	wantIn(t, failTool(t, "handover-setup", "-cluster", fc.cluster, "-out", fc.path("t4"), pub), `unknown key "max_keys"`)
	wantIn(t, failTool(t, "handover-setup", "-cluster", fc.cluster, "-max-keys", "4294967296", "-out", fc.path("t6"), file), "32-bit")
	salted := writeFile(t, fc.path("salted.conf"), "platform = dev\nsalt.max_keys = 0x01\n[signer s1]\nslashing_log_store.dir = /x\n")
	wantIn(t, failTool(t, "handover-setup", "-cluster", fc.cluster, "-out", fc.path("t7"), salted), "signer-admin handover-setup draws the salts")
	// The targets of a cluster made one at a time count the whole cluster
	// for its rules.
	one := targetFile(t, fc, "s2")
	out = mustTool(t, "handover-setup", "-cluster", fc.cluster, "-signers", "s2", "-out", fc.path("t8"), one)
	if len(setupHashes(out)) != 1 {
		t.Fatalf("handover-setup -signers s2:\n%s", out)
	}
	// A longer lock is the target's choice.
	out = mustTool(t, "handover-setup", "-cluster", fc.cluster, "-slashing-log-min-lock-days", "9", "-out", fc.path("t5"), file)
	if s := readSetup(t, fc.path("t5/s2.setup")); s.SlashingLogMinLockDays != 9 {
		t.Fatalf("-slashing-log-min-lock-days 9: %d\n%s", s.SlashingLogMinLockDays, out)
	}
}

// handover-draft takes the target's setup file: it refuses a target whose
// setup is not the one cloud.json pins, and one the source would refuse
// (a shorter mark log lock); it writes the target's published setup into
// the active file, and show prints the target's public values and what
// the source would say of them.
func TestHandoverDraftTargetSetup(t *testing.T) {
	fc := newFakeCluster(t)
	mustTool(t, "pin", "-cluster", fc.cluster)
	dir := fc.path("targets")
	out := mustTool(t, "handover-setup", "-cluster", fc.cluster, "-out", dir, targetFile(t, fc, "s1"))
	th := setupHashes(out)["s1"]
	tsetup := filepath.Join(dir, "s1.setup")
	cert, key := fc.runners["s1"].ClientFiles(t, t.TempDir())
	tcloud := func(name, hash string) string {
		att := map[string]any{"verifier": "dev"}
		if hash != "" {
			att["setup_sha256"] = hash
		}
		return writeJSONFile(t, fc.path(name+"/cloud.json"), map[string]any{
			"address": "tcp:127.0.0.1:1", "client_cert": cert, "client_key": key, "attestation": att})
	}
	cloud := tcloud("s1b", th)
	draft := func(args ...string) (string, error) {
		return tool(t, append([]string{"handover-draft", "-cluster", fc.cluster, "-signer", "s1"}, args...)...)
	}

	out, err := draft("-target-cloud", cloud)
	if err == nil || !strings.Contains(out+err.Error(), "-target-setup") {
		t.Fatalf("a draft without the target's setup: %v\n%s", err, out)
	}
	if out, err = draft("-target-cloud", tcloud("s1x", strings.Repeat("ab", 32)), "-target-setup", tsetup); err == nil ||
		!strings.Contains(err.Error(), "is not the setup_sha256") {
		t.Fatalf("a setup the cloud.json does not pin: %v\n%s", err, out)
	}

	// A target with a shorter lock: the draft refuses it.
	short := readSetup(t, tsetup)
	short.SlashingLogMinLockDays = 3
	shortRaw, err := short.Encode()
	if err != nil {
		t.Fatal(err)
	}
	shortPath := writeFile(t, fc.path("short.setup"), string(shortRaw))
	sh, _ := setupwire.SetupHash(shortRaw)
	if out, err = draft("-target-cloud", tcloud("s1s", hex.EncodeToString(sh[:])), "-target-setup", shortPath); err == nil ||
		!strings.Contains(err.Error(), "slashing_log_min_lock_days is 3, below the source's 7") {
		t.Fatalf("a target with a shorter lock: %v\n%s", err, out)
	}

	// The target made by handover-setup: the draft, and show.
	body := fc.path("handover.bin")
	out, err = draft("-target-cloud", cloud, "-target-setup", tsetup, "-out", body)
	if err != nil {
		t.Fatalf("handover-draft: %v\n%s", err, out)
	}
	wantIn(t, out, "target: the source accepts the target's public values")
	out = mustTool(t, "show", body)
	wantIn(t, out, "target setup "+th+", public part", "\nhandover_generation = 2\n", "\nslashing_log_min_lock_days = 7\n",
		"\nmax_keys = 16\n", "target: the source accepts the target's public values")
	if strings.Contains(out, "WARNING") {
		t.Fatalf("show warns about a good target:\n%s", out)
	}

	// show on an order to the short target (a draft by hand): a WARNING
	// with the source's reason.
	b, _, _, err := readHandover(body)
	if err != nil {
		t.Fatal(err)
	}
	b.Target.SetupHash = sh
	enc, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}
	pubShort, err := setupwire.PublishedOf(short)
	if err != nil {
		t.Fatal(err)
	}
	pubEnc, err := pubShort.Encode()
	if err != nil {
		t.Fatal(err)
	}
	bad := writeFile(t, fc.path("bad.bin"), string(enc))
	writeJSONFile(t, bad+".active", activeFile{Setup: hex.EncodeToString(mustRead(t, fc.path("setups/s1.setup"))), Target: hex.EncodeToString(pubEnc)})
	out = mustTool(t, "show", bad)
	wantIn(t, out, "\nslashing_log_min_lock_days = 3\n", "WARNING target: handover: the target's slashing_log_min_lock_days is 3, below the source's 7")
	// The active file's target must be the order's.
	pubGood, err := setupwire.PublishedOf(readSetup(t, tsetup))
	if err != nil {
		t.Fatal(err)
	}
	goodEnc, err := pubGood.Encode()
	if err != nil {
		t.Fatal(err)
	}
	writeJSONFile(t, bad+".active", activeFile{Setup: hex.EncodeToString(mustRead(t, fc.path("setups/s1.setup"))), Target: hex.EncodeToString(goodEnc)})
	wantIn(t, failTool(t, "show", bad), "not the order's target")
}
