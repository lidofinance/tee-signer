package main

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-admin/fakerunner"
)

// A cluster.json with two single-mode signers of one cluster_id, as
// setup-tool encode makes from two human files: each would hold the whole
// key with its own mark log. pin and import-draft refuse it.
func TestTwoSingleModeSignersRefused(t *testing.T) {
	dir := t.TempDir()
	conf := writeFile(t, filepath.Join(dir, "setup.conf"), setupText(dir, caDER(t), genesisTime(), lockedText(approvers(t, dir, 3), 2, 0, fee1), "x1"))
	mustTool(t, "setup", "-out", filepath.Join(dir, "setups"), conf)
	raw1 := mustRead(t, filepath.Join(dir, "setups", "x1.setup"))
	s, err := setupwire.DecodeSetup(raw1)
	if err != nil {
		t.Fatal(err)
	}
	s.SignerName = "x2"
	raw2, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	var signers []any
	for name, raw := range map[string][]byte{"x1": raw1, "x2": raw2} {
		r := fakerunner.StartSetup(t, raw)
		cert, key := r.ClientFiles(t, t.TempDir())
		writeFile(t, filepath.Join(dir, "cl", name+".setup"), string(raw))
		writeJSONFile(t, filepath.Join(dir, "cl", name, "cloud.json"), map[string]any{
			"address": r.Addr(), "client_cert": cert, "client_key": key, "attestation": map[string]any{"verifier": "dev"}})
		signers = append(signers, map[string]string{"name": name, "cloud": name + "/cloud.json", "setup": name + ".setup"})
	}
	cl := writeJSONFile(t, filepath.Join(dir, "cl", "cluster.json"), map[string]any{"signers": signers})
	wantIn(t, failTool(t, "pin", "-cluster", cl), "signing_mode = single with 2 signers")
	_, _, sp := split(t, dir, 1, 1, []string{"x1"})
	wantIn(t, failTool(t, "import-draft", "-cluster", cl, "-signer", "x1", "-split", sp, "-out", filepath.Join(dir, "x1.bin")),
		"signing_mode = single with 2 signers")
}

// A split file that gives one share index to two signers is refused: both
// would hold the same share. In a 1 of 1 split that is the whole key.
func TestImportDraftRepeatedShareIndex(t *testing.T) {
	fc := newFakeCluster(t)
	mustTool(t, "pin", "-cluster", fc.cluster)
	_, _, sp := split(t, fc.dir, 2, 3, []string{"s1", "s2", "s3"})
	var m map[string]any
	if err := json.Unmarshal(mustRead(t, sp), &m); err != nil {
		t.Fatal(err)
	}
	m["shares"] = map[string]int{"s1": 1, "s2": 1, "s3": 3}
	sp = writeJSONFile(t, fc.path("split2.json"), m)
	for _, n := range []string{"s1", "s2", "s3"} {
		wantIn(t, failTool(t, "import-draft", "-cluster", fc.cluster, "-signer", n, "-split", sp, "-out", fc.path(n+".bin")),
			"share index 1 is given to s1 and s2")
	}
	m["shares"] = map[string]int{"s1": 1, "s2": 2, "s3": 4}
	sp = writeJSONFile(t, fc.path("split3.json"), m)
	wantIn(t, failTool(t, "import-draft", "-cluster", fc.cluster, "-signer", "s1", "-split", sp, "-out", fc.path("s1.bin")),
		"s3: share index 4, want 1 to 3")
}
