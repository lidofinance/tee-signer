package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-admin/fakerunner"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

// proof-check with the setup pins of each signer's cloud.json, against fake
// runners over mutual TLS with the dev document: a signer of another setup,
// an unpinned setup or a config below the minimum is marked bad, and the
// proof file carries the setup state of the good ones.
func TestCheckSetupPins(t *testing.T) {
	withSetup := fullState
	withSetup.Order, withSetup.KeyReleaseHash = cloud.Order{}, cloud.Root{}
	withSetup.Locked.Pending.EffectiveAt = 4_000_000_000 // 2096: still pending
	setupRunner := fakerunner.Start(t, withSetup)
	flagRunner := fakerunner.Start(t, cloud.SetupState{SetupHash: cloud.Root{0xc0, 0xff, 0xee, 0x01}})
	pin := hex.EncodeToString(withSetup.SetupHash[:])

	dir := t.TempDir()
	signer := func(name string, r *fakerunner.Runner, att map[string]any) topoSigner {
		folder := filepath.Join(dir, name)
		if err := os.MkdirAll(folder, 0o700); err != nil {
			t.Fatal(err)
		}
		r.ClientFiles(t, folder)
		att["verifier"] = "dev"
		b, _ := json.Marshal(map[string]any{"address": r.Addr(), "client_cert": "client.pem", "client_key": "client-key.pem",
			"attestation": att, "accounts": "accounts.json", "slots_per_epoch": 32})
		if err := os.WriteFile(filepath.Join(folder, "cloud.json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
		return topoSigner{Name: name, Enabled: true, Proof: true}
	}
	tests := []struct {
		s    topoSigner
		want string // empty: the check passes
	}{
		{signer("pinned", setupRunner, map[string]any{"setup_sha256": pin, "min_locked_version": 2}), ""},
		{signer("other-setup", setupRunner, map[string]any{"setup_sha256": strings.Repeat("99", 32)}), "is not the pinned setup_sha256"},
		{signer("unpinned", setupRunner, map[string]any{}), "no setup_sha256 is pinned"},
		{signer("below-min", setupRunner, map[string]any{"setup_sha256": pin, "min_open_version": 2}), "below min_open_version 2"},
		{signer("flag-path", flagRunner, map[string]any{}), ""},
	}
	of := outFile{IntervalS: 60}
	longHex := regexp.MustCompile(`[0-9a-f]{16,}`)
	for _, tc := range tests {
		r := check(dir, tc.s, 10*time.Second)
		of.Signers = append(of.Signers, r)
		if tc.want == "" {
			if !r.OK || r.Setup == nil {
				t.Fatalf("%s: %+v", tc.s.Name, r)
			}
			continue
		}
		if r.OK || !strings.Contains(r.Error, tc.want) || r.Setup != nil {
			t.Fatalf("%s: ok %v error %q setup %+v, want a failed check with %q", tc.s.Name, r.OK, r.Error, r.Setup, tc.want)
		}
		if longHex.MatchString(r.Error) {
			t.Fatalf("%s: a full hash in the error %q", tc.s.Name, r.Error)
		}
	}
	if v := of.Signers[0].Setup; !v.Pinned || v.SetupHash != "5e700000" || v.Locked.Version != 2 || v.Locked.MinVersion != 2 ||
		v.Locked.Pending == nil || v.Locked.Pending.Version != 3 {
		t.Fatalf("pinned signer's setup %+v locked %+v", v, v.Locked)
	}
	if v := of.Signers[4].Setup; v.Pinned || !v.FlagPath || v.SetupHash != "c0ffee01" {
		t.Fatalf("flag-path signer's setup %+v", v)
	}

	// The file the exporter reads: "setup" on the passed checks only.
	path := filepath.Join(t.TempDir(), "proof.json")
	if err := write(path, of); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	var raw struct {
		Signers []map[string]json.RawMessage `json:"signers"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	for i, s := range raw.Signers {
		_, has := s["setup"]
		if has != (tests[i].want == "") {
			t.Fatalf("%s: setup in the file %v", tests[i].s.Name, has)
		}
	}
	if !strings.Contains(string(raw.Signers[0]["setup"]), `"pending": {`) {
		t.Fatalf("pinned signer's setup in the file: %s", raw.Signers[0]["setup"])
	}
}
