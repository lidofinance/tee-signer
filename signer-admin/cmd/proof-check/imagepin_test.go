package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// With the signer's setup in its folder, proof-check holds the image pin
// of cloud.json to the setup's list before it connects: an unlisted pin
// fails the check, a listed one is reported as listed, and a folder
// without a setup as unchecked.
func TestCheckImagePin(t *testing.T) {
	setup, err := os.ReadFile(filepath.Join("..", "..", "..", "governance", "setupwire", "testdata", "setup-nitro.bin"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	signer := func(name, pin string, withSetup bool) topoSigner {
		folder := filepath.Join(dir, name)
		if err := os.MkdirAll(folder, 0o700); err != nil {
			t.Fatal(err)
		}
		v := strings.Repeat(pin, 48)
		b, _ := json.Marshal(map[string]any{"address": "tcp:127.0.0.1:1", "client_cert": "client.pem", "client_key": "client-key.pem",
			"attestation": map[string]any{"verifier": "aws-nitro", "nitro_pcrs": map[string]string{"0": v, "1": v, "2": v}}})
		if err := os.WriteFile(filepath.Join(folder, "cloud.json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
		if withSetup {
			if err := os.WriteFile(filepath.Join(folder, "setup"), setup, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return topoSigner{Name: name, Enabled: true, Proof: true}
	}
	r := check(dir, signer("unlisted", "22", true), time.Second)
	if r.OK || r.Pin != "" || !strings.Contains(r.Error, "allowed_image_measurements") {
		t.Fatalf("unlisted pin: %+v", r)
	}
	r = check(dir, signer("listed", "11", true), time.Second)
	if r.Pin != "listed" || strings.Contains(r.Error, "allowed_image_measurements") {
		t.Fatalf("listed pin: %+v", r)
	}
	if r = check(dir, signer("no-setup", "22", false), time.Second); r.Pin != "unchecked" {
		t.Fatalf("no setup: %+v", r)
	}
}
