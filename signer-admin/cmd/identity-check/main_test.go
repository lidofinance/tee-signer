//go:build !peerselect

package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func token(payload string) []byte {
	e := base64.RawURLEncoding.EncodeToString
	return []byte(e([]byte(`{"alg":"RS256"}`)) + "." + e([]byte(payload)) + "." + e([]byte("sig")))
}

func TestClaimLines(t *testing.T) {
	tok := token(`{"hwmodel":"GCP_AMD_SEV","swname":"CONFIDENTIAL_SPACE","dbgstat":"disabled-since-boot","secboot":true,
		"google_service_accounts":["a@p.iam.gserviceaccount.com"],
		"submods":{"confidential_space":{"support_attributes":["LATEST","STABLE","USABLE"]},
		"container":{"image_digest":"sha256:ab","env":{"SECRET":"hunter2"},"env_override":["x"]}}}`)
	lines, err := claimLines(tok)
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(lines, "\n")
	for _, want := range []string{
		"hwmodel = GCP_AMD_SEV",
		"swname = CONFIDENTIAL_SPACE",
		"dbgstat = disabled-since-boot",
		"secboot = true",
		"google_service_accounts = [a@p.iam.gserviceaccount.com]",
		"submods.confidential_space.support_attributes = [LATEST, STABLE, USABLE]",
		"submods.container.image_digest = sha256:ab",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in\n%s", want, all)
		}
	}
	if strings.Contains(all, "hunter2") {
		t.Errorf("an env value is shown:\n%s", all)
	}
	if !strings.Contains(all, "submods.container.env.SECRET = <value not shown>") {
		t.Errorf("env claim not masked:\n%s", all)
	}
	if !strings.Contains(all, "submods.container.env_override = <1 entries, values not shown>") {
		t.Errorf("env_override claim not masked:\n%s", all)
	}
}

func TestClaimLinesRefusesANonToken(t *testing.T) {
	if _, err := claimLines([]byte("not a token")); err == nil {
		t.Fatal("accepted a string that is not a JWT")
	}
}

func TestRunRefusesBadSettings(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "unknown-field.json")
	if err := os.WriteFile(good, []byte(`{"address":"tcp:127.0.0.1:1","bogus":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"no config":      {},
		"missing file":   {"-config", filepath.Join(dir, "none.json")},
		"unknown field":  {"-config", good},
		"zero runs":      {"-config", good, "-n", "0"},
		"unknown option": {"-nope"},
	} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != 2 {
			t.Errorf("%s: exit %d, want 2 (stdout %q stderr %q)", name, code, out.String(), errb.String())
		}
	}
}

func TestRunRefusesAnIncompleteConnection(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	// No client certificate and no verifier: the config must not run.
	if err := os.WriteFile(p, []byte(`{"address":"tcp:127.0.0.1:1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"-config", p}, &out, &errb); code != 2 {
		t.Fatalf("exit %d, want 2 (stdout %q stderr %q)", code, out.String(), errb.String())
	}
	if out.Len() != 0 {
		t.Errorf("printed on stdout before the config was valid: %q", out.String())
	}
}
