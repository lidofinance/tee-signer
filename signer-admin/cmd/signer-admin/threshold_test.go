package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// signer-admin setup refuses a cluster in which no split passes the
// signers' threshold rule (setupwire.CheckThresholdOn): a cluster of one
// GCP signer can only hold keys 1 of 1, which a GCP signer refuses on every
// chain. The refusal comes when the setup is made, not at the first order.
// One dev signer on a test chain still makes a setup.
func TestSetupRefusesSingleGCPSigner(t *testing.T) {
	full := cloudSetupText(t, 1, "", "")
	shared, _, ok := strings.Cut(full, "\n[signer gsigner-1]")
	_, gcp, ok2 := strings.Cut(full, "\n[signer gsigner-3]")
	if !ok || !ok2 {
		t.Fatal("cloudSetupText changed its sections")
	}
	file := writeFile(t, filepath.Join(t.TempDir(), "setup.conf"), shared+"\n[signer gsigner-3]"+gcp)
	wantIn(t, failTool(t, "setup", "-out", filepath.Join(t.TempDir(), "setups"), file), "gsigner-3", "single-node signer on GCP")

	dir := t.TempDir()
	one := writeFile(t, filepath.Join(dir, "one.conf"), setupText(dir, caDER(t), genesisTime(), lockedText(approvers(t, dir, 3), 2, 0, fee1), "s1"))
	mustTool(t, "setup", "-out", filepath.Join(dir, "setups"), one)
}
