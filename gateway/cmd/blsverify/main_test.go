package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// The hand-written SSZ must reproduce the signing roots in the Web3Signer
// spec examples (computed with genesis fork version 0x00000001).
func TestSigningRootsMatchWeb3SignerExamples(t *testing.T) {
	b, err := os.ReadFile("../../../web3signer-api/signing/testdata/web3signer-26.9.0-sign-examples.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors map[string]json.RawMessage
	if err := json.Unmarshal(b, &vectors); err != nil {
		t.Fatal(err)
	}
	*genesisForkVersion = "0x00000001"
	names := []string{
		"ATTESTATION", "RANDAO_REVEAL", "AGGREGATION_SLOT", "SYNC_COMMITTEE_MESSAGE",
		"VALIDATOR_REGISTRATION", "BLOCK_V2 (BELLATRIX)", "BLOCK_V2 (DENEB)", "BLOCK_V2 (FULU)",
	}
	for _, name := range names {
		raw := strings.NewReplacer(`"previousVersion"`, `"previous_version"`, `"currentVersion"`, `"current_version"`).Replace(string(vectors[name]))
		var req request
		if err := json.Unmarshal([]byte(raw), &req); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var want struct {
			SigningRoot string `json:"signingRoot"`
		}
		_ = json.Unmarshal([]byte(raw), &want)
		root, err := signingRoot(&req)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := fmt.Sprintf("%#x", root); got != want.SigningRoot {
			t.Errorf("%s: %s, want %s", name, got, want.SigningRoot)
		}
	}
}
