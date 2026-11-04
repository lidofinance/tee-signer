package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

// exit against three fake runners with a 2 of 3 split: s1 answers with a
// wrong partial and is skipped, s2 and s3 give the exit, whose combined
// signature verifies under the validator key and lands in the beacon API
// body. With s1 and s2 only, one partial verifies and nothing is written.
func TestExitCommand(t *testing.T) {
	fc := newFakeCluster(t)
	sk, err := software.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := core.PubkeyOf(sk)
	shares, comm, err := software.SplitWithCommitments(sk, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	// The chain of setupText.
	cfg := software.DevConfig(uint64(genesisTime()), secondsPerSlot, slotsPerEpoch)
	cfg.GenesisValidatorsRoot = cloud.Root{0x4b, 0x36}
	cfg.VoluntaryExitForkVersion = cloud.Version{0x04, 0x00, 0x00, 0x10}
	const index = 42
	signers := make([]*core.Signer, len(shares))
	keys := make([]cloud.ValidatorKey, len(shares))
	for i, sh := range shares {
		s, err := core.NewSigner(cfg, 1, 0, software.NewMemHooks())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		if keys[i], err = s.AddValidator(pk, sh.Secret, index, nil); err != nil {
			t.Fatal(err)
		}
		signers[i] = s
	}
	// s1 holds share 1 but signs with share 3.
	fc.runners["s1"].SetSigner(keys[0], signers[2].Sign)
	fc.runners["s2"].SetSigner(keys[1], signers[1].Sign)
	fc.runners["s3"].SetSigner(keys[2], signers[2].Sign)
	split := writeJSONFile(t, fc.path("split.json"), map[string]any{
		"t": 2, "n": 3, "shares": map[string]int{"s1": 1, "s2": 2, "s3": 3},
		"validators": []map[string]any{{"pubkey": pk.String(), "commitments": []string{comm[0].String(), comm[1].String()}}},
	})

	out := filepath.Join(fc.dir, "exit.json")
	res := mustTool(t, "exit", "-cluster", fc.cluster, "-split", split, "-pubkey", pk.String(), "-index", "42", "-epoch", "7", "-out", out)
	wantIn(t, res, "s1: partial signature does not verify under its share key", "signed by s2,s3 (2 needed)", "wrote "+out)
	var body exitJSON
	if err := json.Unmarshal(mustRead(t, out), &body); err != nil {
		t.Fatal(err)
	}
	if body.Message.Epoch != "7" || body.Message.ValidatorIndex != "42" {
		t.Fatalf("exit body %+v", body)
	}
	var sig cloud.Signature
	if err := sig.UnmarshalText([]byte(body.Signature)); err != nil {
		t.Fatal(err)
	}
	domain := cloud.ComputeDomain(cloud.DomainVoluntaryExit, cfg.VoluntaryExitForkVersion, cfg.GenesisValidatorsRoot)
	obj, _ := cloud.HashTreeRoot(&cloud.VoluntaryExit{Epoch: 7, ValidatorIndex: index})
	if !core.Verify(pk, cloud.SigningRoot(obj, domain), sig) {
		t.Fatal("the written exit does not verify under the validator key")
	}

	out2 := filepath.Join(fc.dir, "exit2.json")
	res = failTool(t, "exit", "-cluster", fc.cluster, "-signers", "s1,s2", "-split", split, "-pubkey", pk.String(), "-index", "42", "-epoch", "7", "-out", out2)
	wantIn(t, res, "1 partial exits verify, 2 needed")
	if _, err := os.Stat(out2); err == nil {
		t.Fatal("a failed exit wrote its file")
	}
}
