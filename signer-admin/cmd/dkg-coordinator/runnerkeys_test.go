package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// TKGARTIFACT-01: check-deposits took the result file's word for which
// keys the DKG made. A coordinator that writes a result of its own keys,
// consistent and with deposits signed by them, got the file passed. The
// fixture is exactly that: keys made here, which no runner holds. Without
// the runners' answers check-deposits refuses to write the funding file.
func TestCheckDepositsNeedsTheRunners(t *testing.T) {
	f := newFixture(t, dirkSetupJSON, 2)
	deps := filepath.Join(f.dir, "deposits.json")
	if err := writeJSON(deps, f.deposits(t)); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(f.dir, "checked.json")
	err := cmdCheckDeposits([]string{"-policy", f.policyPath, "-platform", "dev", "-result", f.resultPath, "-deposits", deps,
		"-fork-version", hex.EncodeToString(testFork[:]), "-out", out})
	if err == nil || !strings.Contains(err.Error(), "-config") {
		t.Fatalf("check-deposits without the runners: %v", err)
	}
	// Runners that hold the keys of another DKG: refused, nothing written.
	other := newFixture(t, dirkSetupJSON, 2)
	other.runnersHoldFixture(t)
	err = cmdCheckDeposits([]string{"-policy", f.policyPath, "-platform", "dev", "-result", f.resultPath, "-deposits", deps,
		"-fork-version", hex.EncodeToString(testFork[:]), "-config", f.configPath(t), "-out", out})
	if err == nil || !strings.Contains(err.Error(), "runner 1: does not hold validator 0") {
		t.Fatalf("check-deposits with runners that do not hold the keys: %v", err)
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("the funding file was written")
	}
	// The runners of this DKG: passed.
	f.runnersHoldFixture(t)
	if err := cmdCheckDeposits([]string{"-policy", f.policyPath, "-platform", "dev", "-result", f.resultPath, "-deposits", deps,
		"-fork-version", hex.EncodeToString(testFork[:]), "-config", f.configPath(t), "-out", out}); err != nil {
		t.Fatal(err)
	}
}

// heldBy refuses a result unless runner i holds, for every validator, the
// share at its position: the key and the public share the result names.
func TestHeldBy(t *testing.T) {
	f := newFixture(t, dirkSetupJSON, 2)
	gks, shares, err := f.res.Keys()
	if err != nil {
		t.Fatal(err)
	}
	held := func(i int) []backend.ValidatorKey {
		var ks []backend.ValidatorKey
		for v := range gks {
			ks = append(ks, backend.ValidatorKey{Pubkey: gks[v], SharePubkey: shares[v][i], Index: backend.IndexUnknown})
		}
		return ks
	}
	for i := range 3 {
		if err := heldBy(f.res, i, held(i)); err != nil {
			t.Fatalf("runner %d: %v", i+1, err)
		}
	}
	other := held(1)
	other[0].SharePubkey = shares[0][2]
	for _, tc := range []struct {
		name string
		keys []backend.ValidatorKey
		want string
	}{
		{"no keys", nil, "does not hold validator 0"},
		{"one key missing", held(0)[1:], "does not hold validator 0"},
		{"another share", other, "holds another share of validator 0"},
		{"another runner's keys", held(2), fmt.Sprintf("holds another share of validator %d", 0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := heldBy(f.res, 1, tc.keys); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}
