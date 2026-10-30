//go:build !debugimport

package server

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// A handover keeps the signing_mode: a single-mode source hands whole
// keys, which only a single-mode target may hold, and a threshold source
// hands shares, which a single-mode target would hold as if they were
// whole keys. checkTargetPolicy refuses a target of the other mode, in
// both directions, and takes one of the same mode.
func TestHandoverKeepsSigningMode(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "governance", "setupwire", "testdata", "setup-nitro.bin"))
	if err != nil {
		t.Fatal(err)
	}
	single, threshold := setupwire.SigningModeSingle, setupwire.SigningModeThreshold
	for _, c := range []struct{ src, tgt setupwire.SigningMode }{
		{single, single}, {threshold, threshold}, {single, threshold}, {threshold, single},
	} {
		src, err := setupwire.DecodeSetup(raw)
		if err != nil {
			t.Fatal(err)
		}
		src.SigningMode = c.src
		target := src.Policy()
		target.HandoverGeneration++
		target.SigningMode = c.tgt
		err = checkTargetPolicy(src, &src.Locked, &src.Open, target)
		if c.src == c.tgt {
			if err != nil {
				t.Errorf("%s to %s: %v", c.src, c.tgt, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), "public.signing_mode") {
			t.Errorf("%s to %s: %v, want a refusal naming public.signing_mode", c.src, c.tgt, err)
		}
	}
}

// The sample setups as they are, each with its own signing_mode:
// setup-dev-single and setup-gcp-single take a whole key (1 of 1) and
// refuse a share of a 2-of-3 split, setup-dev-threshold the other way
// round. The refusals here come from checkSplit (the import order's
// split); TestSingleModeRefusesAnotherKey is the test of checkWholeKey.
func TestImportSampleSigningModes(t *testing.T) {
	for _, name := range []string{"setup-dev-single", "setup-dev-threshold", "setup-gcp-single"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "governance", "setupwire", "testdata", name+".bin"))
		if err != nil {
			t.Fatal(err)
		}
		g, err := setupwire.DecodeSetup(raw)
		if err != nil {
			t.Fatal(err)
		}
		single := g.SigningMode == setupwire.SigningModeSingle
		for _, split := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s split %v", name, split), func(t *testing.T) {
				e := newTgtEnv(t, "dev", func(s *setupwire.Setup) { s.Platform, s.SigningMode = g.Platform, g.SigningMode })
				sk, pk := newKey(t)
				var err error
				if split {
					err = e.importShareOf(sk, pk)
				} else {
					err = e.importSealed(pk, sk, 5, nil)
				}
				if want := single != split; (err == nil) != want || hasKey(e.srv.Signer.Keys(), pk) != want {
					t.Fatalf("%s mode, split %v: %v, want taken %v", g.SigningMode, split, err, want)
				}
			})
		}
	}
}

// checkWholeKey: a single-mode runner stores and loads whole keys only: a key whose
// public key is not the validator key is refused where it is added (the
// sealed import, the handover import) and where a restart loads it. A
// threshold runner takes the same key as a share of that validator.
func TestSingleModeRefusesAnotherKey(t *testing.T) {
	sk, _ := newKey(t)
	_, pk := newKey(t)
	single := newTgtEnv(t, "dev", nil)
	_, err := single.srv.addShare(pk, &sk, 1, nil, "sealed")
	var r *backend.RefusedError
	if err == nil || !errors.As(err, &r) || r.Code != backend.StatusBadKey || !strings.Contains(err.Error(), "signing_mode = single") {
		t.Fatalf("single mode, a key of another validator: %v, want a BAD_KEY refusal", err)
	}
	if hasKey(single.srv.Signer.Keys(), pk) {
		t.Fatal("the refused key loaded")
	}
	if _, err := single.srv.Platform.Store.Get(shareKey(pk)); err == nil {
		t.Fatal("the refused key was stored")
	}
	// A record of such a key in the store (written by an earlier build)
	// does not load.
	blob, err := single.srv.sealRecord(shareRecord{Pubkey: pk, Secret: sk[:], Index: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := single.srv.Platform.Store.Put(shareKey(pk), blob); err != nil {
		t.Fatal(err)
	}
	if n, err := single.srv.LoadListedShares([]string{shareKey(pk)}); n != 0 || err == nil || !strings.Contains(err.Error(), "signing_mode = single") {
		t.Fatalf("load of a stored key of another validator: %d loaded, %v", n, err)
	}
	if hasKey(single.srv.Signer.Keys(), pk) {
		t.Fatal("the stored key of another validator loaded")
	}
	// The whole key of the validator loads.
	own, _ := newKey(t)
	ownPk, _ := core.PubkeyOf(own)
	if _, err := single.srv.addShare(ownPk, &own, 1, nil, "sealed"); err != nil {
		t.Fatalf("single mode, the validator's own key: %v", err)
	}
	threshold := newShareTgtEnv(t, "dev", nil)
	if _, err := threshold.srv.addShare(pk, &sk, 1, nil, "sealed"); err != nil {
		t.Fatalf("threshold mode, a share: %v", err)
	}
}
