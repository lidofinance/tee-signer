//go:build !debugimport

package server

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/importorder"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/threshold"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/sealedimport"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
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
// split); TestSingleModeRefusesAnotherKey and
// TestThresholdModeRefusesAWholeKey are the tests of checkWholeKey.
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

// checkWholeKey, the other side: a threshold-mode runner holds shares of
// splits only, never the validator key itself. A key whose public key is
// the validator key is refused where it is added and where a restart
// loads it; a single-mode runner takes it.
func TestThresholdModeRefusesAWholeKey(t *testing.T) {
	sk, pk := newKey(t)
	threshold := newShareTgtEnv(t, "dev", nil)
	_, err := threshold.srv.addShare(pk, &sk, 1, nil, "sealed")
	var r *backend.RefusedError
	if err == nil || !errors.As(err, &r) || r.Code != backend.StatusBadKey || !strings.Contains(err.Error(), "signing_mode = threshold") {
		t.Fatalf("threshold mode, the whole key: %v, want a BAD_KEY refusal", err)
	}
	if hasKey(threshold.srv.Signer.Keys(), pk) {
		t.Fatal("the refused key loaded")
	}
	if _, err := threshold.srv.Platform.Store.Get(shareKey(pk)); err == nil {
		t.Fatal("the refused key was stored")
	}
	blob, err := threshold.srv.sealRecord(shareRecord{Pubkey: pk, Secret: sk[:], Index: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := threshold.srv.Platform.Store.Put(shareKey(pk), blob); err != nil {
		t.Fatal(err)
	}
	if n, err := threshold.srv.LoadListedShares([]string{shareKey(pk)}); n != 0 || err == nil || !strings.Contains(err.Error(), "signing_mode = threshold") {
		t.Fatalf("load of a stored whole key: %d loaded, %v", n, err)
	}
	if hasKey(threshold.srv.Signer.Keys(), pk) {
		t.Fatal("the stored whole key loaded")
	}
	single := newTgtEnv(t, "dev", nil)
	if _, err := single.srv.addShare(pk, &sk, 1, nil, "sealed"); err != nil {
		t.Fatalf("single mode, the whole key: %v", err)
	}
}

// curveOrder is r, the order of the BLS12-381 G1 subgroup.
var curveOrder, _ = new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)

// pubkeyOfScalar is the public key of the scalar x mod r (not zero).
func pubkeyOfScalar(t *testing.T, x *big.Int) backend.Pubkey {
	t.Helper()
	var sk [32]byte
	new(big.Int).Mod(x, curveOrder).FillBytes(sk[:])
	pk, err := core.PubkeyOf(sk)
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

// An approver-signed import order whose split is degenerate at this
// runner's index hands it the whole key: with commitments [pk, infinity]
// every share of a 2-of-3 split is the key, on GCP too, where a 1 of 1
// order is refused without the setup's acceptance; with t = 3,
// commitments [pk, a*G, b*G] and a*i + b*i^2 = 0, share i is. A
// threshold-mode runner refuses both: checkSplit refuses the point at
// infinity and a share equal to the validator key in a split with n >= 2,
// and checkWholeKey refuses a share whose public key is the validator key.
func TestImportDegenerateSplit(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "governance", "setupwire", "testdata", "setup-gcp.bin"))
	if err != nil {
		t.Fatal(err)
	}
	gcp, err := setupwire.DecodeSetup(raw)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := rand.Int(rand.Reader, curveOrder)
	b.Add(b, big.NewInt(1))
	a := new(big.Int).Mul(b, big.NewInt(-2)) // a*2 + b*4 = 0 at index 2
	for _, c := range []struct {
		name    string
		gcp     bool
		t, n    uint8
		commits func(pk backend.Pubkey) []backend.Pubkey
		want    string
	}{
		{"infinity", false, 2, 3, func(pk backend.Pubkey) []backend.Pubkey { return []backend.Pubkey{pk, {0xc0}} }, "point at infinity"},
		{"infinity on gcp", true, 2, 3, func(pk backend.Pubkey) []backend.Pubkey { return []backend.Pubkey{pk, {0xc0}} }, "point at infinity"},
		{"zero at index 2", false, 3, 4, func(pk backend.Pubkey) []backend.Pubkey {
			return []backend.Pubkey{pk, pubkeyOfScalar(t, a), pubkeyOfScalar(t, b)}
		}, "is the validator key"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var change func(s *setupwire.Setup)
			if c.gcp {
				change = func(s *setupwire.Setup) { s.Platform = gcp.Platform }
			}
			e := newShareTgtEnv(t, "dev", change)
			sk, pk := newKey(t)
			commitments := c.commits(pk)
			if got, err := threshold.FeldmanEval(commitments, 2); err != nil || got != pk {
				t.Fatalf("the split is not degenerate at index 2: %v", err)
			}
			order := e.importOrder([]byte{1, 2}, pk, func(b *importorder.Body) {
				b.T, b.N, b.ShareIndex = c.t, c.n, 2
				b.Validators[0].CommitmentsHash = importorder.CommitmentsHash(commitments)
			})
			req := backend.SealedImportRequest{Pubkey: pk, SharePubkey: pk, Index: 5, Order: order,
				T: c.t, N: c.n, ShareIndex: 2, Commitments: commitments}
			var err error
			if req.Sealed, err = sealedimport.Seal(e.sealTo(), &req, &sk); err != nil {
				t.Fatal(err)
			}
			p, err := wireadmin.EncodeImportSealed(&req)
			if err != nil {
				t.Fatal(err)
			}
			_, err = e.srv.dispatch(ctx, wire.Frame{Type: wireadmin.TypeImportSealed, Payload: p})
			var r *backend.RefusedError
			if err == nil || !errors.As(err, &r) || r.Code != backend.StatusBadKey || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("%v, want a BAD_KEY refusal with %q", err, c.want)
			}
			if hasKey(e.srv.Signer.Keys(), pk) {
				t.Fatal("the whole key loaded")
			}
		})
	}
}
