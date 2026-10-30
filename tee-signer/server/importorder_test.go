//go:build !debugimport

package server

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/importorder"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/sealedimport"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

// Issue #4 F1, option B: a runner with a setup takes a sealed share only
// under an import order of k approvers in force that names the validator,
// this cluster, chain and setup, and has not expired.
func TestImportOrderRequired(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	send := func(order []byte) error {
		t.Helper()
		sk, pk := newKey(t)
		if order == nil {
			order = e.importOrder([]byte{1, 2}, pk, nil)
		} else if len(order) == 1 {
			order = nil // no order at all
		}
		sp, _ := core.PubkeyOf(sk)
		req := backend.SealedImportRequest{Pubkey: pk, SharePubkey: sp, Index: 5, Order: order}
		if order != nil {
			req.T, req.N, req.ShareIndex, req.Commitments = 1, 1, 1, []backend.Pubkey{pk}
		}
		var err error
		if req.Sealed, err = sealedimport.Seal(e.sealTo(), &req, &sk); err != nil {
			t.Fatal(err)
		}
		p, err := wireadmin.EncodeImportSealed(&req)
		if err != nil {
			t.Fatal(err)
		}
		_, err = e.srv.dispatch(ctx, wire.Frame{Type: wireadmin.TypeImportSealed, Payload: p})
		return err
	}
	if err := send(nil); err != nil {
		t.Fatalf("import under a valid order: %v", err)
	}
	_, other := newKey(t)
	for name, c := range map[string]struct {
		order []byte
		want  string
	}{
		"no order":          {[]byte{0}, "needs an import order"},
		"one approver":      {e.importOrder([]byte{1}, other, nil), "approvals_needed"},
		"unknown approver":  {e.importOrder([]byte{1, 4}, other, nil), "the set in force has"},
		"another validator": {e.importOrder([]byte{1, 2}, other, nil), "does not name"},
		"expired":           {e.importOrder([]byte{1, 2}, other, func(b *importorder.Body) { b.NotAfter = e.now() }), "expired"},
		"another target":    {e.importOrder([]byte{1, 2}, other, func(b *importorder.Body) { b.Target[0] ^= 1 }), "its target"},
		"another cluster":   {e.importOrder([]byte{1, 2}, other, func(b *importorder.Body) { b.ClusterID[0] ^= 1 }), "cluster_id"},
	} {
		err := send(c.order)
		var r *backend.RefusedError
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want a refusal with %q", name, err, c.want)
		} else if errors.As(err, &r) && r.Code != backend.StatusForbidden {
			t.Errorf("%s: status %v, want FORBIDDEN", name, r.Code)
		}
	}
}

// Issue #5 R5 and R1: the request carries the split (t, n, share index,
// commitments) the order names; the share must be the commitments' value
// at the index, commitment 0 the validator key, and 2t > n.
func TestImportSplit(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	sk, pk := newKey(t)
	shares, commitments, err := software.SplitWithCommitments(sk, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	split := func(b *importorder.Body) {
		b.T, b.N, b.ShareIndex = 2, 3, 2
		b.Validators[0].CommitmentsHash = importorder.CommitmentsHash(commitments)
	}
	send := func(share [32]byte, order []byte, change func(r *backend.SealedImportRequest)) error {
		t.Helper()
		sp, _ := core.PubkeyOf(share)
		req := backend.SealedImportRequest{Pubkey: pk, SharePubkey: sp, Index: 5, Order: order,
			T: 2, N: 3, ShareIndex: 2, Commitments: commitments}
		if change != nil {
			change(&req)
		}
		if req.Sealed, err = sealedimport.Seal(e.sealTo(), &req, &share); err != nil {
			t.Fatal(err)
		}
		p, err := wireadmin.EncodeImportSealed(&req)
		if err != nil {
			t.Fatal(err)
		}
		_, err = e.srv.dispatch(ctx, wire.Frame{Type: wireadmin.TypeImportSealed, Payload: p})
		return err
	}
	order := e.importOrder([]byte{1, 2}, pk, split)
	other := commitments[1]
	for name, c := range map[string]struct {
		share  [32]byte
		order  []byte
		change func(r *backend.SealedImportRequest)
		want   string
	}{
		"share 1 sent as share 2": {shares[0].Secret, order, nil, "is not share 2"},
		"another key's share":     {sk, order, nil, "is not share 2"},
		"no split":                {shares[1].Secret, order, func(r *backend.SealedImportRequest) { r.T, r.N, r.ShareIndex, r.Commitments = 0, 0, 0, nil }, "needs t, n"},
		"split not the order's":   {shares[1].Secret, order, func(r *backend.SealedImportRequest) { r.ShareIndex = 3 }, "the import order names"},
		"other commitments": {shares[1].Secret, order, func(r *backend.SealedImportRequest) {
			r.Commitments = []backend.Pubkey{pk, pk}
		}, "not the ones the import order names"},
		"commitment 0 not the key": {shares[1].Secret, e.importOrder([]byte{1, 2}, pk, func(b *importorder.Body) {
			split(b)
			b.Validators[0].CommitmentsHash = importorder.CommitmentsHash([]backend.Pubkey{other, other})
		}), func(r *backend.SealedImportRequest) { r.Commitments = []backend.Pubkey{other, other} }, "commitment 0"},
	} {
		err := send(c.share, c.order, c.change)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want a refusal with %q", name, err, c.want)
		}
	}
	if err := send(shares[1].Secret, order, nil); err != nil {
		t.Fatalf("share 2 of a 2-of-3 split under its order: %v", err)
	}
}

// A single-node split (t = n = 1) is taken under an import order on the
// dev, Nitro and Azure setups; a GCP signer takes no share of one, on any
// chain: the import order's 1 of 1 is refused (setupwire.CheckThresholdOn).
func TestImportSingleNode(t *testing.T) {
	for _, name := range []string{"setup-dev", "setup-nitro", "setup-azure", "setup-gcp"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("..", "..", "governance", "setupwire", "testdata", name+".bin"))
			if err != nil {
				t.Fatal(err)
			}
			g, err := setupwire.DecodeSetup(raw)
			if err != nil {
				t.Fatal(err)
			}
			e := newTgtEnv(t, "dev", func(s *setupwire.Setup) { s.Platform = g.Platform })
			sk, pk := newKey(t)
			err = e.importSealed(pk, sk, 5, nil)
			if g.Platform.Platform == setupwire.PlatformGCP {
				if err == nil || !strings.Contains(err.Error(), "single-node") {
					t.Fatalf("1 of 1 on gcp: %v, want the single-node refusal", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("1 of 1 on %s: %v", g.Platform.Platform, err)
			}
			if !hasKey(e.srv.Signer.Keys(), pk) {
				t.Fatalf("1 of 1 on %s: the key did not load", g.Platform.Platform)
			}
		})
	}
}

// hasKey reports whether keys holds pk.
func hasKey(keys []backend.ValidatorKey, pk backend.Pubkey) bool {
	for _, k := range keys {
		if k.Pubkey == pk {
			return true
		}
	}
	return false
}
