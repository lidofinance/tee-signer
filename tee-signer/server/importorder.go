package server

import (
	"slices"

	"github.com/lidofinance/tee-signer/governance/importorder"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-core/threshold"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// checkImportOrder is the import order check of IMPORT_SHARE_SEALED on a
// runner with a setup (issue #4 F1): the request carries an order signed
// by k approvers in force, for this cluster, chain and setup, not expired
// by the trusted clock, that names the validator. It returns the order's
// body and the validator's entry. A runner without a setup (the flag path)
// has no approvers and takes sealed shares without an order, as before.
func (s *Server) checkImportOrder(req *backend.SealedImportRequest) (*importorder.Body, *importorder.Entry, error) {
	if len(req.Order) == 0 {
		return nil, nil, backend.Refused(backend.StatusForbidden,
			"IMPORT_SHARE_SEALED needs an import order signed by the approvers in force; the request has none")
	}
	o, err := importorder.Decode(req.Order)
	if err != nil {
		return nil, nil, backend.Refused(backend.StatusBadRequest, "%v", err)
	}
	// One trusted time for the approvers in force and the expiry.
	locked, now, err := s.Updates.lockedNow()
	if err != nil {
		return nil, nil, err
	}
	if err := o.Verify(&locked.Approvers); err != nil {
		return nil, nil, backend.Refused(backend.StatusForbidden, "%v", err)
	}
	e, err := o.Body.Matches(s.Updates.SetupWire(), s.SetupHash, now, req.Pubkey)
	if err != nil {
		return nil, nil, backend.Refused(backend.StatusForbidden, "%v", err)
	}
	return &o.Body, e, nil
}

// singleKey is HEALTH's single_key for the platform part p of the setup
// (docs/protocol.md, "Key rule lock"): on GCP, whether the setup accepts
// a key held alone (a 1 of 1 import order, setupwire.CheckThresholdOn),
// "accepted" or "refused"; "n/a" elsewhere, where such an order needs no
// acceptance. The acceptance is in the private part of the setup, so a
// verifier sees it only here, unattested, as it sees key_lock.
func singleKey(p *setupwire.PlatformConfig) string {
	switch {
	case p.Platform != setupwire.PlatformGCP:
		return "n/a"
	case p.SealingKeyRelease.UnsafeSingleKeyAccepted:
		return "accepted"
	}
	return "refused"
}

// infinity is the compressed G1 point at infinity.
var infinity = backend.Pubkey{0xc0}

// checkSplit checks the share against the split the order names (issue #5
// R1 and R5): the request's t, n and share index are the order's, the
// split fits the setup's signing_mode (1 of 1 only in a single-mode setup,
// never in a threshold-mode one: setupwire.CheckThresholdOn, issue #23), 2t > n,
// its commitments hash to the order's entry, commitment 0 is the
// validator key, and share_pubkey is the commitments' Feldman value at the
// share index. So a
// share is filed only under the validator whose polynomial it lies on.
//
// A degenerate split is refused: a commitment at the point at infinity
// (a valid G1 point; [pk, infinity] makes every share the key), and with
// n >= 2 a share_pubkey equal to the validator key (a share that is the
// whole key; for an honest split the chance is about 1 in r).
func (s *Server) checkSplit(req *backend.SealedImportRequest, b *importorder.Body, e *importorder.Entry) error {
	// The threshold rule of this signer's platform and chain, once: the
	// case and its message use the same result.
	w := s.Updates.SetupWire()
	thresholdErr := setupwire.CheckThresholdOn(w, int(req.T), int(req.N))
	switch {
	case req.T == 0:
		return backend.Refused(backend.StatusBadRequest, "IMPORT_SHARE_SEALED under an import order needs t, n, the share index and the commitments")
	case req.T != b.T || req.N != b.N || req.ShareIndex != b.ShareIndex:
		return backend.Refused(backend.StatusBadKey, "split %d of %d, share index %d; the import order names %d of %d, index %d",
			req.T, req.N, req.ShareIndex, b.T, b.N, b.ShareIndex)
	case 2*int(req.T) <= int(req.N):
		return backend.Refused(backend.StatusBadKey, "threshold %d of %d: two disjoint groups of signers could both sign", req.T, req.N)
	case thresholdErr != nil:
		return backend.Refused(backend.StatusBadKey, "%v", thresholdErr)
	case len(req.Commitments) != int(req.T):
		return backend.Refused(backend.StatusBadKey, "%d commitments for threshold %d", len(req.Commitments), req.T)
	case importorder.CommitmentsHash(req.Commitments) != e.CommitmentsHash:
		return backend.Refused(backend.StatusBadKey, "the commitments are not the ones the import order names for %s", req.Pubkey.String()[:18])
	case req.Commitments[0] != req.Pubkey:
		return backend.Refused(backend.StatusBadKey, "commitment 0 is not the validator key %s", req.Pubkey.String()[:18])
	case slices.Contains(req.Commitments, infinity):
		return backend.Refused(backend.StatusBadKey, "a commitment of validator %s is the point at infinity: the split is degenerate", req.Pubkey.String()[:18])
	}
	want, err := threshold.FeldmanEval(req.Commitments, uint64(req.ShareIndex))
	if err != nil {
		return backend.Refused(backend.StatusBadKey, "commitments: %v", err)
	}
	if want != req.SharePubkey {
		return backend.Refused(backend.StatusBadKey, "share_pubkey is not share %d of validator %s", req.ShareIndex, req.Pubkey.String()[:18])
	}
	if req.N >= 2 && req.SharePubkey == req.Pubkey {
		return backend.Refused(backend.StatusBadKey, "share %d of a %d-of-%d split is the validator key %s: the split is degenerate",
			req.ShareIndex, req.T, req.N, req.Pubkey.String()[:18])
	}
	if w.Platform.Platform == setupwire.PlatformGCP && req.T == 1 && req.N == 1 {
		s.Log.Warn("UNSAFE: taking a 1 of 1 share on GCP under the setup's unsafe_single_key_accepted", "pubkey", req.Pubkey.String(), "why", setupwire.UnsafeSingleKeyWarning)
	}
	return nil
}
