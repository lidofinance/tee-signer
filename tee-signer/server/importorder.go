package server

import (
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

// checkSplit checks the share against the split the order names (issue #5
// R1 and R5): the request's t, n and share index are the order's, 2t > n,
// its commitments hash to the order's entry, commitment 0 is the
// validator key, and share_pubkey is the commitments' Feldman value at the
// share index (the check key generation makes of its own share). So a
// share is filed only under the validator whose polynomial it lies on.
func (s *Server) checkSplit(req *backend.SealedImportRequest, b *importorder.Body, e *importorder.Entry) error {
	switch {
	case req.T == 0:
		return backend.Refused(backend.StatusBadRequest, "IMPORT_SHARE_SEALED under an import order needs t, n, the share index and the commitments")
	case req.T != b.T || req.N != b.N || req.ShareIndex != b.ShareIndex:
		return backend.Refused(backend.StatusBadKey, "split %d of %d, share index %d; the import order names %d of %d, index %d",
			req.T, req.N, req.ShareIndex, b.T, b.N, b.ShareIndex)
	case 2*int(req.T) <= int(req.N):
		return backend.Refused(backend.StatusBadKey, "threshold %d of %d: two disjoint groups of signers could both sign", req.T, req.N)
	case setupwire.CheckThresholdOn(s.Updates.SetupWire().Platform.Platform, s.Updates.SetupWire().Chain.GenesisForkVersion, int(req.T), int(req.N)) != nil:
		return backend.Refused(backend.StatusBadKey, "%v", setupwire.CheckThresholdOn(s.Updates.SetupWire().Platform.Platform, s.Updates.SetupWire().Chain.GenesisForkVersion, int(req.T), int(req.N)))
	case len(req.Commitments) != int(req.T):
		return backend.Refused(backend.StatusBadKey, "%d commitments for threshold %d", len(req.Commitments), req.T)
	case importorder.CommitmentsHash(req.Commitments) != e.CommitmentsHash:
		return backend.Refused(backend.StatusBadKey, "the commitments are not the ones the import order names for %s", req.Pubkey.String()[:18])
	case req.Commitments[0] != req.Pubkey:
		return backend.Refused(backend.StatusBadKey, "commitment 0 is not the validator key %s", req.Pubkey.String()[:18])
	}
	want, err := threshold.FeldmanEval(req.Commitments, uint64(req.ShareIndex))
	if err != nil {
		return backend.Refused(backend.StatusBadKey, "commitments: %v", err)
	}
	if want != req.SharePubkey {
		return backend.Refused(backend.StatusBadKey, "share_pubkey is not share %d of validator %s", req.ShareIndex, req.Pubkey.String()[:18])
	}
	return nil
}
