package server

import (
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// signing_mode = dv_share: the runner holds one share of each distributed
// validator of a Charon cluster. The import is the threshold one: the
// request's pubkey is the validator (group) key, the approvers' order names
// the cluster's split, and checkSplit checks that share_pubkey is the
// split's value at the share index. The runner then files and serves the
// share under share_pubkey, the key the Charon validator client asks for,
// and keeps the group key with it for the selection proof check of
// aggregates and contributions (core AddValidatorGroup). Marks, floors and
// policy apply to the share key.

// dvShare reports whether the setup says signing_mode = dv_share.
func (s *Server) dvShare() bool {
	return s.Updates != nil && s.Updates.SetupWire().SigningMode == setupwire.SigningModeDVShare
}

// importKey is the key a checked sealed import files the share under, and
// its group key: share_pubkey and the request's validator key in dv_share
// mode, the validator key and nil otherwise.
func (s *Server) importKey(req *backend.SealedImportRequest) (backend.Pubkey, *backend.Pubkey) {
	if s.dvShare() {
		group := req.Pubkey
		return req.SharePubkey, &group
	}
	return req.Pubkey, nil
}

// checkGroupKey refuses a key pk without a group key in dv_share mode, and
// a key with one in the other modes. A dv_share key without its group key
// would check selection proofs against itself, and the group key comes
// only from an approver-signed import (never from the plain debug import
// or a signing request).
func (s *Server) checkGroupKey(pk backend.Pubkey, group *backend.Pubkey) error {
	if s.Updates == nil {
		if group != nil {
			return backend.Refused(backend.StatusBadKey, "a group key needs a setup with signing_mode = dv_share")
		}
		return nil
	}
	switch dv := s.dvShare(); {
	case dv && group == nil:
		return backend.Refused(backend.StatusBadKey, "the setup says signing_mode = dv_share, and key %s has no group key: import it under an import order for its validator key", pk.String()[:18])
	case dv && *group == pk:
		return backend.Refused(backend.StatusBadKey, "key %s is its own group key: a dv_share key is a share, not the validator key", pk.String()[:18])
	case !dv && group != nil:
		return backend.Refused(backend.StatusBadKey, "key %s has a group key, and the setup says signing_mode = %s: group keys are for signing_mode = dv_share", pk.String()[:18], s.Updates.SetupWire().SigningMode)
	}
	return nil
}

// addValidator loads a key into the core, with its group key if it has one.
// It takes the secret by pointer so that it makes no copy of its own; the
// core binding clears the copy it gets.
func (s *Server) addValidator(pk backend.Pubkey, secret *[32]byte, index uint64, imp *backend.Watermark, group *backend.Pubkey) (backend.ValidatorKey, error) {
	if group != nil {
		return s.Signer.AddValidatorGroup(pk, *secret, index, imp, *group)
	}
	return s.Signer.AddValidator(pk, *secret, index, imp)
}
