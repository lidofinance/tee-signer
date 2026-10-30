package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// The key origin of the setup state counts the loaded keys. Every key comes
// in by an import: sealed, plaintext in debug builds, or the handover's. So
// Imported is their number.

// keyOrigin is the key origin of keys, the loaded keys.
func keyOrigin(keys []backend.ValidatorKey) backend.KeyOrigin {
	return backend.KeyOrigin{Imported: uint32(len(keys))}
}

// parseShareRecord reads a stored share's record strictly: a field that
// shareRecord does not have refuses it, and so does trailing data. Earlier
// builds marked a share made in key generation inside the runner with
// "generated" and that order's hash with "order". Such a record does not
// load, so it never counts as an import.
func parseShareRecord(plain []byte) (shareRecord, error) {
	var rec shareRecord
	d := json.NewDecoder(bytes.NewReader(plain))
	d.DisallowUnknownFields()
	err := d.Decode(&rec)
	if err == nil {
		if _, end := d.Token(); end != io.EOF {
			err = errors.New("trailing data after the share record")
		}
	}
	if err != nil {
		clear(rec.Secret)
		return shareRecord{}, err
	}
	return rec, nil
}

// stateWithKeys is the setup state this runner reports now and the loaded
// keys its key origin counts, read once, so an ATTEST answer binds a
// keys_hash over the same keys. The server adds key_release_hash and the
// key origin to State's answer. A runner without a setup adds neither
// (the flag path: setup_hash and zeros).
func (s *Server) stateWithKeys() (backend.SetupState, []backend.ValidatorKey) {
	var keys []backend.ValidatorKey
	if s.Signer != nil {
		keys = s.Signer.Keys()
	}
	if s.State == nil {
		return backend.SetupState{}, keys
	}
	st := s.State()
	if s.SetupHash != ([32]byte{}) {
		st.KeyReleaseHash = s.KeyReleaseHash
		st.KeyOrigin = keyOrigin(keys)
	}
	return st, keys
}
