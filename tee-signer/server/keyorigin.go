package server

import "github.com/lidofinance/tee-signer/signer-protocol"

// The key origin of the setup state (attestation-prover.md, "Signer
// changes", item 6; docs/attestation-statement.md, section 5): of the
// loaded keys, how many this runner made in key generation, how many it
// imported, and the hash of the DKG orders of the generated ones. A share's
// origin is in its sealed record (shareRecord), so it holds across
// restarts. A key whose record names no origin counts as imported: sealed
// import, plaintext import in debug builds, and the handover's import.

// validOrigin refuses a share record with an order hash of the wrong size
// or an order on an imported share.
func validOrigin(rec *shareRecord) bool {
	switch {
	case rec.Order == nil:
		return true
	case !rec.Generated:
		return false
	}
	return len(rec.Order) == 32
}

// noteGenerated records that the loaded key pk was made in key generation
// under the DKG order order (nil under a policy file).
func (s *Server) noteGenerated(pk backend.Pubkey, order []byte) {
	s.originMu.Lock()
	defer s.originMu.Unlock()
	if s.generated == nil {
		s.generated = map[backend.Pubkey][]byte{}
	}
	s.generated[pk] = order
}

// keyOrigin counts keys, the loaded keys, by where they came from.
func (s *Server) keyOrigin(keys []backend.ValidatorKey) backend.KeyOrigin {
	var ko backend.KeyOrigin
	var orders [][32]byte
	s.originMu.Lock()
	for _, k := range keys {
		order, ok := s.generated[k.Pubkey]
		if !ok {
			ko.Imported++
			continue
		}
		ko.Generated++
		if len(order) == 32 {
			orders = append(orders, [32]byte(order))
		}
	}
	s.originMu.Unlock()
	ko.OrdersHash = backend.KeygenOrdersHash(orders)
	return ko
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
		st.KeyOrigin = s.keyOrigin(keys)
	}
	return st, keys
}
