package server

import (
	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// Revoked client certificates (revoked_client_certs, open group). The
// runner refuses a TLS client whose verified chain holds a revoked leaf,
// intermediate or CA certificate: at the handshake (attls.WithRevoked) and
// at every frame (stillValid), so a revocation also closes the connections
// already open.
//
// The set in force is the union of the setup's list, the active open
// update's and the pending one's. A pending revocation thus applies as soon
// as the runner takes the update, before its effective time. Revocations
// only add entries, except that an update may drop the entry of a
// certificate that has expired; such an entry stays in the union until
// the drop is in force and the set is refreshed, which refuses only a
// certificate that no longer works.

// RevokedClientCerts is the union of the revoked_client_certs of the
// setup, of the open update in force and of the pending one.
func (u *Updates) RevokedClientCerts() [][32]byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	return revokedOf(u.opt.Setup, &u.view)
}

func revokedOf(s *setupwire.Setup, v *view) [][32]byte {
	var out [][32]byte
	if s != nil {
		out = append(out, s.Open.RevokedClientCerts...)
	}
	for _, o := range []*setupwire.Open{v.open, v.newest} {
		if o != nil {
			out = append(out, o.RevokedClientCerts...)
		}
	}
	return out
}

// RefreshRevokedClientCerts sets Revoked to the list of the config in
// force (Updates.RevokedClientCerts). The runner calls it at start and the
// server after each accepted CONFIG_UPDATE. Without Updates or Revoked it
// does nothing.
func (s *Server) RefreshRevokedClientCerts() {
	if s.Updates == nil || s.Revoked == nil {
		return
	}
	s.Revoked.Set(s.Updates.RevokedClientCerts())
}
