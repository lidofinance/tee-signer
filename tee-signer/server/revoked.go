package server

import "github.com/lidofinance/tee-signer/tee-signer/attls"

// Revoked client certificates (revoked_client_certs, open group). The
// runner refuses a TLS client whose chain holds a revoked leaf,
// intermediate or CA certificate: at the handshake (attls.WithRevoked) and
// at every frame (stillValid), so a revocation also closes the connections
// already open.
//
// The set in force is the list of the open group in force (version 0 is
// the setup's own list) plus the pending open update's. A pending
// revocation thus applies as soon as the runner takes the update, before
// its effective time. An update that drops an entry needs every approver
// in force (setupwire Update.Decide); the entry goes once that update is
// in force. Updates gives the set to Revoked at each view it computes
// (reconcileLocked calls publishRevokedLocked): at start, after each
// CONFIG_UPDATE, at each effective time, and after a failed record write.
//
// While the open body in force or the pending one is unreadable, the set
// is not complete: Revoked keeps every hash it held and adds what is
// readable, so it never shrinks, and the server serves TLS clients HEALTH
// and CONFIG_UPDATE only (stillValid) until the body is back.

// UseRevoked makes u give r the revoked certificates of each view, and
// gives it those of the view now. Call it once, after StartConfig.
func (u *Updates) UseRevoked(r *attls.Revoked) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.opt.OnRevoked = r.Update
	u.publishRevokedLocked()
}

// publishRevokedLocked gives the revoked certificates of the view to
// OnRevoked. u.mu is held.
func (u *Updates) publishRevokedLocked() {
	if u.opt.OnRevoked != nil {
		u.opt.OnRevoked(revokedOf(&u.view))
	}
}

// revokedOf is the revoked certificates of view v: the open values in
// force and the pending open update's. complete is false when either body
// is unreadable.
func revokedOf(v *view) (list [][32]byte, complete bool) {
	complete = true
	if v.open != nil {
		list = append(list, v.open.RevokedClientCerts...)
	} else {
		complete = false
	}
	if p := v.state.Open.Pending; p != nil {
		if v.newest != nil && v.newestRef == (updateRef{p.Version, p.Hash}) {
			list = append(list, v.newest.RevokedClientCerts...)
		} else {
			complete = false
		}
	}
	return list, complete
}
