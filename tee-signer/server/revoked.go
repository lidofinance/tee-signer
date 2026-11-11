package server

import (
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/tee-signer/attls"
)

// Revoked client certificates (revoked_client_certs, open group). The
// runner refuses a TLS client whose chain holds a revoked leaf,
// intermediate or CA certificate, or a certificate of a revoked public key
// (attls.Revoked): at the handshake (attls.WithRevoked) and at every frame
// (stillValid), so a revocation also closes the connections already open.
//
// The set in force is the list of the open group in force (version 0 is
// the setup's own list) plus the pending open update's. A pending
// revocation thus applies as soon as the runner takes the update, before
// its effective time. An update that drops an entry of that set needs
// every approver in force: one of the list in force by setupwire
// Update.Decide, one that only the pending update holds by Accept
// (checkPendingRevocations), since a new open update replaces the pending
// one. The entry goes once that update is in force. Updates gives the set
// to Revoked at each view it computes
// (reconcileLocked calls publishRevokedLocked): at start, after each
// CONFIG_UPDATE, at each effective time, and after a failed record write.
//
// While the open body in force or the pending one is unreadable, the set
// is not complete: Revoked keeps every hash it held and adds what is
// readable, so it never shrinks, and the server serves TLS clients HEALTH,
// IDENTITY, ATTEST and CONFIG_UPDATE only (stillValid) until the body is
// back.

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

// checkPendingRevocations refuses a new open update that drops an entry of
// the revoked set the runner enforces, the list in force plus the pending
// open update's, unless every approver in force signed. Decide compares
// with the list in force only; a new open update replaces the pending one,
// so without this check the usual count could drop a pending revocation.
// With every approver, the path is break-glass, as in Decide. v is the
// view Accept checked, with the approvers in force (v.locked) known.
func checkPendingRevocations(upd *setupwire.Update, v *view, d *setupwire.Decision) error {
	b := &upd.Body
	p := v.state.Open.Pending
	if b.Group != setupwire.GroupOpen || p == nil || d.Path == setupwire.PathBreakGlass {
		return nil
	}
	enforced, complete := revokedOf(v)
	if !complete {
		return backend.Refused(backend.StatusStorage,
			"config update: the pending open version %d has no readable body, so the revocations it holds are unknown; send that update again first", p.Version)
	}
	kept := map[[32]byte]bool{}
	for _, h := range b.Open.RevokedClientCerts {
		kept[h] = true
	}
	for _, h := range enforced {
		if kept[h] {
			continue
		}
		if n := len(v.locked.Approvers.Keys); len(upd.Approvals) != n {
			return backend.Refused(backend.StatusBadRequest,
				"config update: open: dropping an entry of revoked_client_certs (%x, of the pending open version %d) needs every approver in force (%d), %d signed",
				h[:8], p.Version, n, len(upd.Approvals))
		}
		d.Path = setupwire.PathBreakGlass
		return nil
	}
	return nil
}
