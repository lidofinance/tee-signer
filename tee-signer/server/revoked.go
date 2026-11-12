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
// the setup's own list), plus the pending open update's, plus the carried
// ones: the list of a pending open update that a rotation dropped
// (markstore.ConfigState.Carried, kept until the next open update comes
// into force). A pending revocation thus applies as soon as the runner
// takes the update, before its effective time, and a rotation does not
// undo it. An update that drops an entry of that set needs every approver
// in force: one of the list in force by setupwire Update.Decide, one that
// only the pending update or the carried list holds by Accept
// (checkPendingRevocations), since a new open update replaces the pending
// one. The entry goes once that update is in force. Updates gives the set
// to Revoked at each view it computes (reconcileLocked calls
// publishRevokedLocked): at start, after each CONFIG_UPDATE, at each
// effective time, and after a failed record write.
//
// While a body the view needs is unreadable (view.missing: the open body
// in force, the pending one, a locked one, or that of a dropped pending
// open update), the set is not complete: Revoked keeps every hash it held
// and adds what is readable, so it never shrinks, and the server serves
// TLS clients HEALTH, IDENTITY, ATTEST and CONFIG_UPDATE only (stillValid)
// until the body is back.

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
// force, the pending open update's and the carried ones. complete is false
// when a body the view needs is unreadable (v.missing), and when the open
// body in force or the pending one is.
func revokedOf(v *view) (list [][32]byte, complete bool) {
	complete = v.missing == nil
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
	list = append(list, v.state.Carried...)
	return list, complete
}

// checkPendingRevocations refuses a new open update that drops an entry of
// the revoked set the runner enforces (revokedOf: the list in force, the
// pending open update's and the carried ones), unless every approver in
// force signed and break-glass is a path now (h, setupwire
// History.BreakGlassHeld). Decide compares with the list in force only; a
// new open update replaces the pending one, so without this check the
// usual count could drop a pending or carried revocation. With every
// approver, the path is break-glass, as in Decide. v is the view Accept
// checked, with the approvers in force (v.locked) known.
func checkPendingRevocations(upd *setupwire.Update, v *view, d *setupwire.Decision, h setupwire.History, c *setupwire.Chain) error {
	b := &upd.Body
	p := v.state.Open.Pending
	if b.Group != setupwire.GroupOpen || p == nil && len(v.state.Carried) == 0 || d.Path == setupwire.PathBreakGlass {
		return nil
	}
	enforced, complete := revokedOf(v)
	if !complete {
		return backend.Refused(backend.StatusStorage,
			"config update: a body the revocations in force need is unreadable, so they are unknown; send that update again first")
	}
	kept := map[[32]byte]bool{}
	for _, x := range b.Open.RevokedClientCerts {
		kept[x] = true
	}
	for _, x := range enforced {
		if kept[x] {
			continue
		}
		if n := len(v.locked.Approvers.Keys); len(upd.Approvals) != n {
			return backend.Refused(backend.StatusBadRequest,
				"config update: open: dropping an entry of revoked_client_certs (%x, pending or carried) needs every approver in force (%d), %d signed",
				x[:8], n, len(upd.Approvals))
		}
		if held, until := h.BreakGlassHeld(c, v.locked); held {
			return backend.Refused(backend.StatusBadRequest,
				"config update: open: dropping an entry of revoked_client_certs is break-glass, which waits until %d, one change delay after the approver removal in force at %d",
				until, h.RemovedAt)
		}
		d.Path = setupwire.PathBreakGlass
		return nil
	}
	return nil
}
