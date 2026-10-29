//go:build !debugimport

package server

import (
	"context"
	"testing"

	"github.com/lidofinance/tee-signer/governance/importorder"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/sealedimport"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
	"github.com/lidofinance/tee-signer/slashing-log"
	"github.com/lidofinance/tee-signer/tee-signer/attls"
)

// Tests that reproduce findings of the security reviews in issues #4 and #5
// on lidofinance/threshold-signer-poc. Each asserts the behaviour the
// finding asks for, so each fails until its fix lands.

// sealedImportPayload is an IMPORT_SHARE_SEALED payload for sk filed under
// the validator key pk, sealed to e's import key.
func (e *tgtEnv) sealedImportPayload(pk backend.Pubkey, sk [32]byte, index uint64, interchange *backend.Watermark) []byte {
	e.t.Helper()
	sp, err := core.PubkeyOf(sk)
	if err != nil {
		e.t.Fatal(err)
	}
	req := backend.SealedImportRequest{Pubkey: pk, SharePubkey: sp, Index: index, Interchange: interchange,
		Order: e.importOrder([]byte{1, 2}, pk, nil), T: 1, N: 1, ShareIndex: 1, Commitments: []backend.Pubkey{pk}}
	if req.Sealed, err = sealedimport.Seal(e.sealTo(), &req, &sk); err != nil {
		e.t.Fatal(err)
	}
	p, err := wireadmin.EncodeImportSealed(&req)
	if err != nil {
		e.t.Fatal(err)
	}
	return p
}

// importOrder is an import order for pk (a 1-of-1 split, share index 1)
// to this runner, signed by the approvers ids and changed by change.
func (e *tgtEnv) importOrder(ids []byte, pk backend.Pubkey, change func(b *importorder.Body)) []byte {
	e.t.Helper()
	b := importorder.Body{ClusterID: e.setup.ClusterID, ChainHash: e.setup.Chain.Hash(), Target: e.hash,
		NotAfter: e.now() + 3600, T: 1, N: 1, ShareIndex: 1,
		Validators: []importorder.Entry{{Pubkey: pk, CommitmentsHash: importorder.CommitmentsHash([]backend.Pubkey{pk})}}}
	if change != nil {
		change(&b)
	}
	enc, err := b.Encode()
	if err != nil {
		e.t.Fatal(err)
	}
	o := importorder.Order{Body: b}
	for _, id := range ids {
		o.Approvals = append(o.Approvals, setupwire.Approval{Position: id - 1, Signature: importorder.SignBody(approver(id), enc)})
	}
	raw, err := o.Encode()
	if err != nil {
		e.t.Fatal(err)
	}
	return raw
}

// importSealed sends IMPORT_SHARE_SEALED as a client with every right.
func (e *tgtEnv) importSealed(pk backend.Pubkey, sk [32]byte, index uint64, interchange *backend.Watermark) error {
	e.t.Helper()
	_, err := e.srv.dispatch(ctx, wire.Frame{Type: wireadmin.TypeImportSealed, Payload: e.sealedImportPayload(pk, sk, index, interchange)})
	return err
}

// signMsg sends SIGN for m under the domain the runner's config gives it.
func (e *tgtEnv) signMsg(pk backend.Pubkey, m backend.Message) error {
	e.t.Helper()
	cfg := e.signer.Config()
	d, err := cfg.MessageDomain(m)
	if err != nil {
		e.t.Fatal(err)
	}
	p, err := wire.EncodeSign(backend.SignRequest{Pubkey: pk, Message: m, Domain: d})
	if err != nil {
		e.t.Fatal(err)
	}
	_, err = e.srv.dispatch(ctx, wire.Frame{Type: wire.TypeSign, Payload: p})
	return err
}

// vote is an attestation of the dev sample chain (8 slots per epoch).
func vote(source, target uint64) *backend.AttestationData {
	return &backend.AttestationData{Slot: target * 8, BeaconBlockRoot: backend.Root{0xbb},
		Source: backend.Checkpoint{Epoch: source, Root: backend.Root{0x5}},
		Target: backend.Checkpoint{Epoch: target, Root: backend.Root{0x7}}}
}

func newKey(t *testing.T) ([32]byte, backend.Pubkey) {
	t.Helper()
	sk, err := software.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	pk, err := core.PubkeyOf(sk)
	if err != nil {
		t.Fatal(err)
	}
	return sk, pk
}

// Issue #4 F1 (issue #5 R5): a client with an ordinary client certificate
// (no admin role) and no real share makes its own BLS secret, seals it to
// the runner's import key with interchange maxima of 2^64-1 and imports it.
// The runner must refuse the import and must never write a mark above the
// clock horizon. Today it raises the mark log to the handover tombstone:
// the honest key stops signing and after a restart the runner reads the log
// as handed over.
func TestReview4F1SealedImportRaisesMarkBeyondClock(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)

	// An honest key, imported without interchange, signs at the clock.
	hsk, hpk := newKey(t)
	if err := e.importSealed(hpk, hsk, 5, nil); err != nil {
		t.Fatal(err)
	}
	e.clock.add(4 * testEpoch) // past the restart floor (margin 3)
	now := e.signer.EpochAt(e.now())
	if err := e.signMsg(hpk, vote(now-1, now)); err != nil {
		t.Fatalf("honest vote before the hostile import: %v", err)
	}

	// The hostile import, over mutual TLS with a plain client certificate.
	root := newTestCA(t, nil, nil, nil)
	c, err := dial(t, e.srv, root.pem(), root.leaf(t, clientAuth, nil))
	if err != nil {
		t.Fatal(err)
	}
	ask, apk := newKey(t)
	maxima := markstore.Tombstone
	_, err = c.call(wireadmin.TypeImportSealed, e.sealedImportPayload(apk, ask, 99, &maxima))
	if err == nil {
		t.Errorf("IMPORT_SHARE_SEALED with maxima 2^64-1 from an ordinary client certificate was accepted")
	} else {
		t.Logf("hostile import refused: %v", err)
	}
	horizon := now + e.setup.Safety.MaxSignEpochsAheadOfClock + 1
	if m, _ := e.marks.Mark(); m.TargetEpoch > horizon || m.SourceEpoch > horizon || m.BlockSlot/8 > horizon {
		t.Errorf("mark log raised beyond the clock horizon (epoch %d): source %d target %d block %d (tombstone: %v)",
			horizon, m.SourceEpoch, m.TargetEpoch, m.BlockSlot, markstore.IsTombstone(m))
	}

	// The honest key still signs the next epoch.
	e.clock.add(testEpoch)
	if err := e.signMsg(hpk, vote(now, now+1)); err != nil {
		t.Errorf("honest vote after the hostile import refused: %v", err)
	}

	// After a restart the runner is not handed over and the honest key signs.
	e.restart()
	if e.srv.HandedOver() || e.hooks.HandedOver() {
		t.Errorf("after a restart the runner reads its mark log as handed over")
	}
	e.clock.add(4 * testEpoch)
	now = e.signer.EpochAt(e.now())
	if err := e.signMsg(hpk, vote(now-1, now)); err != nil {
		t.Errorf("honest vote after the restart refused: %v", err)
	}
}

// Issue #4 F1, access: a client certificate without the admin role gets
// FORBIDDEN for IMPORT_SHARE_SEALED before the payload is read, and the
// payload is wiped.
func TestReview4F1SealedImportNeedsAdminRole(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	ask, apk := newKey(t)
	p := e.sealedImportPayload(apk, ask, 7, nil)
	_, err := e.srv.dispatchFor(context.Background(), wire.Frame{Type: wireadmin.TypeImportSealed, Payload: p}, &client{role: attls.RoleSigning})
	if refusedWith(err) != backend.StatusForbidden {
		t.Fatalf("signing client IMPORT_SHARE_SEALED: %v, want FORBIDDEN", err)
	}
	for _, b := range p {
		if b != 0 {
			t.Fatal("refused IMPORT_SHARE_SEALED payload not cleared")
		}
	}
	root := newTestCA(t, nil, nil, nil)
	c, err := dial(t, e.srv, root.pem(), root.leaf(t, clientAuth, nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.call(wireadmin.TypeImportSealed, e.sealedImportPayload(apk, ask, 7, nil)); refusedWith(err) != backend.StatusForbidden {
		t.Fatalf("TLS client without a mark, IMPORT_SHARE_SEALED: %v, want FORBIDDEN", err)
	}
	if len(e.signer.Keys()) != 0 {
		t.Fatal("a key was imported")
	}
}

// Issue #4 F1, smaller maxima: an import whose maxima sit a few hundred
// epochs above the clock gives a silent outage of that length. Maxima above
// the clock horizon must be refused.
func TestReview4F1SealedImportMaximaBoundedByClock(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	now := e.signer.EpochAt(e.now())
	ahead := now + 500
	wm := backend.Watermark{HasAttestation: true, SourceEpoch: ahead, TargetEpoch: ahead, HasBlock: true, BlockSlot: ahead * 8}
	ask, apk := newKey(t)
	if err := e.importSealed(apk, ask, 99, &wm); err == nil {
		t.Errorf("IMPORT_SHARE_SEALED with maxima 500 epochs above the clock (epoch %d) was accepted", now)
	}
	if m, _ := e.marks.Mark(); m.TargetEpoch >= ahead {
		t.Errorf("mark log target raised to %d, clock epoch %d", m.TargetEpoch, now)
	}
}

// Issue #4 F1, junk keys: the setup names max_keys. Sealed import must not
// load more keys than that.
func TestReview4F1SealedImportCapMaxKeys(t *testing.T) {
	e2 := newTgtEnv(t, "dev", func(s *setupwire.Setup) { s.MaxKeys = 2 })
	var errs []error
	for i := range 3 {
		sk, pk := newKey(t)
		errs = append(errs, e2.importSealed(pk, sk, uint64(10+i), nil))
	}
	if errs[0] != nil || errs[1] != nil {
		t.Fatalf("imports within max_keys refused: %v", errs)
	}
	if errs[2] == nil {
		t.Errorf("a third sealed import was accepted with max_keys 2: %d keys loaded", len(e2.signer.Keys()))
	}
}

// Issue #5 R5: sealed import checks the share only against share_pubkey,
// not against the validator key it is filed under. A junk share filed first
// under a real validator key must be refused, so that the real share can
// be imported after it.
func TestReview5R5SealedShareNotBoundToValidatorKey(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	vsk, vpk := newKey(t) // the real validator key (t = 1: the share is the key)
	junk, _ := newKey(t)
	if err := e.importSealed(vpk, junk, 5, nil); err == nil {
		t.Errorf("a share that is not a share of validator %s was filed under it", vpk.String()[:18])
	}
	if err := e.importSealed(vpk, vsk, 5, nil); err != nil {
		t.Errorf("the real share of the validator refused after the junk import: %v", err)
	}
}

// Issue #5 R1, the import check: t > n/2 is checked only in key
// generation. Sealed import (and the share-import dealer tool) carry no t
// or n, so a share of a 2-of-4 split is taken, and two disjoint pairs of
// such signers can both sign. The import must refuse a share whose split
// it cannot show to have 2t > n.
func TestReview5R1SealedImportMinorityThreshold(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	sk, pk := newKey(t)
	shares, err := software.Split(sk, 2, 4)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.importSealed(pk, shares[0].Secret, 5, nil); err == nil {
		t.Errorf("a share of a 2-of-4 split was imported: the sealed import carries no t or n, so 2t > n is never checked")
	}
}

// Issue #5 R2: on a fresh mark log the device mark's source bound is 0
// (state.LoadDeviceMark), while floor-only mode keeps it at the floor
// epoch. A share re-imported without interchange then signs a vote with
// source 0, which surrounds any vote it cast before the log was lost. The
// lost-log path (runner/start.go: "a new setup and a share re-import")
// reaches exactly this state. The vote must be refused.
func TestReview5R2FreshLogSourceBoundZero(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	if m, _ := e.marks.Mark(); m.HasAttestation {
		t.Fatalf("not a fresh log: %+v", m)
	}
	start := e.signer.EpochAt(e.now())
	floor := start + e.setup.Safety.MaxSignEpochsAheadOfClock + 1
	sk, pk := newKey(t)
	if err := e.importSealed(pk, sk, 5, nil); err != nil { // re-import, no interchange
		t.Fatal(err)
	}
	e.clock.add((floor + 1 - start) * testEpoch)
	if err := e.signMsg(pk, vote(0, floor+1)); err == nil {
		t.Errorf("fresh mark log: vote (source 0, target %d) signed; the restart floor is epoch %d, so the source bound should be at least that", floor+1, floor)
	} else {
		t.Logf("refused: %v", err)
	}
}

// Issue #4 F4: the runner signed a voluntary exit for an allowlisted index
// with no approval and no stake cap, while the setup (and the attestation
// statement built from it) carries exit_approvals_needed 2 and
// exit_stake_cap_per_day 4096 ETH. Like the TA, it now needs m-of-n
// approvals bound to key, index, epoch and a nonce, under a daily cap.
func TestReview4F4ExitWithoutApprovals(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	l := e.setup.Locked
	t.Logf("setup: exit_allowed_validators %v, exit_approvals_needed %d, exit_stake_cap_per_day %d Gwei",
		l.ExitAllowedValidators, l.ExitApprovalsNeeded, l.ExitStakeCapPerDay)
	if l.ExitApprovalsNeeded < 2 || len(l.ExitAllowedValidators) == 0 {
		t.Fatal("the dev sample setup no longer asks for exit approvals")
	}
	sk, pk := newKey(t)
	idx := l.ExitAllowedValidators[0]
	if err := e.importSealed(pk, sk, idx, nil); err != nil {
		t.Fatal(err)
	}
	exit := &backend.VoluntaryExit{Epoch: e.signer.EpochAt(e.now()), ValidatorIndex: idx}
	if err := e.signMsg(pk, exit); err == nil {
		t.Errorf("voluntary exit of index %d signed with no approval (exit_approvals_needed %d) and no cap check", idx, l.ExitApprovalsNeeded)
	}
}
