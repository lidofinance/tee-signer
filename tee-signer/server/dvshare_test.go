//go:build !debugimport

package server

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/importorder"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/sealedimport"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

// newDVEnv is a runner whose setup says signing_mode = dv_share.
func newDVEnv(t *testing.T) *tgtEnv {
	t.Helper()
	return newShareTgtEnv(t, "dev", func(s *setupwire.Setup) { s.SigningMode = setupwire.SigningModeDVShare })
}

// dvShare is share index of a 3-of-4 split of a fresh group key, as a
// Charon cluster lock holds it: the group key, the share and its key, and
// the split's commitments.
type dvShare struct {
	groupSk, sk [32]byte
	group, pk   backend.Pubkey
	commitments []backend.Pubkey
	index       uint8
	otherSk     [32]byte // another share of the same split
	otherPk     backend.Pubkey
	otherIndex  uint8
}

func newDVShare(t *testing.T) *dvShare {
	t.Helper()
	gsk, gpk := newKey(t)
	shares, commitments, err := software.SplitWithCommitments(gsk, 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	d := &dvShare{groupSk: gsk, group: gpk, commitments: commitments, index: 2, sk: shares[1].Secret,
		otherSk: shares[2].Secret, otherIndex: 3}
	d.pk, _ = core.PubkeyOf(d.sk)
	d.otherPk, _ = core.PubkeyOf(d.otherSk)
	return d
}

// request is the IMPORT_SHARE_SEALED request of share (sk, index) of d,
// under an order the approvers signed for the group key.
func (e *tgtEnv) dvRequest(d *dvShare, sk [32]byte, index uint8) backend.SealedImportRequest {
	e.t.Helper()
	sp, _ := core.PubkeyOf(sk)
	order := e.importOrder([]byte{1, 2}, d.group, func(b *importorder.Body) {
		b.T, b.N, b.ShareIndex = 3, 4, index
		b.Validators[0].CommitmentsHash = importorder.CommitmentsHash(d.commitments)
	})
	req := backend.SealedImportRequest{Pubkey: d.group, SharePubkey: sp, Index: 9, Order: order,
		T: 3, N: 4, ShareIndex: index, Commitments: d.commitments}
	var err error
	if req.Sealed, err = sealedimport.Seal(e.sealTo(), &req, &sk); err != nil {
		e.t.Fatal(err)
	}
	return req
}

func (e *tgtEnv) importDV(d *dvShare) error {
	e.t.Helper()
	req := e.dvRequest(d, d.sk, d.index)
	p, err := wireadmin.EncodeImportSealed(&req)
	if err != nil {
		e.t.Fatal(err)
	}
	_, err = e.srv.dispatch(ctx, wire.Frame{Type: wireadmin.TypeImportSealed, Payload: p})
	return err
}

// groupContribution is a ContributionAndProof (minimal preset, the dev
// chain's) for validator index 9 whose selection proof the group key sk
// made, as a Charon cluster combines it.
func (e *tgtEnv) groupContribution(sk [32]byte, pk backend.Pubkey) *backend.ContributionAndProof {
	e.t.Helper()
	m := software.NewMemHooks()
	m.Clock = func() (uint64, error) { return e.now(), nil }
	cfg := e.signer.Config()
	gcfg := cfg
	gcfg.DeviceMark = false // the memory hooks keep per-validator marks
	g, err := core.NewSigner(gcfg, 1, 1, m)
	if err != nil {
		e.t.Fatal(err)
	}
	defer g.Close()
	if _, err := g.AddValidator(pk, sk, 9, nil); err != nil {
		e.t.Fatal(err)
	}
	slot := e.signer.EpochAt(e.now()) * cfg.SlotsPerEpoch
	sel := &backend.SyncSelectionProof{Slot: slot, SubcommitteeIndex: 1}
	d, _ := cfg.MessageDomain(sel)
	proof, err := g.Sign(backend.SignRequest{Pubkey: pk, Message: sel, Domain: d})
	if err != nil {
		e.t.Fatal(err)
	}
	le := binary.LittleEndian
	b := le.AppendUint64(nil, 9)
	b = le.AppendUint64(b, slot)
	b = append(b, make([]byte, 32)...)
	b = le.AppendUint64(b, 1)
	b = append(b, 0x01)                // aggregation_bits: 32 / 4 subnets = 8 bits
	b = append(b, make([]byte, 96)...) // contribution signature
	b = append(b, proof[:]...)
	return &backend.ContributionAndProof{SSZ: b}
}

// A dv_share runner takes a share of a Charon split under the approvers'
// order for the group key, and serves it under the share's own key, the
// key the Charon validator client asks for. A contribution that carries
// the group's selection proof signs; the group key is no key of the
// runner. After a restart the sealed record brings the group key back.
func TestDVShareImportAndSign(t *testing.T) {
	e := newDVEnv(t)
	d := newDVShare(t)
	if err := e.importDV(d); err != nil {
		t.Fatalf("import: %v", err)
	}
	keys := e.srv.Signer.Keys()
	if len(keys) != 1 || keys[0].Pubkey != d.pk || keys[0].SharePubkey != d.pk {
		t.Fatalf("keys %+v, want the share key %s alone", keys, d.pk.String()[:18])
	}
	if rec := e.recordOf(d.pk); rec.GroupPubkey == nil || *rec.GroupPubkey != d.group {
		t.Fatalf("record group key %v, want %s", rec.GroupPubkey, d.group.String()[:18])
	}
	con := e.groupContribution(d.groupSk, d.group)
	if err := e.signMsg(d.pk, con); err != nil {
		t.Fatalf("contribution with the group's proof: %v", err)
	}
	if err := e.signMsg(d.group, con); backend.StatusOf(err) != backend.StatusUnknownValidator {
		t.Fatalf("sign under the group key: %v, want UNKNOWN_VALIDATOR", err)
	}
	// The protocol level stays 2: a client that does not know dv_share reads
	// the mode as unknown and refuses the keys (the gateway's whole-key gate).
	if h, err := e.srv.health(); err != nil || h.SigningMode != "dv_share" || h.EffectiveProtocol() != 2 {
		t.Fatalf("HEALTH signing_mode, protocol: %v, %v", h, err)
	}

	e.restart()
	if !hasKey(e.srv.Signer.Keys(), d.pk) {
		t.Fatal("the share did not load after a restart")
	}
	if err := e.signMsg(d.pk, e.groupContribution(d.groupSk, d.group)); err != nil {
		t.Fatalf("contribution after a restart: %v", err)
	}
}

// A Charon client may register the group key with the builder: a dv_share
// runner signs a registration that names the share key or the group key,
// and refuses another key. A single-mode runner takes only its own key.
func TestDVShareRegistrationPubkey(t *testing.T) {
	e := newDVEnv(t)
	d := newDVShare(t)
	if err := e.importDV(d); err != nil {
		t.Fatal(err)
	}
	_, other := newKey(t)
	for _, c := range []struct {
		name string
		pk   backend.Pubkey
		ok   bool
	}{{"group key", d.group, true}, {"share key", d.pk, true}, {"another key", other, false}} {
		err := e.signMsg(d.pk, e.registration(c.pk))
		if c.ok && err != nil || !c.ok && backend.StatusOf(err) != backend.StatusPolicyPubkey {
			t.Errorf("dv_share, registration for the %s: %v, want ok %v", c.name, err, c.ok)
		}
	}
	single := newTgtEnv(t, "dev", nil)
	if err := single.importSealed(d.pk, d.sk, 9, nil); err != nil {
		t.Fatal(err)
	}
	if err := single.signMsg(d.pk, single.registration(d.group)); backend.StatusOf(err) != backend.StatusPolicyPubkey {
		t.Errorf("single mode, registration for the group key: %v, want POLICY_PUBKEY", err)
	}
}

// The problem dv_share solves: a single-mode runner holds the same Charon
// share as a whole key, and refuses the contribution with the group's
// proof.
func TestSingleModeRefusesGroupSelectionProof(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	d := newDVShare(t)
	if err := e.importSealed(d.pk, d.sk, 9, nil); err != nil {
		t.Fatal(err)
	}
	err := e.signMsg(d.pk, e.groupContribution(d.groupSk, d.group))
	if backend.StatusOf(err) != backend.StatusSelectionProof {
		t.Fatalf("single mode, the group's proof: %v, want SELECTION_PROOF", err)
	}
}

// The batch import takes dv_share shares the same way, under the share keys.
func TestDVShareBatch(t *testing.T) {
	e := newDVEnv(t)
	a, b := newDVShare(t), newDVShare(t)
	order := e.importOrder([]byte{1, 2}, a.group, func(o *importorder.Body) {
		o.T, o.N, o.ShareIndex = 3, 4, 2
		o.Validators = []importorder.Entry{
			{Pubkey: a.group, CommitmentsHash: importorder.CommitmentsHash(a.commitments)},
			{Pubkey: b.group, CommitmentsHash: importorder.CommitmentsHash(b.commitments)}}
		if string(b.group[:]) < string(a.group[:]) {
			o.Validators[0], o.Validators[1] = o.Validators[1], o.Validators[0]
		}
	})
	reqs := []backend.SealedImportRequest{e.dvRequest(a, a.sk, 2), e.dvRequest(b, b.sk, 2)}
	for i := range reqs {
		reqs[i].Order = nil
	}
	p, err := wireadmin.EncodeImportBatch(order, reqs)
	if err != nil {
		t.Fatal(err)
	}
	out, err := e.srv.dispatch(ctx, wire.Frame{Type: wireadmin.TypeImportBatch, Payload: p})
	if err != nil {
		t.Fatalf("batch: %v", err)
	}
	keys, err := wire.DecodeKeys(out)
	if err != nil || len(keys) != 2 || keys[0].Pubkey != a.pk || keys[1].Pubkey != b.pk {
		t.Fatalf("batch keys %+v, %v", keys, err)
	}
	if err := e.signMsg(b.pk, e.groupContribution(b.groupSk, b.group)); err != nil {
		t.Fatalf("contribution of the batch's second key: %v", err)
	}
	e.restart()
	if !hasKey(e.srv.Signer.Keys(), a.pk) || !hasKey(e.srv.Signer.Keys(), b.pk) {
		t.Fatal("the batch's keys did not load after a restart")
	}
}

// A dv_share key exists only with its group key: a key added without one
// (the debug plain import's path) is refused, and so is a stored record
// without one, or a record with one under another mode.
func TestDVShareNeedsGroupKey(t *testing.T) {
	e := newDVEnv(t)
	sk, pk := newKey(t)
	if _, err := e.srv.addShare(pk, &sk, 1, nil, "plaintext"); backend.StatusOf(err) != backend.StatusBadKey || !strings.Contains(err.Error(), "group key") {
		t.Fatalf("dv_share key without a group key: %v, want BAD_KEY", err)
	}
	blob, err := e.srv.sealRecord(shareRecord{Pubkey: pk, Secret: sk[:], Index: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.srv.putShare(pk, blob); err != nil {
		t.Fatal(err)
	}
	if n, err := e.srv.LoadListedShares([]string{shareKey(pk)}); n != 0 || err == nil || !strings.Contains(err.Error(), "group key") {
		t.Fatalf("load of a dv_share record without a group key: %d, %v", n, err)
	}

	single := newTgtEnv(t, "dev", nil)
	_, gpk := newKey(t)
	blob, err = single.srv.sealRecord(shareRecord{Pubkey: pk, Secret: sk[:], Index: 1, GroupPubkey: &gpk})
	if err != nil {
		t.Fatal(err)
	}
	if err := single.srv.putShare(pk, blob); err != nil {
		t.Fatal(err)
	}
	if n, err := single.srv.LoadListedShares([]string{shareKey(pk)}); n != 0 || err == nil || !strings.Contains(err.Error(), "group key") {
		t.Fatalf("load of a single-mode record with a group key: %d, %v", n, err)
	}
}

// The order's split check holds in dv_share mode: a share that is not the
// commitments' value at its index is refused, so the group key the runner
// keeps is the one the share belongs to.
func TestDVShareWrongIndexRefused(t *testing.T) {
	e := newDVEnv(t)
	d := newDVShare(t)
	// The share of index 3 sent under an order for index 2.
	req := e.dvRequest(d, d.otherSk, d.index)
	p, err := wireadmin.EncodeImportSealed(&req)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.srv.dispatch(ctx, wire.Frame{Type: wireadmin.TypeImportSealed, Payload: p})
	if backend.StatusOf(err) != backend.StatusBadKey || hasKey(e.srv.Signer.Keys(), d.otherPk) {
		t.Fatalf("share of another index: %v, want BAD_KEY", err)
	}
}
