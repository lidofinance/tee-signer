//go:build (peer_azure || peer_aws || peer_gcp || peer_dev) && !debugimport

package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	"github.com/lidofinance/tee-signer/governance/dkgorder"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/dev"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/sealedimport"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
	"github.com/lidofinance/tee-signer/slashing-log"
	"github.com/lidofinance/tee-signer/tee-signer/handover"
	"github.com/lidofinance/tee-signer/tee-signer/handoverorder"
	"github.com/lidofinance/tee-signer/tee-signer/state"
)

// Tests of IMPORT_HANDOVER on a dev runner with a setup of handover
// generation 2 and the mark log. The source is made up here with the
// encodings of package handover: shares sealed to the target's import key
// under their header and the carry's hash, an origin key per source
// process that signs each header, and a dev document that proves the key
// for the order.

// devDoc is the dev platform's document over nonce and userData.
func devDoc(nonce, userData []byte) *backend.Attestation {
	doc, _ := json.Marshal(map[string]any{"nonce": nonce, "user_data": userData})
	return &backend.Attestation{Platform: "dev", Format: "dev-json", UserData: userData, Document: doc}
}

// devDocAttester answers like the dev platform, without hashing the test
// binary.
type devDocAttester struct{}

func (devDocAttester) Attest(_ context.Context, nonce, userData []byte) (*backend.Attestation, error) {
	return devDoc(nonce, userData), nil
}

// tgtEnv is a handover target whose store and mark log outlive restarts.
type tgtEnv struct {
	t        *testing.T
	raw      []byte
	setup    *setupwire.Setup
	hash     [32]byte
	dir      string
	clock    *fakeClock
	store    *shareStore
	sealer   platform.Sealer
	platName string
	fl       *markstore.FileLog
	marks    *markstore.MarkLog
	hooks    *state.Hooks
	upd      *Updates
	signer   *core.Signer
	srv      *Server
}

// newTgtEnv starts a target with the dev sample setup at handover
// generation 2: approvers 1 to 3, k = 2, max_keys 1024, changed by change.
func newTgtEnv(t *testing.T, platName string, change func(s *setupwire.Setup)) *tgtEnv {
	t.Helper()
	if !runnerclient.Available(runnerclient.VerifierDev) {
		t.Skip("the made-up source has a dev document: build with peer_dev (the dev key generation runner's tags)")
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "governance", "setupwire", "testdata", "setup-dev.bin"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := setupwire.DecodeSetup(raw)
	if err != nil {
		t.Fatal(err)
	}
	s.HandoverGeneration, s.MaxKeys, s.SlashingLogMinLockDays = 2, 1024, 100
	s.Locked.Approvers = approverSet(2, 1, 2, 3)
	if change != nil {
		change(s)
	}
	if raw, err = s.Encode(); err != nil {
		t.Fatal(err)
	}
	e := &tgtEnv{t: t, raw: raw, setup: s, hash: mustHash(t, s), dir: t.TempDir(), platName: platName,
		clock: &fakeClock{t: time.Unix(testGenesis+startEpoch*testEpoch+5, 0), trusted: true},
		store: &shareStore{m: map[string][]byte{}}, sealer: dev.NewDevSealer()}
	e.start()
	return e
}

// start is a runner's start as main does it with the mark log: list the
// shares, claim the log, the config in force, the core with the device
// mark, a new import key, load the listed shares, the import on.
func (e *tgtEnv) start() {
	t := e.t
	t.Helper()
	ms, err := markstore.SetupOf(e.setup, e.hash)
	if err != nil {
		t.Fatal(err)
	}
	if e.fl, err = markstore.NewFileLog(filepath.Join(e.dir, "marks")); err != nil {
		t.Fatal(err)
	}
	m, err := markstore.New(e.fl, e.setup.SignerName, dev.NewDevKeys("handover import test"), markstore.Options{Setup: ms, Clock: e.clock.Now, Log: quiet})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := ListShares(e.store)
	if err != nil {
		t.Fatal(err)
	}
	mark, found, err := m.Claim(ctx, len(stored) > 0)
	if err != nil {
		t.Fatal(err)
	}
	e.marks = m
	if e.upd, err = NewUpdates(UpdatesOptions{Setup: e.setup, SetupHash: e.hash, Log: m, Clock: e.clock, Logger: quiet}); err != nil {
		t.Fatal(err)
	}
	cfg, err := e.upd.StartConfig(baseConfig(e.setup))
	if err != nil {
		t.Fatal(err)
	}
	cfg.DeviceMark = true
	if e.hooks, err = state.New(cfg, state.Mode{Floor: true, FloorMargin: state.DefaultFloorMargin(cfg), MarkLog: true}, e.clock, e.store, e.sealer, quiet); err != nil {
		t.Fatal(err)
	}
	e.hooks.UseMarkLog(m, mark, found)
	if e.signer, err = core.NewSigner(cfg, 2048, 0, e.hooks); err != nil {
		t.Fatal(err)
	}
	e.hooks.UseClock(e.signer.EpochAt)
	t.Cleanup(e.signer.Close)
	e.upd.Attach(e.signer)
	e.srv = &Server{Signer: e.signer, Hooks: e.hooks, Log: quiet, Updates: e.upd, State: e.upd.SetupState,
		Platform:  &platform.Platform{Name: e.platName, Store: e.store, Sealer: e.sealer, Clock: e.clock, Attester: devDocAttester{}},
		SetupHash: e.hash, LogID: m.LogID()}
	if e.srv.ImportKey, err = sealedimport.Generate(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.LoadListedShares(stored); err != nil {
		t.Fatal(err)
	}
	// As main does it: the source side first, then the import.
	if err := e.srv.EnableHandoverSource(HandoverSourceOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.EnableHandoverImport(HandoverImportOptions{}); err != nil {
		t.Fatal(err)
	}
}

func (e *tgtEnv) restart() {
	e.t.Helper()
	e.signer.Close()
	e.start()
}

func (e *tgtEnv) now() uint64 { t, _ := e.clock.Now(); return uint64(t.Unix()) }

// sealTo is the target's import key as a source seals to it.
func (e *tgtEnv) sealTo() *backend.Identity {
	id := &backend.Identity{}
	e.srv.ImportKey.Fill(id)
	return id
}

// order is a handover order to this target from a dev source, signed by
// the approvers ids, changed by change.
func (e *tgtEnv) order(ids []byte, change func(b *handoverorder.Body)) ([]byte, [32]byte) {
	e.t.Helper()
	b := handoverorder.Body{ClusterID: e.setup.ClusterID, ChainHash: e.setup.Chain.Hash(), NotAfter: e.now() + 12*3600,
		Source: handoverorder.Runner{Name: "signer-1", SetupHash: [32]byte{0x5e}, Verifier: dkgorder.VerifierDev},
		Target: handoverorder.Runner{Name: "signer-1b", SetupHash: e.hash, Verifier: dkgorder.VerifierDev}}
	if change != nil {
		change(&b)
	}
	enc, err := b.Encode()
	if err != nil {
		e.t.Fatal(err)
	}
	o := handoverorder.Order{Body: b}
	for _, id := range ids {
		o.Approvals = append(o.Approvals, setupwire.Approval{Position: id - 1, Signature: handoverorder.SignBody(approver(id), enc)})
	}
	raw, err := o.Encode()
	if err != nil {
		e.t.Fatal(err)
	}
	return raw, handoverorder.Hash(enc)
}

// imp sends one IMPORT_HANDOVER.
func (e *tgtEnv) imp(order []byte, page *handover.Response, flags uint8) (*handover.ImportResponse, error) {
	e.t.Helper()
	p, err := (&handover.ImportRequest{Flags: flags, Order: order, Page: page}).Encode()
	if err != nil {
		e.t.Fatal(err)
	}
	body, err := e.srv.dispatch(ctx, wire.Frame{Type: handover.TypeImport, Payload: p})
	if err != nil {
		return nil, err
	}
	r, err := handover.DecodeImportResponse(body)
	if err != nil {
		e.t.Fatal(err)
	}
	return r, nil
}

func (e *tgtEnv) mustImp(order []byte, page *handover.Response, flags uint8) *handover.ImportResponse {
	e.t.Helper()
	r, err := e.imp(order, page, flags)
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

// attest signs an attestation of pk for source and target.
func (e *tgtEnv) attest(pk backend.Pubkey, source, target uint64) error {
	m := &backend.AttestationData{Slot: target * 8, Source: backend.Checkpoint{Epoch: source}, Target: backend.Checkpoint{Epoch: target}}
	cfg := e.signer.Config()
	d, err := cfg.MessageDomain(m)
	if err != nil {
		e.t.Fatal(err)
	}
	_, err = e.srv.sign(backend.SignRequest{Pubkey: pk, Message: m, Domain: d})
	return err
}

// records are the target's mark log records, oldest first.
func (e *tgtEnv) records() []*markstore.Record {
	e.t.Helper()
	es, err := e.fl.List(ctx, markstore.Prefix(e.hash, e.setup.SignerName))
	if err != nil {
		e.t.Fatal(err)
	}
	var out []*markstore.Record
	for _, en := range es {
		b, err := e.fl.Get(ctx, en)
		if err != nil {
			e.t.Fatal(err)
		}
		r, err := markstore.Parse(b)
		if err != nil {
			continue // a hint or a body
		}
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b *markstore.Record) int { return int(a.Version) - int(b.Version) })
	return out
}

// refusedWith wants a refusal of code whose detail holds want.
func refusedImport(t *testing.T, err error, code backend.Status, want string) {
	t.Helper()
	var r *backend.RefusedError
	if !errors.As(err, &r) || r.Code != code || !strings.Contains(r.Detail, want) {
		t.Fatalf("got %v, want %v with %q", err, code, want)
	}
}

// srcShare is one share of the made-up source.
type srcShare struct {
	pk, share backend.Pubkey
	secret    [32]byte
	index     uint64
	origin    uint8
	order     [32]byte
}

// source is a made-up HANDOVER source: its shares, the mark and the
// origin key of its process.
type source struct {
	t         *testing.T
	shares    []srcShare
	mark      backend.Watermark
	originKey ed25519.PrivateKey
	nonce     []byte
}

// newSource has gen shares made in key generation, split between the DKG
// orders orders (a zero order: a policy file), then imp imported ones.
func newSource(t *testing.T, gen, imp int, orders [][32]byte, mark backend.Watermark) *source {
	t.Helper()
	src := &source{t: t, mark: mark, nonce: []byte("handover-import-test-nonce-0001")}
	_, src.originKey, _ = ed25519.GenerateKey(rand.Reader)
	for i := range gen + imp {
		sk, _ := software.NewSecret()
		other, _ := software.NewSecret()
		pk, _ := core.PubkeyOf(other) // the validator key; sk is its share
		sp, _ := core.PubkeyOf(sk)
		sh := srcShare{pk: pk, share: sp, secret: sk, index: uint64(100 + i), origin: handover.OriginImported}
		if i < gen {
			sh.origin, sh.order = handover.OriginGenerated, orders[i%len(orders)]
		}
		src.shares = append(src.shares, sh)
	}
	slices.SortFunc(src.shares, func(a, b srcShare) int { return bytes.Compare(a.pk[:], b.pk[:]) })
	return src
}

// proof is the origin proof of the source's key for the order.
func (src *source) proof(orderHash [32]byte) handover.OriginProof {
	key := [32]byte(src.originKey.Public().(ed25519.PublicKey))
	return handover.OriginProof{Key: key, Nonce: src.nonce, Attestation: devDoc(src.nonce, handover.OriginUserData(orderHash, key))}
}

// pages seals every share to to, per shares a page, as the source answers
// HANDOVER.
func (src *source) pages(to *backend.Identity, orderHash [32]byte, per int) []*handover.Response {
	src.t.Helper()
	var ic *backend.Watermark
	if src.mark.HasBlock || src.mark.HasAttestation {
		m := src.mark
		ic = &m
	}
	keys := make([]backend.ValidatorKey, len(src.shares))
	for i, sh := range src.shares {
		keys[i] = backend.ValidatorKey{Pubkey: sh.pk, SharePubkey: sh.share}
	}
	carry := handover.Carry{Set: handover.SetOf(keys)}
	ch, err := carry.Hash()
	if err != nil {
		src.t.Fatal(err)
	}
	var out []*handover.Response
	for start := 0; start < len(src.shares); start += per {
		r := &handover.Response{Mark: src.mark, Total: uint32(len(src.shares)), Origin: src.proof(orderHash), Carry: carry}
		for _, sh := range src.shares[start:min(start+per, len(src.shares))] {
			x := handover.Share{SealedImportRequest: backend.SealedImportRequest{Pubkey: sh.pk, SharePubkey: sh.share, Index: sh.index, Interchange: ic},
				Origin: sh.origin, Order: sh.order}
			if x.Sealed, err = sealedimport.SealAAD(to, x.AAD(ch), &sh.secret); err != nil {
				src.t.Fatal(err)
			}
			x.SignOrigin(src.originKey)
			r.Shares = append(r.Shares, x)
		}
		// Through the wire form, as the tool reads a page from its file.
		enc, err := r.Encode()
		if err != nil {
			src.t.Fatal(err)
		}
		if r, err = handover.DecodeResponse(enc); err != nil {
			src.t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

// testMark is a source's mark: it signed up to target epoch 1004.
var testMark = backend.Watermark{HasAttestation: true, SourceEpoch: startEpoch + 3, TargetEpoch: startEpoch + 4, HasBlock: true, BlockSlot: (startEpoch+4)*8 + 7}

// The whole import: the target signs nothing from the first share on, the
// mark log is raised to the mark before any share is stored, every share
// keeps its key origin, and the target signs again above the mark once
// the last share is in. Sending the pages again stores nothing.
func TestHandoverImport(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	d1, d2 := [32]byte{0xd1}, [32]byte{0xd2}
	src := newSource(t, 290, 10, [][32]byte{d1, d2, {}}, testMark)
	order, hash := e.order([]byte{1, 2}, nil)

	// Before: version 0, no key, the first record holds version 0 of both
	// groups, which is the source's config handed over in the setup.
	recs := e.records()
	if len(recs) != 1 || recs[0].State.Locked.Version != 0 || recs[0].State.Open.Version != 0 || recs[0].State.Order != nil {
		t.Fatalf("first record %+v", recs)
	}
	lh, _ := e.setup.GroupHash(locked)
	oh, _ := e.setup.GroupHash(open)
	if recs[0].State.Locked.Hash != lh || recs[0].State.Open.Hash != oh {
		t.Fatalf("first record names groups %x and %x, the setup's are %x and %x",
			recs[0].State.Locked.Hash[:8], recs[0].State.Open.Hash[:8], lh[:8], oh[:8])
	}

	pages := src.pages(e.sealTo(), hash, handover.MaxPerResponse)
	if len(pages) != 2 {
		t.Fatalf("%d pages", len(pages))
	}
	r := e.mustImp(order, pages[0], 0)
	if r.Done || r.Held != handover.MaxPerResponse || r.Total != 300 || len(r.Outcomes) != handover.MaxPerResponse {
		t.Fatalf("first page: %+v", r)
	}
	for _, o := range r.Outcomes {
		if o != handover.Stored {
			t.Fatalf("outcome %d", o)
		}
	}
	// Mid-import: nothing is signed, HEALTH is not ready, IDENTITY shows
	// the order in the slot, the log holds the mark.
	e.clock.add(8 * testEpoch)
	refusedImport(t, e.attest(src.shares[0].pk, startEpoch+7, startEpoch+8), backend.StatusNotReady, "handover import")
	if h, _ := e.srv.health(); h.Ready {
		t.Fatal("ready mid-import")
	}
	id := identityOf(t, e.srv, []byte("n-0123456789abcdef"))
	if id.State.Order.Kind != uint8(markstore.OrderHandover) || id.State.Order.Hash != hash {
		t.Fatalf("IDENTITY's order slot %+v", id.State.Order)
	}
	if m := e.marks.State(); m.Order == nil || m.Order.Hash != hash {
		t.Fatalf("log state %+v", m)
	}
	recs = e.records()
	raised := slices.IndexFunc(recs, func(r *markstore.Record) bool { return r.Mark == testMark })
	slot := slices.IndexFunc(recs, func(r *markstore.Record) bool { return r.State.Order != nil })
	if raised < 0 || slot < 0 || slot > raised {
		t.Fatalf("records: slot at %d, mark at %d", slot, raised)
	}

	r = e.mustImp(order, pages[1], 0)
	if !r.Done || r.Held != 300 || r.Generated != 290 || r.Imported != 10 {
		t.Fatalf("second page: %+v", r)
	}
	st := e.srv.SetupState()
	want := backend.KeyOrigin{Generated: 290, Imported: 10}
	var orders [][32]byte
	for _, sh := range src.shares {
		if sh.origin == handover.OriginGenerated && sh.order != ([32]byte{}) {
			orders = append(orders, sh.order)
		}
	}
	want.OrdersHash = backend.KeygenOrdersHash(orders)
	if st.KeyOrigin != want || st.Order.Kind != 0 {
		t.Fatalf("after the import: key origin %+v, order %+v; want %+v", st.KeyOrigin, st.Order, want)
	}
	// Signing: at or below the mark refused, above it signed.
	pk := src.shares[0].pk
	if err := e.attest(pk, startEpoch+3, startEpoch+4); err == nil {
		t.Fatal("signed at the handed-over mark")
	}
	if err := e.attest(pk, startEpoch+7, startEpoch+8); err != nil {
		t.Fatalf("above the mark: %v", err)
	}
	// The pages again: every share held, nothing written.
	n := len(e.records())
	for _, p := range pages {
		r := e.mustImp(order, p, 0)
		if !r.Done || slices.ContainsFunc(r.Outcomes, func(o uint8) bool { return o != handover.Held }) {
			t.Fatalf("again: %+v", r)
		}
	}
	if len(e.records()) != n {
		t.Fatal("the pages again wrote records")
	}

	// A restart reads every share with its origin, and the mark.
	e.restart()
	if st := e.srv.SetupState(); st.KeyOrigin != want || len(e.signer.Keys()) != 300 {
		t.Fatalf("after a restart: %+v, %d keys", st.KeyOrigin, len(e.signer.Keys()))
	}
	if err := e.attest(pk, startEpoch+3, startEpoch+4); err == nil {
		t.Fatal("signed at the handed-over mark after a restart")
	}
}

// A restart mid-import: the slot holds, so nothing is signed; the pages
// sealed for the old boot do not open; sealed again for the new import key,
// the import goes on, skips what is in and ends.
func TestHandoverImportRestart(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	src := newSource(t, 20, 0, [][32]byte{{0xd1}}, testMark)
	order, hash := e.order([]byte{2, 3}, nil)
	pages := src.pages(e.sealTo(), hash, 8)
	e.mustImp(order, pages[0], 0)
	e.restart()
	e.clock.add(10 * testEpoch)
	refusedImport(t, e.attest(src.shares[0].pk, startEpoch+9, startEpoch+10), backend.StatusNotReady, "handover import")
	if id := identityOf(t, e.srv, []byte("n-0123456789abcdef")); id.State.Order.Hash != hash {
		t.Fatal("the slot did not survive the restart")
	}
	_, err := e.imp(order, pages[1], 0)
	refusedImport(t, err, backend.StatusBadKey, "identity again")

	pages = src.pages(e.sealTo(), hash, 8)
	var last *handover.ImportResponse
	for i, p := range pages {
		last = e.mustImp(order, p, 0)
		if i == 0 && slices.ContainsFunc(last.Outcomes, func(o uint8) bool { return o != handover.Held }) {
			t.Fatalf("the first page again: %+v", last)
		}
	}
	if !last.Done || last.Held != 20 || last.Generated != 20 {
		t.Fatalf("after the restart: %+v", last)
	}
	if err := e.attest(src.shares[0].pk, startEpoch+9, startEpoch+10); err != nil {
		t.Fatal(err)
	}
}

// A few requests at once, as the tool sends them: each share is stored
// once, the import ends once.
func TestHandoverImportParallel(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	src := newSource(t, 60, 4, [][32]byte{{0xd1}}, testMark)
	order, hash := e.order([]byte{1, 3}, nil)
	pages := src.pages(e.sealTo(), hash, 4)
	var wg sync.WaitGroup
	errs := make(chan error, len(pages))
	for _, p := range pages {
		wg.Go(func() {
			if _, err := e.imp(order, p, 0); err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	r := e.mustImp(order, pages[0], 0)
	if !r.Done || r.Held != 64 || r.Generated != 60 || r.Imported != 4 {
		t.Fatalf("%+v", r)
	}
	slots := 0
	for _, rec := range e.records() {
		if rec.State.Order != nil {
			slots++
		}
	}
	if slots == 0 || e.marks.State().Order != nil {
		t.Fatalf("slot records %d, slot now %+v", slots, e.marks.State().Order)
	}
}

// What breaks the contract is refused, and nothing is stored.
func TestHandoverImportRefusals(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	src := newSource(t, 4, 1, [][32]byte{{0xd1}}, testMark)
	order, hash := e.order([]byte{1, 2}, nil)
	page := src.pages(e.sealTo(), hash, 8)[0]
	none := func() {
		t.Helper()
		if n := len(e.signer.Keys()); n != 0 || e.srv.importing() != nil {
			t.Fatalf("refused, but %d keys are in, slot %+v", n, e.srv.importing())
		}
	}
	for _, c := range []struct {
		name  string
		order func() []byte
		want  string
	}{
		{"another target", func() []byte {
			o, _ := e.order([]byte{1, 2}, func(b *handoverorder.Body) { b.Target.SetupHash = [32]byte{0x77} })
			return o
		}, "hands over to setup"},
		{"another cluster", func() []byte {
			o, _ := e.order([]byte{1, 2}, func(b *handoverorder.Body) { b.ClusterID = [32]byte{0x77} })
			return o
		}, "another cluster_id"},
		{"another chain", func() []byte {
			o, _ := e.order([]byte{1, 2}, func(b *handoverorder.Body) { b.ChainHash = [32]byte{0x77} })
			return o
		}, "another chain"},
		{"one approver", func() []byte { o, _ := e.order([]byte{3}, nil); return o }, "approvals_needed is 2"},
		{"a rotated set", func() []byte {
			b, _ := handoverorder.Decode(order)
			enc, _ := b.Body.Encode()
			b.Approvals = []setupwire.Approval{{Position: 0, Signature: handoverorder.SignBody(approver(7), enc)},
				{Position: 1, Signature: handoverorder.SignBody(approver(8), enc)}}
			raw, _ := b.Encode()
			return raw
		}, "does not verify"},
	} {
		_, err := e.imp(c.order(), page, 0)
		refusedImport(t, err, backend.StatusBadRequest, c.want)
		none()
	}

	// The origin: a proof for another order, a header signed by another
	// key, the dev verifier off the dev platform.
	bad := *page
	bad.Origin = src.proof([32]byte{0x99})
	_, err := e.imp(order, &bad, 0)
	refusedImport(t, err, backend.StatusBadKey, "origin proof")
	none()
	bad = *page
	bad.Shares = slices.Clone(page.Shares)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	bad.Shares[1].SignOrigin(other)
	_, err = e.imp(order, &bad, 0)
	refusedImport(t, err, backend.StatusBadRequest, "origin signature")
	none()

	// The mark lowered by whoever passes the pages on: the header is in
	// the associated data, so the share does not open.
	low := *page
	low.Mark = backend.Watermark{HasAttestation: true, SourceEpoch: 1, TargetEpoch: 2}
	low.Shares = slices.Clone(page.Shares)
	for i := range low.Shares {
		m := low.Mark
		low.Shares[i].Interchange = &m
		low.Shares[i].SignOrigin(src.originKey)
	}
	_, err = e.imp(order, &low, 0)
	refusedImport(t, err, backend.StatusBadKey, "open failed")
	none()

	// Sealed to another runner's key.
	k2, _ := sealedimport.Generate()
	id2 := &backend.Identity{}
	k2.Fill(id2)
	_, err = e.imp(order, src.pages(id2, hash, 8)[0], 0)
	refusedImport(t, err, backend.StatusBadKey, "open failed")
	none()

	// The good page goes in; then a second order and another mark are
	// refused, and so are a plain sealed import and a sign request.
	if r := e.mustImp(order, page, 0); !r.Done {
		t.Fatalf("%+v", r)
	}
	other2 := newSource(t, 1, 0, [][32]byte{{0xd1}}, testMark)
	o2, h2 := e.order([]byte{1, 2}, func(b *handoverorder.Body) { b.NotAfter++ })
	_, err = e.imp(o2, other2.pages(e.sealTo(), h2, 8)[0], 0)
	refusedImport(t, err, backend.StatusBadRequest, "empty runner only")
}

// The runner's state before the first share: an empty target at version 0
// of a generation 2 setup only.
func TestHandoverImportNeedsAnEmptyTarget(t *testing.T) {
	src := newSource(t, 2, 0, [][32]byte{{0xd1}}, testMark)

	gen1 := newTgtEnv(t, "dev", func(s *setupwire.Setup) { s.HandoverGeneration = 1 })
	order, hash := gen1.order([]byte{1, 2}, nil)
	_, err := gen1.imp(order, src.pages(gen1.sealTo(), hash, 8)[0], 0)
	refusedImport(t, err, backend.StatusBadRequest, "handover_generation 1")

	small := newTgtEnv(t, "dev", func(s *setupwire.Setup) { s.MaxKeys = 1 })
	order, hash = small.order([]byte{1, 2}, nil)
	_, err = small.imp(order, src.pages(small.sealTo(), hash, 8)[0], 0)
	refusedImport(t, err, backend.StatusBadRequest, "max_keys is 1")

	// A key imported before.
	e := newTgtEnv(t, "dev", nil)
	sk, _ := software.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	if _, err := e.srv.addShare(pk, &sk, 1, nil, "sealed"); err != nil {
		t.Fatal(err)
	}
	order, hash = e.order([]byte{1, 2}, nil)
	_, err = e.imp(order, src.pages(e.sealTo(), hash, 8)[0], 0)
	refusedImport(t, err, backend.StatusBadRequest, "empty runner only")

	// A config update pending.
	p := newTgtEnv(t, "dev", func(s *setupwire.Setup) { s.Locked.ChangeDelaySeconds = u64(600) })
	lh, _ := p.setup.GroupHash(locked)
	b := &setupwire.UpdateBody{ClusterID: p.setup.ClusterID, ChainHash: p.setup.Chain.Hash(), Group: locked, Version: 1, PrevHash: lh,
		ActivateAt: p.now(), Locked: &setupwire.Locked{}}
	*b.Locked = p.setup.Locked
	b.Locked.AllowedFeeRecipients = append(slices.Clone(b.Locked.AllowedFeeRecipients), x)
	slices.SortFunc(b.Locked.AllowedFeeRecipients, func(a, c backend.Address) int { return bytes.Compare(a[:], c[:]) })
	b.Salts = testSalts(b)
	if _, _, err := p.upd.Accept(ctx, signed(t, b, first2, nil)); err != nil {
		t.Fatal(err)
	}
	order, hash = p.order([]byte{1, 2}, nil)
	_, err = p.imp(order, src.pages(p.sealTo(), hash, 8)[0], 0)
	refusedImport(t, err, backend.StatusBadRequest, "pending")
}

// Off the dev platform the dev source's proof is refused; the operator can
// count every share as imported instead.
func TestHandoverImportAsImported(t *testing.T) {
	e := newTgtEnv(t, "nitro", nil)
	src := newSource(t, 5, 0, [][32]byte{{0xd1}}, testMark)
	order, hash := e.order([]byte{1, 2}, nil)
	page := src.pages(e.sealTo(), hash, 8)[0]
	_, err := e.imp(order, page, 0)
	refusedImport(t, err, backend.StatusBadKey, "-as-imported")
	r := e.mustImp(order, page, handover.ImportAsImported)
	if !r.Done || r.Generated != 0 || r.Imported != 5 {
		t.Fatalf("%+v", r)
	}
}

// A source that never signed hands over an empty mark: its shares carry no
// maxima and the target's log is not raised.
func TestHandoverImportEmptyMark(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	src := newSource(t, 3, 0, [][32]byte{{0xd1}}, backend.Watermark{})
	order, hash := e.order([]byte{1, 2}, nil)
	page := src.pages(e.sealTo(), hash, 8)[0]
	if page.Shares[0].Interchange != nil {
		t.Fatal("a share of an empty mark carries maxima")
	}
	if r := e.mustImp(order, page, 0); !r.Done {
		t.Fatalf("%+v", r)
	}
	for _, rec := range e.records() {
		if rec.Mark.HasAttestation || rec.Mark.HasBlock {
			t.Fatalf("a record with mark %+v", rec.Mark)
		}
	}
}

// Mid-import the runner takes the shares of its import only: no other
// order, no other mark, no plain sealed import, no key generation.
func TestHandoverImportMidway(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	src := newSource(t, 8, 0, [][32]byte{{0xd1}}, testMark)
	order, hash := e.order([]byte{1, 2}, nil)
	pages := src.pages(e.sealTo(), hash, 4)
	e.mustImp(order, pages[0], 0)

	o2, h2 := e.order([]byte{1, 2}, func(b *handoverorder.Body) { b.NotAfter++ })
	_, err := e.imp(o2, newSource(t, 1, 0, [][32]byte{{0xd1}}, testMark).pages(e.sealTo(), h2, 4)[0], 0)
	refusedImport(t, err, backend.StatusBadRequest, "takes no other order")

	higher := testMark
	higher.TargetEpoch++
	_, err = e.imp(order, newSource(t, 1, 0, [][32]byte{{0xd1}}, higher).pages(e.sealTo(), hash, 4)[0], 0)
	refusedImport(t, err, backend.StatusBadRequest, "this import has")

	sk, _ := software.NewSecret()
	sp, _ := core.PubkeyOf(sk)
	other, _ := software.NewSecret()
	pk, _ := core.PubkeyOf(other)
	req := backend.SealedImportRequest{Pubkey: pk, SharePubkey: sp, Index: 1}
	if req.Sealed, err = sealedimport.Seal(e.sealTo(), &req, &sk); err != nil {
		t.Fatal(err)
	}
	p, err := wireadmin.EncodeImportSealed(&req)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.srv.dispatch(ctx, wire.Frame{Type: wireadmin.TypeImportSealed, Payload: p})
	refusedImport(t, err, backend.StatusNotReady, "handover import")
	_, err = e.srv.AddGeneratedShares(nil, nil)
	refusedImport(t, err, backend.StatusNotReady, "handover import")

	if r := e.mustImp(order, pages[1], 0); !r.Done || r.Held != 8 {
		t.Fatalf("%+v", r)
	}
}
