package core_test

import (
	"encoding/hex"
	"testing"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// Vectors from signer-core/tests/data/gloas_go.txt (go-eth2-client v0.30.1).
const (
	gloasEnv     = "30bc71b3e8dd60ae77517bab3080213d651f7bb1e0338702d489d8b9284cb29dc6cda01dcfac91c20fbf84f976d2d9c2dfce29fd58d023a3407a4ad601b96ada2ba74a62f8334f5dbd267e8ef16004de75a19887acada8858c89266a7410124cc01b3561856e8cfb5a3054be85ae2d8de6d97abc60b3a824ff1186d8864bd41bddc305e9cb22084d394fff4a8c11d01d776be53cc15a848d8ac51e866b83922dbf6632e807f73eb635a19aa352243a9c43cbdcfd44f3571d01ce103ca213070900000000390d610000000000c77f6da9ba6194eccf7a7a2f988352fda44faff5250a7d1f0e7797c65f9d434fe4c3a8397a53ad086adf9622fd59a4c55951f256d36b11412fb04258db5567737be8f3298a70ff15d409cd20d6f394a1cc61278942680e7c32a4ffb6c19ae78a6bc9d6995462e09f42ae357300285040e336b43dca714859615c310914976f23f9ae925652eeabe717d16965083dcf2115f6f8c95fe19e029cb3e7bbd0df628536b49dceb763e49e3850040000000000915b7a24c5228f49505e013bdc5a2fcfd8a0b894c88b386cfedc2939340db8fbfecbf62475ee3b4de69a0c00000000001aa96de167ed91c34f26683a2962141320926f6f125e8d0a20a19803f92ae26b222036938c84dce2e26b33814ce04fb508f417bb8277b1340c74403cc60955d9d831c7400e740c3a5c28f2df281678bcf11abe15e946bc8d8271efa82def9a258f62ae49afdabdc2"
	gloasEnvRoot = "11c446e37119f9f0c30cd657fdba6c1bc5886e36435452ef7eb338158ac82f6b"
	gloasPTC     = "763674ec79cfea8b8e1503fd9e1fffb8754f196def1adebde4133f2d7d37f55aad4df30bae771bdc0000"
	gloasPTCRoot = "94e388a6e676a7ccd6c85d27ad3a23d1f2a00b2cc9723e0095bb50cdb95f2dec"
)

const gloasEpoch = 15

// gloasSigner is newTestSigner with a Gloas fork at epoch 15 and the clock
// at epoch 20.
func gloasSigner(t *testing.T, hooks *software.MemHooks) (*core.Signer, backend.Pubkey, core.Config, [32]byte) {
	t.Helper()
	cfg := software.DevConfig(genesis, 12, 32)
	cfg.Forks = append(cfg.Forks, core.Fork{Epoch: gloasEpoch, Version: backend.Version{0x07, 0x00, 0x00, 0x01}})
	e := uint64(gloasEpoch)
	cfg.GloasForkEpoch = &e
	if hooks.Clock == nil {
		hooks.Clock = clockAtEpoch(20)
	}
	s, err := core.NewSigner(cfg, 16, 16, hooks)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	sk := [32]byte{0x11, 0x22, 0x33}
	pk, err := core.PubkeyOf(sk)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddValidator(pk, sk, 7, nil); err != nil {
		t.Fatal(err)
	}
	return s, pk, cfg, sk
}

func TestGloasRootsMatchGo(t *testing.T) {
	b, _ := hex.DecodeString(gloasEnv)
	m, err := backend.DecodeSSZ(backend.KindPayloadEnvelope, b)
	if err != nil {
		t.Fatal(err)
	}
	if enc, _ := backend.EncodeSSZ(m); hex.EncodeToString(enc) != gloasEnv {
		t.Fatal("envelope layout does not round trip")
	}
	if r, _ := backend.HashTreeRoot(m); hex.EncodeToString(r[:]) != gloasEnvRoot {
		t.Fatalf("envelope root %x", r)
	}
	b, _ = hex.DecodeString(gloasPTC)
	m, err = backend.DecodeSSZ(backend.KindPayloadAttestation, b)
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := backend.HashTreeRoot(m); hex.EncodeToString(r[:]) != gloasPTCRoot {
		t.Fatalf("PTC root %x", r)
	}
	b[40] = 2
	if _, err := backend.DecodeSSZ(backend.KindPayloadAttestation, b); err == nil {
		t.Fatal("boolean 2 accepted")
	}
}

func TestGloasSigning(t *testing.T) {
	s, pk, cfg, _ := gloasSigner(t, software.NewMemHooks())
	sign := func(m backend.Message) (backend.Signature, error) {
		return s.Sign(signReq(s, pk, m))
	}
	verify := func(m backend.Message, sig backend.Signature) {
		t.Helper()
		root, err := cfg.SigningRoot(m)
		if err != nil {
			t.Fatal(err)
		}
		if !core.Verify(pk, root, sig) {
			t.Fatalf("%v: signature does not verify against the Go signing root", m.Kind())
		}
	}

	ptc := &backend.PayloadAttestationData{BeaconBlockRoot: backend.Root{1}, Slot: 20*32 + 4, PayloadPresent: true}
	sig, err := sign(ptc)
	if err != nil {
		t.Fatal(err)
	}
	verify(ptc, sig)
	again, err := sign(ptc)
	if err != nil || again != sig {
		t.Fatalf("exact repeat: %v", err)
	}
	other := *ptc
	other.PayloadPresent = false
	_, err = sign(&other)
	wantStatus(t, err, backend.StatusEquivocation)
	if !backend.StatusEquivocation.IsSlashing() {
		t.Fatal("equivocation should count as slashing protection")
	}
	_, err = sign(&backend.PayloadAttestationData{Slot: (gloasEpoch-1)*32 + 31})
	wantStatus(t, err, backend.StatusPolicyFork)

	block := &backend.BeaconBlockHeader{Slot: 20*32 + 6, ProposerIndex: 7, ParentRoot: backend.Root{4}, BodyRoot: backend.Root{5}}
	env := &backend.PayloadEnvelope{BuilderIndex: backend.BuilderIndexSelfBuild, ParentBeaconBlockRoot: block.ParentRoot}
	env.Payload.SlotNumber = block.Slot
	env.Payload.FeeRecipient = cfg.FeeRecipients[0]
	env.BeaconBlockRoot, _ = backend.HashTreeRoot(block)
	_, err = sign(env)
	wantStatus(t, err, backend.StatusPolicyEnvelope)
	if _, err := sign(block); err != nil {
		t.Fatal(err)
	}
	env.BuilderIndex = 3
	_, err = sign(env)
	wantStatus(t, err, backend.StatusPolicyBuilder)
	env.BuilderIndex = backend.BuilderIndexSelfBuild
	if sig, err = sign(env); err != nil {
		t.Fatal(err)
	}
	verify(env, sig)
	env2 := *env
	env2.Payload.TransactionsRoot = backend.Root{9}
	_, err = sign(&env2)
	wantStatus(t, err, backend.StatusEquivocation)

	pref := &backend.ProposerPreferences{ProposalSlot: 21 * 32, ValidatorIndex: 7, FeeRecipient: cfg.FeeRecipients[0], TargetGasLimit: 45_000_000}
	if sig, err = sign(pref); err != nil {
		t.Fatal(err)
	}
	verify(pref, sig)
	pref.ValidatorIndex = 8
	_, err = sign(pref)
	wantStatus(t, err, backend.StatusPolicyIndex)
}

// Without gloas_fork_epoch the core refuses every Gloas message.
func TestGloasNotScheduled(t *testing.T) {
	s, pk, _ := newTestSigner(t, software.NewMemHooks())
	for _, m := range []backend.Message{
		&backend.PayloadAttestationData{Slot: 20 * 32},
		&backend.PayloadEnvelope{BuilderIndex: backend.BuilderIndexSelfBuild},
		&backend.ProposerPreferences{ProposalSlot: 20 * 32, ValidatorIndex: 7},
	} {
		_, err := s.Sign(signReq(s, pk, m))
		wantStatus(t, err, backend.StatusPolicyFork)
	}
	cfg := software.DevConfig(genesis, 12, 32)
	bad := uint64(11)
	cfg.GloasForkEpoch = &bad
	if err := cfg.Validate(); err == nil {
		t.Fatal("gloas_fork_epoch that is no fork epoch accepted")
	}
}

// The Gloas root types (stock Vouch through Dirk's generic Sign): refused
// with the unverified switch off; with it on, signed under the Gloas fork
// version from the fork epoch on and counted as unverified, refused before
// it and on a chain without Gloas.
func TestGloasUnverifiedRoots(t *testing.T) {
	types := []struct {
		typ backend.RootType
		dt  backend.DomainType
	}{
		{backend.RootPayloadAttestation, backend.DomainPTCAttester},
		{backend.RootPayloadEnvelope, backend.DomainBeaconBuilder},
		{backend.RootProposerPreferences, backend.DomainProposerPreferences},
	}
	for _, tt := range types {
		if dt, ok := tt.typ.DomainType(); !ok || dt != tt.dt || !tt.typ.Unverified() {
			t.Fatalf("root type %d: domain %x %v, unverified %v", tt.typ, dt, ok, tt.typ.Unverified())
		}
	}
	root := func(cfg core.Config, typ backend.RootType, dt backend.DomainType, epoch uint64) *backend.RootMessage {
		return &backend.RootMessage{Type: typ, Epoch: epoch, ObjectRoot: backend.Root{byte(typ), 0x42}, Domain: cfg.Domain(dt, epoch)}
	}

	// Switch off (gloasSigner uses DevConfig): refused, nothing counted.
	off, pk, cfg, _ := gloasSigner(t, software.NewMemHooks())
	for _, tt := range types {
		_, err := off.Sign(signReq(off, pk, root(cfg, tt.typ, tt.dt, 20)))
		wantStatus(t, err, backend.StatusPolicyDomain)
	}

	// Switch on.
	cfg.AllowUnverifiedNonslashable = true
	h := software.NewMemHooks()
	h.Clock = clockAtEpoch(20)
	on, err := core.NewSigner(cfg, 16, 16, h)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(on.Close)
	sk := [32]byte{0x11, 0x22, 0x33}
	if _, err := on.AddValidator(pk, sk, 7, nil); err != nil {
		t.Fatal(err)
	}
	for _, tt := range types {
		for _, epoch := range []uint64{gloasEpoch, 20, 21} {
			m := root(cfg, tt.typ, tt.dt, epoch)
			sig, err := on.Sign(signReq(on, pk, m))
			if err != nil {
				t.Fatalf("type %d epoch %d: %v", tt.typ, epoch, err)
			}
			sr, _ := cfg.SigningRoot(m)
			if !core.Verify(pk, sr, sig) {
				t.Fatalf("type %d epoch %d: signature does not verify", tt.typ, epoch)
			}
			// The Gloas fork version is in the domain.
			if m.Domain != backend.ComputeDomain(tt.dt, backend.Version{0x07, 0x00, 0x00, 0x01}, cfg.GenesisValidatorsRoot) {
				t.Fatalf("type %d: domain not of the Gloas fork version", tt.typ)
			}
		}
		// A second, different root at the same epoch signs too: the bare
		// root has no slot for the typed one-per-slot rule.
		m := root(cfg, tt.typ, tt.dt, 20)
		m.ObjectRoot[31] = 1
		if _, err := on.Sign(signReq(on, pk, m)); err != nil {
			t.Fatalf("type %d, second root: %v", tt.typ, err)
		}
		_, err := on.Sign(signReq(on, pk, root(cfg, tt.typ, tt.dt, gloasEpoch-1)))
		wantStatus(t, err, backend.StatusPolicyFork)
		_, err = on.Sign(signReq(on, pk, root(cfg, tt.typ, tt.dt, 22)))
		wantStatus(t, err, backend.StatusPolicyFuture)
		// The domain of another fork version or type is refused.
		bad := root(cfg, tt.typ, tt.dt, 20)
		bad.Domain = cfg.Domain(tt.dt, gloasEpoch-1)
		_, err = on.Sign(signReq(on, pk, bad))
		wantStatus(t, err, backend.StatusDomainMismatch)
		bad.Domain = cfg.Domain(backend.DomainBeaconAttester, 20)
		_, err = on.Sign(signReq(on, pk, bad))
		wantStatus(t, err, backend.StatusDomainMismatch)
	}
	if n := on.Stats().UnverifiedSignatures; n != 3*4 {
		t.Fatalf("unverified count %d, want 12", n)
	}

	// A chain without Gloas: refused at any epoch, switch on.
	plain := software.DevConfig(genesis, 12, 32)
	plain.AllowUnverifiedNonslashable = true
	ns, pk2, plain := newTestSignerWith(t, software.NewMemHooks(), plain)
	for _, tt := range types {
		_, err := ns.Sign(signReq(ns, pk2, root(plain, tt.typ, tt.dt, 20)))
		wantStatus(t, err, backend.StatusPolicyFork)
	}
}

// After a restart the PTC slot bound comes from the stored block bound.
func TestGloasRestart(t *testing.T) {
	h := software.NewMemHooks()
	s, pk, _, sk := gloasSigner(t, h)
	ptc := &backend.PayloadAttestationData{Slot: 20*32 + 4}
	if _, err := s.Sign(signReq(s, pk, ptc)); err != nil {
		t.Fatal(err)
	}
	cfg := s.Config()
	s.Close()
	// Same storage: a new signer on the same hooks.
	r, err := core.NewSigner(cfg, 16, 16, h)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.AddValidator(pk, sk, 7, nil); err != nil {
		t.Fatal(err)
	}
	_, err = r.Sign(signReq(r, pk, ptc))
	wantStatus(t, err, backend.StatusEquivocation)
	st, _ := r.State(pk)
	if !st.Committed.HasBlock || st.Committed.BlockSlot < ptc.Slot {
		t.Fatalf("stored block bound %+v does not cover the PTC slot", st.Committed)
	}
}
