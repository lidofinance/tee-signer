package core

import (
	"errors"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

const genesis = 1_000_000

// clockAtEpoch returns a fixed clock 5 s into epoch e of DevConfig(genesis, 12, 32).
func clockAtEpoch(e uint64) func() (uint64, error) {
	return func() (uint64, error) { return genesis + e*12*32 + 5, nil }
}

func newTestSigner(t *testing.T, hooks *MemHooks) (*Signer, backend.Pubkey, Config) {
	t.Helper()

	return newTestSignerWith(t, hooks, DevConfig(genesis, 12, 32))
}

func newTestSignerWith(t *testing.T, hooks *MemHooks, cfg Config) (*Signer, backend.Pubkey, Config) {
	t.Helper()
	if hooks.Clock == nil {
		hooks.Clock = clockAtEpoch(20)
	}
	s, err := NewSigner(cfg, 16, 16, hooks)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	sk, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	pk, err := PubkeyOf(sk)
	if err != nil {
		t.Fatal(err)
	}
	k, err := s.AddValidator(pk, sk, 7, nil)
	if err != nil {
		t.Fatal(err)
	}
	if k.SharePubkey != pk {
		t.Fatal("share pubkey of a full key should equal the key")
	}
	return s, pk, cfg
}

func att(source, target uint64) *backend.AttestationData {
	a := &backend.AttestationData{Slot: target * 32, BeaconBlockRoot: backend.Root{0xbb}}
	a.Source = backend.Checkpoint{Epoch: source, Root: backend.Root{0x5}}
	a.Target = backend.Checkpoint{Epoch: target, Root: backend.Root{0x7}}
	return a
}

// signReq is a request for m with the domain the signer's own config gives
// it, as a caller on the same fork sends it.
func signReq(s *Signer, pk backend.Pubkey, m backend.Message) backend.SignRequest {
	cfg := s.Config()
	d, _ := cfg.MessageDomain(m)
	return backend.SignRequest{Pubkey: pk, Message: m, Domain: d}
}

func wantStatus(t *testing.T, err error, want backend.Status) {
	t.Helper()
	if got := backend.StatusOf(err); got != want {
		t.Fatalf("got %v (%v), want %v", got, err, want)
	}
}

func TestStatusNamesMatchCore(t *testing.T) {
	for i := 0; i <= int(backend.StatusPolicyBuilderAuth); i++ {
		if got, want := StatusName(i), backend.Status(i).String(); got != want {
			t.Errorf("status %d: core says %s, Go says %s", i, got, want)
		}
	}
}

// Signing every kind and checking the signature against a signing root
// computed in Go cross-checks the Go SSZ code against the C core.
func TestSignAllKindsVerifies(t *testing.T) {
	cfg := DevConfig(genesis, 12, 32)
	cfg.AllowUnverifiedNonslashable = true // aggregates and contributions below
	s, pk, cfg := newTestSignerWith(t, NewMemHooks(), cfg)
	selection := backend.HashTreeRootUint64(20 * 32)
	msgs := []backend.Message{
		att(19, 20),
		&backend.BeaconBlockHeader{Slot: 20*32 + 3, ProposerIndex: 7, ParentRoot: backend.Root{1}, StateRoot: backend.Root{2}, BodyRoot: backend.Root{3}},
		&backend.VoluntaryExit{Epoch: 5, ValidatorIndex: 7},
		&backend.ValidatorRegistration{FeeRecipient: cfg.FeeRecipients[0], GasLimit: 36_000_000, Timestamp: genesis, Pubkey: pk},
		&backend.RootMessage{Type: backend.RootRandaoReveal, Epoch: 20, ObjectRoot: backend.HashTreeRootUint64(20), Domain: cfg.Domain(backend.DomainRandao, 20)},
		&backend.RootMessage{Type: backend.RootAggregationSlot, Epoch: 20, ObjectRoot: selection, Domain: cfg.Domain(backend.DomainSelectionProof, 20)},
		&backend.RootMessage{Type: backend.RootAggregateAndProof, Epoch: 20, ObjectRoot: backend.Root{9}, Domain: cfg.Domain(backend.DomainAggregateAndProof, 20)},
		&backend.RootMessage{Type: backend.RootSyncCommitteeMessage, Epoch: 20, ObjectRoot: backend.Root{8}, Domain: cfg.Domain(backend.DomainSyncCommittee, 20)},
		&backend.RootMessage{Type: backend.RootSyncCommitteeSelectionProof, Epoch: 20, ObjectRoot: backend.Root{7}, Domain: cfg.Domain(backend.DomainSyncCommitteeSelectionProof, 20)},
		&backend.RootMessage{Type: backend.RootSyncCommitteeContributionAndProof, Epoch: 20, ObjectRoot: backend.Root{6}, Domain: cfg.Domain(backend.DomainContributionAndProof, 20)},
	}
	for _, m := range msgs {
		sig, err := s.Sign(signReq(s, pk, m))
		if err != nil {
			t.Fatalf("%v: %v", m.Kind(), err)
		}
		root, err := cfg.SigningRoot(m)
		if err != nil {
			t.Fatal(err)
		}
		if !Verify(pk, root, sig) {
			t.Fatalf("%v %+v: signature does not verify against the Go signing root", m.Kind(), m)
		}
	}
	if got := s.Stats().Signatures; got != uint64(len(msgs)) {
		t.Fatalf("signatures = %d", got)
	}
}

func TestForkVersionSwitch(t *testing.T) {
	h := NewMemHooks()
	h.Clock = clockAtEpoch(9)
	s, pk, cfg := newTestSigner(t, h)
	// Epoch 9 uses the genesis version, epoch 10 the fork version.
	for _, a := range []*backend.AttestationData{att(8, 9), att(9, 10)} {
		sig, err := s.Sign(signReq(s, pk, a))
		if err != nil {
			t.Fatal(err)
		}
		root, _ := cfg.SigningRoot(a)
		if !Verify(pk, root, sig) {
			t.Fatalf("target %d: bad signature", a.Target.Epoch)
		}
	}
	if cfg.Domain(backend.DomainBeaconAttester, 9) == cfg.Domain(backend.DomainBeaconAttester, 10) {
		t.Fatal("domains across the fork should differ")
	}
}

func TestSlashingAndPolicyRefusals(t *testing.T) {
	s, pk, cfg := newTestSigner(t, NewMemHooks())
	sign := func(m backend.Message) error {
		_, err := s.Sign(signReq(s, pk, m))
		return err
	}
	if err := sign(att(18, 19)); err != nil {
		t.Fatal(err)
	}
	double := att(18, 19)
	double.BeaconBlockRoot = backend.Root{0xcc}
	wantStatus(t, sign(double), backend.StatusSlashTarget)
	wantStatus(t, sign(att(17, 20)), backend.StatusSlashSource) // would surround (18,19)
	wantStatus(t, sign(att(21, 20)), backend.StatusSlashSourceGtTarget)
	wantStatus(t, sign(att(19, 22)), backend.StatusPolicyFuture) // clock epoch 20 + 1

	blk := &backend.BeaconBlockHeader{Slot: 20 * 32, ProposerIndex: 7}
	if err := sign(blk); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, sign(&backend.BeaconBlockHeader{Slot: 20 * 32, ProposerIndex: 7, BodyRoot: backend.Root{1}}), backend.StatusSlashBlock)
	wantStatus(t, sign(&backend.BeaconBlockHeader{Slot: 20*32 + 1, ProposerIndex: 8}), backend.StatusPolicyIndex)

	wantStatus(t, sign(&backend.VoluntaryExit{Epoch: 5, ValidatorIndex: 8}), backend.StatusPolicyIndex)
	reg := &backend.ValidatorRegistration{FeeRecipient: backend.Address{0x22}, GasLimit: 36_000_000, Timestamp: genesis, Pubkey: pk}
	wantStatus(t, sign(reg), backend.StatusPolicyFeeRecipient)

	// Root messages: wrong domain, wrong RANDAO root, unknown type, future epoch.
	wantStatus(t, sign(&backend.RootMessage{Type: backend.RootRandaoReveal, Epoch: 20, ObjectRoot: backend.Root{20}, Domain: cfg.Domain(backend.DomainRandao, 5)}), backend.StatusDomainMismatch)
	wantStatus(t, sign(&backend.RootMessage{Type: backend.RootRandaoReveal, Epoch: 20, ObjectRoot: backend.Root{1}, Domain: cfg.Domain(backend.DomainRandao, 20)}), backend.StatusArg)
	wantStatus(t, sign(&backend.RootMessage{Type: 99, Epoch: 20}), backend.StatusUnsupported)
	wantStatus(t, sign(&backend.RootMessage{Type: backend.RootRandaoReveal, Epoch: 30, ObjectRoot: backend.Root{30}, Domain: cfg.Domain(backend.DomainRandao, 30)}), backend.StatusPolicyFuture)
}

// An exact repeat of the last attestation or block gets the same signature
// (the core signs the same root again) with no write; anything else at that
// target or slot is refused, and so is a repeat of an older message.
func TestExactRepeat(t *testing.T) {
	h := NewMemHooks()
	s, pk, _ := newTestSigner(t, h)
	sign := func(m backend.Message) (backend.Signature, bool, error) {
		return s.SignDetailed(signReq(s, pk, m))
	}
	first, rep, err := sign(att(18, 19))
	if err != nil || rep {
		t.Fatal(err, rep)
	}
	writes := h.Writes
	again, rep, err := sign(att(18, 19))
	if err != nil || !rep || again != first {
		t.Fatalf("repeat: rep=%v err=%v same=%v", rep, err, again == first)
	}
	if st := s.Stats(); h.Writes != writes || h.RootWrites != 0 || st.ExactRepeats != 1 || st.RepeatRootWrites != 0 {
		t.Fatalf("repeat must not write: writes %d->%d, root writes %d, %+v", writes, h.Writes, h.RootWrites, st)
	}
	other := att(18, 19)
	other.BeaconBlockRoot = backend.Root{0xcc}
	_, _, err = sign(other)
	wantStatus(t, err, backend.StatusSlashTarget)
	if _, _, err := sign(att(19, 20)); err != nil {
		t.Fatal(err)
	}
	_, _, err = sign(att(18, 19)) // no longer the last one
	if !backend.StatusOf(err).IsSlashing() {
		t.Fatalf("repeat of an older vote: %v", err)
	}

	blk := &backend.BeaconBlockHeader{Slot: 20 * 32, ProposerIndex: 7, BodyRoot: backend.Root{1}}
	b1, _, err := sign(blk)
	if err != nil {
		t.Fatal(err)
	}
	b2, rep, err := sign(&backend.BeaconBlockHeader{Slot: 20 * 32, ProposerIndex: 7, BodyRoot: backend.Root{1}})
	if err != nil || !rep || b1 != b2 {
		t.Fatalf("block repeat: %v %v", rep, err)
	}
	_, _, err = sign(&backend.BeaconBlockHeader{Slot: 20 * 32, ProposerIndex: 7, BodyRoot: backend.Root{2}})
	wantStatus(t, err, backend.StatusSlashBlock)
}

// persist_repeat_root across a restart (a second Signer on the same hooks).
// On: one root write per vote, and the repeat signs after the restart with
// the same signature, while another root at that target is refused. Off: no
// root writes, and the repeat is refused after the restart.
func TestRepeatAfterRestart(t *testing.T) {
	for _, persist := range []bool{true, false} {
		h := NewMemHooks()
		h.Clock = clockAtEpoch(20)
		cfg := DevConfig(genesis, 12, 32)
		cfg.PersistRepeatRoot = persist
		sk, _ := NewSecret()
		pk, _ := PubkeyOf(sk)
		start := func() *Signer {
			s, err := NewSigner(cfg, 4, 4, h)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.AddValidator(pk, sk, 7, nil); err != nil {
				t.Fatal(err)
			}
			return s
		}
		s1 := start()
		first, err := s1.Sign(signReq(s1, pk, att(18, 19)))
		if err != nil {
			t.Fatal(err)
		}
		blk := &backend.BeaconBlockHeader{Slot: 19*32 + 1, ProposerIndex: 7, BodyRoot: backend.Root{4}}
		bsig, err := s1.Sign(signReq(s1, pk, blk))
		if err != nil {
			t.Fatal(err)
		}
		wantRoots := 0
		if persist {
			wantRoots = 2
		}
		if h.RootWrites != wantRoots || s1.Stats().RepeatRootWrites != uint64(wantRoots) {
			t.Fatalf("persist=%v: root writes %d, stats %+v", persist, h.RootWrites, s1.Stats())
		}
		s1.Close()

		s2 := start()
		again, rep, err := s2.SignDetailed(signReq(s2, pk, att(18, 19)))
		bagain, brep, berr := s2.SignDetailed(signReq(s2, pk, blk))
		if persist {
			if err != nil || !rep || again != first || berr != nil || !brep || bagain != bsig {
				t.Fatalf("persist on: repeat after restart: %v %v %v %v", rep, err, brep, berr)
			}
		} else if !backend.StatusOf(err).IsSlashing() || !backend.StatusOf(berr).IsSlashing() {
			t.Fatalf("persist off: repeat after restart must be refused: %v %v", err, berr)
		}
		other := att(18, 19)
		other.BeaconBlockRoot = backend.Root{0xcc}
		if _, err := s2.Sign(signReq(s2, pk, other)); !backend.StatusOf(err).IsSlashing() {
			t.Fatalf("persist=%v: another root at target 19 after restart: %v", persist, err)
		}
		s2.Close()
	}

	// Without hooks that store roots the setting is refused.
	cfg := DevConfig(genesis, 12, 32)
	cfg.PersistRepeatRoot = true
	if _, err := NewSigner(cfg, 4, 4, marksOnly{NewMemHooks()}); err == nil {
		t.Fatal("persist_repeat_root accepted without RepeatRootHooks")
	}
}

// marksOnly hides MemHooks' repeat root methods.
type marksOnly struct{ m *MemHooks }

func (h marksOnly) LoadWatermark(pk backend.Pubkey) (backend.Watermark, bool, error) {
	return h.m.LoadWatermark(pk)
}
func (h marksOnly) StoreWatermark(pk backend.Pubkey, wm backend.Watermark) error {
	return h.m.StoreWatermark(pk, wm)
}
func (h marksOnly) Now() (uint64, error) { return h.m.Now() }

// A failed root write does not refuse the vote; after a restart the repeat
// is then refused (the root was in RAM only).
func TestRepeatRootWriteFailure(t *testing.T) {
	h := NewMemHooks()
	h.Clock = clockAtEpoch(20)
	h.FailRoots = true
	cfg := DevConfig(genesis, 12, 32)
	cfg.PersistRepeatRoot = true
	sk, _ := NewSecret()
	pk, _ := PubkeyOf(sk)
	s, err := NewSigner(cfg, 4, 4, h)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddValidator(pk, sk, 7, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sign(signReq(s, pk, att(18, 19))); err != nil {
		t.Fatalf("vote refused because the root write failed: %v", err)
	}
	if _, rep, err := s.SignDetailed(signReq(s, pk, att(18, 19))); err != nil || !rep {
		t.Fatalf("repeat in the same run: %v %v", rep, err)
	}
	s.Close()
	h.FailRoots = false
	s, _ = NewSigner(cfg, 4, 4, h)
	defer s.Close()
	if _, err := s.AddValidator(pk, sk, 7, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sign(signReq(s, pk, att(18, 19))); !backend.StatusOf(err).IsSlashing() {
		t.Fatalf("repeat after restart with no stored root: %v", err)
	}
}

// A validator whose index is not on the allowlist cannot exit.
func TestExitAllowlist(t *testing.T) {
	cfg := DevConfig(genesis, 12, 32)
	h := NewMemHooks()
	h.Clock = clockAtEpoch(20)
	s, err := NewSigner(cfg, 4, 0, h)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	sk, _ := NewSecret()
	pk, _ := PubkeyOf(sk)
	if _, err := s.AddValidator(pk, sk, 8, nil); err != nil {
		t.Fatal(err)
	}
	_, err = s.Sign(signReq(s, pk, &backend.VoluntaryExit{Epoch: 5, ValidatorIndex: 8}))
	wantStatus(t, err, backend.StatusPolicyExit)
}

type failingHooks struct {
	*MemHooks
	failStore bool
	failClock bool
}

func (f *failingHooks) StoreWatermark(pk backend.Pubkey, wm backend.Watermark) error {
	if f.failStore {
		return errors.New("disk on fire")
	}
	return f.MemHooks.StoreWatermark(pk, wm)
}

func (f *failingHooks) Now() (uint64, error) {
	if f.failClock {
		return 0, errors.New("no time")
	}
	return f.MemHooks.Now()
}

func TestHookFailuresRefuse(t *testing.T) {
	cfg := DevConfig(genesis, 12, 32)
	mh := NewMemHooks()
	mh.Clock = clockAtEpoch(20)
	h := &failingHooks{MemHooks: mh}
	s, err := NewSigner(cfg, 4, 0, h)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	sk, _ := NewSecret()
	pk, _ := PubkeyOf(sk)
	if _, err := s.AddValidator(pk, sk, 7, nil); err != nil {
		t.Fatal(err)
	}
	h.failStore = true
	_, err = s.Sign(signReq(s, pk, att(19, 20)))
	wantStatus(t, err, backend.StatusStorage)
	st, _ := s.State(pk)
	if st.RAM.HasAttestation {
		t.Fatal("failed store must leave the state unchanged")
	}
	h.failStore, h.failClock = false, true
	_, err = s.Sign(signReq(s, pk, att(19, 20)))
	wantStatus(t, err, backend.StatusClock)
	h.failClock = false
	if _, err := s.Sign(signReq(s, pk, att(19, 20))); err != nil {
		t.Fatal(err)
	}
}

func TestInterchangeImportOnAdd(t *testing.T) {
	cfg := DevConfig(genesis, 12, 32)
	h := NewMemHooks()
	h.Clock = clockAtEpoch(20)
	s, _ := NewSigner(cfg, 4, 0, h)
	defer s.Close()
	sk, _ := NewSecret()
	pk, _ := PubkeyOf(sk)
	wm := &backend.Watermark{HasAttestation: true, SourceEpoch: 18, TargetEpoch: 19, HasBlock: true, BlockSlot: 600}
	if _, err := s.AddValidator(pk, sk, 7, wm); err != nil {
		t.Fatal(err)
	}
	_, err := s.Sign(signReq(s, pk, att(18, 19)))
	wantStatus(t, err, backend.StatusSlashTarget)
	_, err = s.Sign(signReq(s, pk, &backend.BeaconBlockHeader{Slot: 600, ProposerIndex: 7}))
	wantStatus(t, err, backend.StatusSlashBlock)
	if _, err := s.Sign(signReq(s, pk, att(19, 20))); err != nil {
		t.Fatal(err)
	}
}

func TestWatermarkRecord(t *testing.T) {
	in := backend.Watermark{BlockSlot: 1, SourceEpoch: 2, TargetEpoch: 3, HasBlock: true, HasAttestation: true}
	rec := EncodeWatermark(in)
	if len(rec) != 32 {
		t.Fatal(len(rec))
	}
	out, err := DecodeWatermark(rec)
	if err != nil || out != in {
		t.Fatalf("%+v %v", out, err)
	}
	rec[0] ^= 1
	if _, err := DecodeWatermark(rec); err == nil {
		t.Fatal("corrupt record accepted")
	}
}

// 3-of-5: every 3-subset of partial signatures recovers a signature that
// verifies under the full public key.
func TestThresholdRecover(t *testing.T) {
	cfg := DevConfig(genesis, 12, 32)
	sk, _ := NewSecret()
	pk, _ := PubkeyOf(sk)
	shares, err := Split(sk, 3, 5)
	if err != nil {
		t.Fatal(err)
	}
	a := att(19, 20)
	root, _ := cfg.SigningRoot(a)
	sigs := map[uint64]backend.Signature{}
	sharePks := map[uint64]backend.Pubkey{}
	for _, sh := range shares {
		h := NewMemHooks()
		h.Clock = clockAtEpoch(20)
		s, err := NewSigner(cfg, 1, 0, h)
		if err != nil {
			t.Fatal(err)
		}
		k, err := s.AddValidator(pk, sh.Secret, 7, nil)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := s.Sign(signReq(s, pk, a))
		s.Close()
		if err != nil {
			t.Fatal(err)
		}
		if !Verify(k.SharePubkey, root, sig) {
			t.Fatalf("share %d: partial signature does not verify under the share key", sh.ID)
		}
		if Verify(pk, root, sig) {
			t.Fatalf("share %d: partial signature verifies under the full key", sh.ID)
		}
		sigs[sh.ID], sharePks[sh.ID] = sig, k.SharePubkey
	}
	subsets := 0
	for i := uint64(1); i <= 5; i++ {
		for j := i + 1; j <= 5; j++ {
			for k := j + 1; k <= 5; k++ {
				ids := []uint64{i, j, k}
				full, err := RecoverSignature(ids, []backend.Signature{sigs[i], sigs[j], sigs[k]})
				if err != nil {
					t.Fatal(err)
				}
				if !Verify(pk, root, full) {
					t.Fatalf("subset %v: recovered signature does not verify", ids)
				}
				rpk, err := RecoverPubkey(ids, []backend.Pubkey{sharePks[i], sharePks[j], sharePks[k]})
				if err != nil || rpk != pk {
					t.Fatalf("subset %v: recovered pubkey differs", ids)
				}
				subsets++
			}
		}
	}
	two, _ := RecoverSignature([]uint64{1, 2}, []backend.Signature{sigs[1], sigs[2]})
	if Verify(pk, root, two) {
		t.Fatal("2 shares must not be enough")
	}
	t.Logf("3-of-5: %d subsets recovered and verified", subsets)
}
