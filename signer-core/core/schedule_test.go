package core

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

var nextVersion = backend.Version{0x09, 0x00, 0x00, 0x01}

// Every typed kind carries the caller's domain. A domain of another fork,
// another chain or none is refused before the core signs or writes anything;
// the domain the signer's own schedule gives signs.
func TestTypedDomainCheck(t *testing.T) {
	h := NewMemHooks()
	s, pk, cfg := newTestSigner(t, h)
	gs, gpk, gcfg, _ := gloasSigner(t, NewMemHooks())
	slot := uint64(20*32 + 3)
	proof := mustSign(t, s, pk, &backend.SelectionProof{Slot: slot})
	syncProof := mustSign(t, s, pk, &backend.SyncSelectionProof{Slot: slot, SubcommitteeIndex: 2})
	type signer struct {
		s   *Signer
		pk  backend.Pubkey
		cfg Config
	}
	plain, gloas := signer{s, pk, cfg}, signer{gs, gpk, gcfg}
	env := &backend.PayloadEnvelope{BuilderIndex: backend.BuilderIndexSelfBuild}
	env.Payload.SlotNumber = 20*32 + 1
	for _, c := range []struct {
		on signer
		m  backend.Message
	}{
		{plain, att(19, 20)},
		{plain, &backend.BeaconBlockHeader{Slot: 20*32 + 1, ProposerIndex: 7, BodyRoot: backend.Root{1}}},
		{plain, &backend.VoluntaryExit{Epoch: 5, ValidatorIndex: 7}},
		{plain, &backend.ValidatorRegistration{FeeRecipient: cfg.FeeRecipients[0], GasLimit: 36_000_000, Timestamp: genesis, Pubkey: pk}},
		{plain, &backend.SelectionProof{Slot: slot + 1}},
		{plain, &backend.AggregateAndProof{Form: backend.AggregateElectra, SSZ: electraAggregate(7, slot, proof)}},
		{plain, &backend.SyncCommitteeMessage{Slot: slot, BeaconBlockRoot: backend.Root{0x4d}}},
		{plain, &backend.SyncSelectionProof{Slot: slot, SubcommitteeIndex: 1}},
		{plain, &backend.ContributionAndProof{SSZ: contribution(7, slot, 2, syncProof)}},
		{gloas, &backend.PayloadAttestationData{BeaconBlockRoot: backend.Root{2}, Slot: 20*32 + 2}},
		{gloas, &backend.ProposerPreferences{ProposalSlot: 20*32 + 4, ValidatorIndex: 7, FeeRecipient: gcfg.FeeRecipients[0], TargetGasLimit: 36_000_000}},
	} {
		want, err := c.on.cfg.MessageDomain(c.m)
		if err != nil {
			t.Fatalf("%v: %v", c.m.Kind(), err)
		}
		// The same domain type under the genesis fork version, and under
		// the fork version of another chain.
		oldFork := backend.ComputeDomain(backend.DomainType(want[:4]), c.on.cfg.GenesisForkVersion, c.on.cfg.GenesisValidatorsRoot)
		otherChain := backend.ComputeDomain(backend.DomainType(want[:4]), c.on.cfg.ForkVersionAt(20), sha256.Sum256([]byte("another chain")))
		sigs, writes := c.on.s.Stats().Signatures, c.on.s.Stats().WatermarkWrites
		for _, d := range []backend.Root{{}, oldFork, otherChain} {
			if d == want {
				continue // exits and registrations do not follow the fork
			}
			_, err := c.on.s.Sign(backend.SignRequest{Pubkey: c.on.pk, Message: c.m, Domain: d})
			wantStatus(t, err, backend.StatusDomainMismatch)
		}
		if st := c.on.s.Stats(); st.Signatures != sigs || st.WatermarkWrites != writes {
			t.Fatalf("%v: a refused domain reached the core", c.m.Kind())
		}
		sig, err := c.on.s.Sign(backend.SignRequest{Pubkey: c.on.pk, Message: c.m, Domain: want})
		if err != nil {
			t.Fatalf("%v: %v", c.m.Kind(), err)
		}
		if root, _ := c.on.cfg.SigningRoot(c.m); !Verify(c.on.pk, root, sig) {
			t.Fatalf("%v: signature does not verify", c.m.Kind())
		}
	}
	// The payload envelope needs the signer's last block first; its domain
	// is checked like the others.
	blk := &backend.BeaconBlockHeader{Slot: env.Payload.SlotNumber, ProposerIndex: 7, ParentRoot: backend.Root{3}}
	mustSign(t, gs, gpk, blk)
	env.BeaconBlockRoot, _ = backend.HashTreeRoot(blk)
	env.ParentBeaconBlockRoot = blk.ParentRoot
	env.Payload.FeeRecipient = gcfg.FeeRecipients[0]
	_, err := gs.Sign(backend.SignRequest{Pubkey: gpk, Message: env})
	wantStatus(t, err, backend.StatusDomainMismatch)
	mustSign(t, gs, gpk, env)
	// An unknown message type is refused as before.
	_, err = s.Sign(backend.SignRequest{Pubkey: pk, Message: unknownMessage{}})
	wantStatus(t, err, backend.StatusUnsupported)
}

type unknownMessage struct{}

func (unknownMessage) Kind() backend.Kind { return 99 }

func mustSign(t *testing.T, s *Signer, pk backend.Pubkey, m backend.Message) backend.Signature {
	t.Helper()
	sig, err := s.Sign(signReq(s, pk, m))
	if err != nil {
		t.Fatalf("%v: %v", m.Kind(), err)
	}
	return sig
}

// SetSchedule goes through the core's fork rule. DevConfig has
// max_epochs_ahead 1, so with the clock in epoch 20 the first epoch an update
// may change is 23. The domain check follows the new schedule.
func TestSetSchedule(t *testing.T) {
	h := NewMemHooks()
	s, pk, cfg := newTestSigner(t, h)
	before := s.Config()
	with := func(epoch uint64) Schedule {
		n := cfg.Schedule()
		n.Forks = append(n.Forks, Fork{Epoch: epoch, Version: nextVersion})
		return n
	}

	wantStatus(t, s.SetSchedule(with(22), 0), backend.StatusSchedule)
	wantStatus(t, s.CheckSchedule(with(22), 0), backend.StatusSchedule)
	if err := s.CheckSchedule(with(23), 0); err != nil {
		t.Fatal(err)
	}
	if now := s.Config(); now.ForkVersionAt(23) != cfg.ForkVersionAt(23) {
		t.Fatal("CheckSchedule changed the schedule")
	}
	if err := s.SetSchedule(with(23), 0); err != nil {
		t.Fatal(err)
	}
	if now := s.Config(); now.ForkVersionAt(23) != nextVersion {
		t.Fatalf("epoch 23 version %v after the update", now.ForkVersionAt(23))
	}
	if len(before.Forks) != len(cfg.Forks) {
		t.Fatal("an earlier Config copy changed")
	}

	// In epoch 23 a caller still on the old schedule is refused; the new
	// domain signs, and the core used the new version.
	h.Clock = clockAtEpoch(23)
	a := att(22, 23)
	_, err := s.Sign(backend.SignRequest{Pubkey: pk, Message: a, Domain: cfg.Domain(backend.DomainBeaconAttester, 23)})
	wantStatus(t, err, backend.StatusDomainMismatch)
	sig := mustSign(t, s, pk, a)
	newCfg := s.Config()
	if root, _ := newCfg.SigningRoot(a); !Verify(pk, root, sig) {
		t.Fatal("signature not under the new fork version")
	}
	// The fork at 23 has started now and stays.
	wantStatus(t, s.SetSchedule(cfg.Schedule(), 0), backend.StatusSchedule)

	// activateAt in epoch 27 moves the first changeable epoch to 30.
	s2, _, _ := newTestSigner(t, NewMemHooks())
	at := uint64(genesis + 27*12*32 + 1)
	wantStatus(t, s2.SetSchedule(with(29), at), backend.StatusSchedule)
	if err := s2.SetSchedule(with(30), at); err != nil {
		t.Fatal(err)
	}

	// A started fork, a malformed schedule and a closed signer.
	started := cfg.Schedule()
	started.Forks[0].Version = nextVersion
	wantStatus(t, s2.SetSchedule(started, 0), backend.StatusSchedule)
	descending := with(30)
	descending.Forks = append(descending.Forks, Fork{Epoch: 25, Version: nextVersion})
	wantStatus(t, s2.SetSchedule(descending, 0), backend.StatusArg)
	gloas := with(40)
	e := uint64(41)
	gloas.GloasForkEpoch = &e
	wantStatus(t, s2.SetSchedule(gloas, 0), backend.StatusArg)
	e = 40
	if err := s2.SetSchedule(gloas, 0); err != nil {
		t.Fatalf("Gloas at a future fork: %v", err)
	}
	if got := s2.Config(); got.GloasForkEpoch == nil || *got.GloasForkEpoch != 40 {
		t.Fatal("Gloas epoch not taken")
	}
	s2.Close()
	if err := s2.SetSchedule(with(30), 0); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed signer: %v", err)
	}
}
