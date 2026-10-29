package core_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

// electraAggregate is an Electra AggregateAndProof (mainnet preset) with a
// one-bit aggregation list, in SSZ.
func electraAggregate(aggregator, slot uint64, proof backend.Signature) []byte {
	le := binary.LittleEndian
	b := le.AppendUint64(nil, aggregator)
	b = le.AppendUint32(b, 108)
	b = append(b, proof[:]...)
	b = le.AppendUint32(b, 236) // offset of aggregation_bits in the Attestation
	data, _ := backend.EncodeSSZ(&backend.AttestationData{Slot: slot, BeaconBlockRoot: backend.Root{0xbb},
		Source: backend.Checkpoint{Epoch: slot/32 - 1, Root: backend.Root{5}},
		Target: backend.Checkpoint{Epoch: slot / 32, Root: backend.Root{7}}})
	b = append(b, data...)
	b = append(b, bytes.Repeat([]byte{0x77}, 96)...) // aggregate signature
	b = append(b, 0x01, 0, 0, 0, 0, 0, 0, 0)         // committee_bits
	return append(b, 0x03)                           // one bit set, delimiter
}

// contribution is a ContributionAndProof (mainnet preset) in SSZ.
func contribution(aggregator, slot, sub uint64, proof backend.Signature) []byte {
	le := binary.LittleEndian
	b := le.AppendUint64(nil, aggregator)
	b = le.AppendUint64(b, slot)
	b = append(b, bytes.Repeat([]byte{0x3c}, 32)...)
	b = le.AppendUint64(b, sub)
	b = append(b, 0x05)
	b = append(b, make([]byte, 15)...)
	b = append(b, bytes.Repeat([]byte{0x66}, 96)...)
	return append(b, proof[:]...)
}

// With the unverified switch off (the default) the typed kinds sign
// aggregates and contributions, and the core checks their content.
func TestTypedAggregatesAndContributions(t *testing.T) {
	s, pk, cfg := newTestSigner(t, software.NewMemHooks())
	if cfg.AllowUnverifiedNonslashable {
		t.Fatal("DevConfig turns the switch on")
	}
	slot := uint64(20*32 + 3)
	sign := func(m backend.Message) (backend.Signature, error) {
		return s.Sign(signReq(s, pk, m))
	}
	mustVerify := func(m backend.Message) backend.Signature {
		t.Helper()
		sig, err := sign(m)
		if err != nil {
			t.Fatalf("%v: %v", m.Kind(), err)
		}
		root, err := cfg.SigningRoot(m)
		if err != nil || !core.Verify(pk, root, sig) {
			t.Fatalf("%v: signature does not verify (%v)", m.Kind(), err)
		}
		return sig
	}

	// The test key is a full key, so its selection proofs are the
	// validator's own and pass the core's check.
	proof := mustVerify(&backend.SelectionProof{Slot: slot})
	mustVerify(&backend.AggregateAndProof{Form: backend.AggregateElectra, SSZ: electraAggregate(7, slot, proof)})
	mustVerify(&backend.SyncCommitteeMessage{Slot: slot, BeaconBlockRoot: backend.Root{0x4d}})
	syncProof := mustVerify(&backend.SyncSelectionProof{Slot: slot, SubcommitteeIndex: 2})
	mustVerify(&backend.ContributionAndProof{SSZ: contribution(7, slot, 2, syncProof)})

	refused := []struct {
		name string
		m    backend.Message
		want backend.Status
	}{
		{"Gloas form, Gloas not scheduled", &backend.AggregateAndProof{Form: backend.AggregateGloas, SSZ: electraAggregate(7, slot, proof)}, backend.StatusPolicyFork},
		{"another aggregator index", &backend.AggregateAndProof{Form: backend.AggregateElectra, SSZ: electraAggregate(8, slot, proof)}, backend.StatusPolicyIndex},
		{"selection proof of another slot", &backend.AggregateAndProof{Form: backend.AggregateElectra, SSZ: electraAggregate(7, slot+1, proof)}, backend.StatusSelectionProof},
		{"garbage selection proof", &backend.AggregateAndProof{Form: backend.AggregateElectra, SSZ: electraAggregate(7, slot, backend.Signature{0xab})}, backend.StatusSelectionProof},
		{"aggregate past the clock horizon", &backend.AggregateAndProof{Form: backend.AggregateElectra, SSZ: electraAggregate(7, 22*32, proof)}, backend.StatusPolicyFuture},
		{"truncated aggregate", &backend.AggregateAndProof{Form: backend.AggregateElectra, SSZ: electraAggregate(7, slot, proof)[:400]}, backend.StatusDecode},
		{"phase0 form of Electra bytes", &backend.AggregateAndProof{Form: backend.AggregatePhase0, SSZ: electraAggregate(7, slot, proof)}, backend.StatusDecode},
		{"contribution, another index", &backend.ContributionAndProof{SSZ: contribution(9, slot, 2, syncProof)}, backend.StatusPolicyIndex},
		{"contribution, proof of another subcommittee", &backend.ContributionAndProof{SSZ: contribution(7, slot, 3, syncProof)}, backend.StatusSelectionProof},
		{"contribution, subcommittee 4", &backend.ContributionAndProof{SSZ: contribution(7, slot, 4, syncProof)}, backend.StatusArg},
		{"contribution, wrong length", &backend.ContributionAndProof{SSZ: contribution(7, slot, 2, syncProof)[:263]}, backend.StatusDecode},
		{"sync selection, subcommittee 4", &backend.SyncSelectionProof{Slot: slot, SubcommitteeIndex: 4}, backend.StatusArg},
		{"selection proof past the horizon", &backend.SelectionProof{Slot: 22 * 32}, backend.StatusPolicyFuture},
		{"sync message past the horizon", &backend.SyncCommitteeMessage{Slot: 22 * 32}, backend.StatusPolicyFuture},
	}
	for _, r := range refused {
		_, err := sign(r.m)
		if got := backend.StatusOf(err); got != r.want {
			t.Fatalf("%s: got %v (%v), want %v", r.name, got, err, r.want)
		}
	}
	if n := s.Stats().UnverifiedSignatures; n != 0 {
		t.Fatalf("typed signatures counted as unverified: %d", n)
	}

	// Every kind goes through the wire and back unchanged.
	for _, m := range []backend.Message{
		&backend.SelectionProof{Slot: slot},
		&backend.AggregateAndProof{Form: backend.AggregateElectra, SSZ: electraAggregate(7, slot, proof)},
		&backend.SyncCommitteeMessage{Slot: slot, BeaconBlockRoot: backend.Root{0x4d}},
		&backend.SyncSelectionProof{Slot: slot, SubcommitteeIndex: 2},
		&backend.ContributionAndProof{SSZ: contribution(7, slot, 2, syncProof)},
	} {
		req := signReq(s, pk, m)
		p, err := wire.EncodeSign(req)
		if err != nil {
			t.Fatal(err)
		}
		back, err := wire.DecodeSign(p)
		if err != nil {
			t.Fatalf("%v: %v", m.Kind(), err)
		}
		a, _ := backend.EncodeSSZ(m)
		b, _ := backend.EncodeSSZ(back.Message)
		if back.Message.Kind() != m.Kind() || !bytes.Equal(a, b) || back.Domain != req.Domain {
			t.Fatalf("%v: changed on the wire", m.Kind())
		}
		// Without the domain the two variable
		// kinds may still parse, with message bytes taken as the domain; the
		// signer refuses them before the core signs.
		if k := m.Kind(); k == backend.KindAggregateAndProof || k == backend.KindContributionAndProof {
			old := append(append(append([]byte(nil), pk[:]...), byte(k)), a...)
			if back, err := wire.DecodeSign(old); err == nil {
				before := s.Stats().Signatures
				if _, err := s.Sign(back); err == nil || s.Stats().Signatures != before {
					t.Fatalf("%v without a domain: signed (%v)", k, err)
				}
			}
		}
	}
	// Frames the decoder refuses before the core sees them.
	for _, bad := range []struct {
		k Kind
		b []byte
	}{
		{backend.KindAggregateAndProof, []byte{3, 1}},
		{backend.KindAggregateAndProof, []byte{1}},
		{backend.KindAggregateAndProof, make([]byte, 2+backend.MaxAggregateAndProofBytes)},
		{backend.KindSelectionProof, make([]byte, 9)},
		{backend.KindSyncCommitteeMessage, make([]byte, 39)},
		{backend.KindSyncSelectionProof, make([]byte, 15)},
		{backend.KindContributionAndProof, nil},
	} {
		if _, err := backend.DecodeSSZ(bad.k, bad.b); err == nil {
			t.Fatalf("%v with %d bytes decoded", bad.k, len(bad.b))
		}
	}
}

// Kind is a local alias so the table above reads short.
type Kind = backend.Kind

// The preset follows the config: minimal for 8 slots an epoch unless set.
func TestPresetName(t *testing.T) {
	c := software.DevConfig(genesis, 6, 8)
	if c.PresetName() != "minimal" {
		t.Fatal(c.PresetName())
	}
	c.Preset = "mainnet"
	if c.PresetName() != "mainnet" || c.Validate() != nil {
		t.Fatal("explicit mainnet")
	}
	c.Preset = "gnosis"
	if c.Validate() == nil {
		t.Fatal("unknown preset accepted")
	}
}
