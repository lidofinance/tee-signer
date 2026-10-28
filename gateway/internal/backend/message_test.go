package backend

import (
	"bytes"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"

	proto "github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/web3signer-api/signing"
)

func testData() *phase0.AttestationData {
	return &phase0.AttestationData{Slot: 100, Index: 3, BeaconBlockRoot: phase0.Root{1},
		Source: &phase0.Checkpoint{Epoch: 2, Root: phase0.Root{2}}, Target: &phase0.Checkpoint{Epoch: 3, Root: phase0.Root{3}}}
}

// The hand-made SSZ of the aggregate and contribution messages equals
// go-eth2-client's (mainnet sizes).
func TestAggregateSSZ(t *testing.T) {
	p0 := &phase0.AggregateAndProof{AggregatorIndex: 9, SelectionProof: phase0.BLSSignature{7},
		Aggregate: &phase0.Attestation{AggregationBits: []byte{0x0f, 0x01}, Data: testData(), Signature: phase0.BLSSignature{5}}}
	el := &electra.AggregateAndProof{AggregatorIndex: 9, SelectionProof: phase0.BLSSignature{7},
		Aggregate: &electra.Attestation{AggregationBits: []byte{0x0f, 0x01}, Data: testData(), Signature: phase0.BLSSignature{5},
			CommitteeBits: []byte{1, 0, 0, 0, 0, 0, 0, 0}}}
	bits := make([]byte, 16)
	bits[0] = 3
	co := &altair.ContributionAndProof{AggregatorIndex: 4, SelectionProof: phase0.BLSSignature{8},
		Contribution: &altair.SyncCommitteeContribution{Slot: 5, BeaconBlockRoot: phase0.Root{6}, SubcommitteeIndex: 1,
			AggregationBits: bits, Signature: phase0.BLSSignature{9}}}
	for _, c := range []struct {
		name  string
		typed any
		form  proto.AggregateForm
		want  func() ([]byte, error)
	}{
		{"phase0", p0, proto.AggregatePhase0, p0.MarshalSSZ},
		{"electra", el, proto.AggregateElectra, el.MarshalSSZ},
		{"contribution", co, 0, co.MarshalSSZ},
	} {
		msg, err := Message(&signing.Job{Type: c.name, Method: signing.MethodGeneric, Typed: c.typed})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		want, err := c.want()
		if err != nil {
			t.Fatal(err)
		}
		var got []byte
		switch m := msg.(type) {
		case *proto.AggregateAndProof:
			if m.Form != c.form {
				t.Fatalf("%s: form %d", c.name, m.Form)
			}
			got = m.SSZ
		case *proto.ContributionAndProof:
			got = m.SSZ
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s:\n got %x\nwant %x", c.name, got, want)
		}
	}
}

// A request without typed data never goes out as a bare root.
func TestNoBareRoots(t *testing.T) {
	_, err := Message(&signing.Job{Type: "X", Method: signing.MethodGeneric, ObjectRoot: phase0.Root{1}})
	if _, ok := err.(*DeniedError); !ok {
		t.Fatalf("got %v", err)
	}
}
