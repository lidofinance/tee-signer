package backend

import (
	"encoding/binary"
	"errors"
	"fmt"

	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"

	proto "github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/web3signer-api/signing"
)

// Message turns a parsed request into the typed message of the signers'
// SIGN (signer-protocol). Each signer computes the signing root from it
// with its own chain config and checks the content: slashing protection
// for attestations and blocks, the aggregator index and selection proof
// of an aggregate, fee recipient and gas limit, the domain. RANDAO goes as
// a root message, whose root the signer checks against the epoch. No type
// goes out as a bare root.
func Message(job *signing.Job) (proto.Message, error) {
	switch job.Method {
	case signing.MethodAttestation:
		return attestationData(job.Attestation)
	case signing.MethodProposal:
		h := job.Proposal
		if h == nil {
			return nil, errors.New("block header missing")
		}

		return &proto.BeaconBlockHeader{
			Slot: uint64(h.Slot), ProposerIndex: uint64(h.ProposerIndex),
			ParentRoot: proto.Root(h.ParentRoot), StateRoot: proto.Root(h.StateRoot), BodyRoot: proto.Root(h.BodyRoot),
		}, nil
	case signing.MethodGeneric, signing.MethodTyped:
		if job.Typed == nil {
			return nil, &DeniedError{Detail: job.Type + ": the signers sign no bare roots"}
		}

		return typedMessage(job)
	}

	return nil, &DeniedError{Detail: "no signer message for " + job.Type}
}

// CallName names the signer message a job becomes, for the log. Empty if
// there is none.
func CallName(job *signing.Job) string {
	msg, err := Message(job)
	if err != nil {
		return ""
	}

	return msg.Kind().String()
}

func checkpoint(c *phase0.Checkpoint) proto.Checkpoint {
	return proto.Checkpoint{Epoch: uint64(c.Epoch), Root: proto.Root(c.Root)}
}

func attestationData(d *phase0.AttestationData) (*proto.AttestationData, error) {
	if d == nil || d.Source == nil || d.Target == nil {
		return nil, errors.New("attestation data incomplete")
	}

	return &proto.AttestationData{
		Slot: uint64(d.Slot), Index: uint64(d.Index), BeaconBlockRoot: proto.Root(d.BeaconBlockRoot),
		Source: checkpoint(d.Source), Target: checkpoint(d.Target),
	}, nil
}

func typedMessage(job *signing.Job) (proto.Message, error) {
	switch t := job.Typed.(type) {
	case *signing.RandaoReveal:
		return &proto.RootMessage{Type: proto.RootRandaoReveal, Epoch: uint64(t.Epoch),
			ObjectRoot: proto.Root(job.ObjectRoot), Domain: proto.Root(job.Domain)}, nil
	case *signing.AggregationSlot:
		return &proto.SelectionProof{Slot: uint64(t.Slot)}, nil
	case *phase0.AggregateAndProof:
		if t.Aggregate == nil {
			return nil, errors.New("aggregate missing")
		}
		ssz, err := aggregateSSZ(uint64(t.AggregatorIndex), t.SelectionProof, t.Aggregate.AggregationBits,
			t.Aggregate.Data, t.Aggregate.Signature, nil)

		return &proto.AggregateAndProof{Form: proto.AggregatePhase0, SSZ: ssz}, err
	case *electra.AggregateAndProof:
		if t.Aggregate == nil {
			return nil, errors.New("aggregate missing")
		}
		ssz, err := aggregateSSZ(uint64(t.AggregatorIndex), t.SelectionProof, t.Aggregate.AggregationBits,
			t.Aggregate.Data, t.Aggregate.Signature, t.Aggregate.CommitteeBits)

		return &proto.AggregateAndProof{Form: proto.AggregateElectra, SSZ: ssz}, err
	case *signing.GloasAggregateAndProof:
		if t.AggregateAndProof == nil || t.Aggregate == nil {
			return nil, errors.New("aggregate missing")
		}
		if len(t.Aggregate.CommitteeBits) == 0 {
			return nil, errors.New("a Gloas aggregate needs committee bits")
		}
		ssz, err := aggregateSSZ(uint64(t.AggregatorIndex), t.SelectionProof, t.Aggregate.AggregationBits,
			t.Aggregate.Data, t.Aggregate.Signature, t.Aggregate.CommitteeBits)

		return &proto.AggregateAndProof{Form: proto.AggregateGloas, SSZ: ssz}, err
	case *signing.SyncCommitteeMessage:
		return &proto.SyncCommitteeMessage{Slot: uint64(t.Slot), BeaconBlockRoot: proto.Root(t.BeaconBlockRoot)}, nil
	case *altair.SyncAggregatorSelectionData:
		return &proto.SyncSelectionProof{Slot: uint64(t.Slot), SubcommitteeIndex: t.SubcommitteeIndex}, nil
	case *altair.ContributionAndProof:
		if t.Contribution == nil {
			return nil, errors.New("contribution missing")
		}

		return &proto.ContributionAndProof{SSZ: contributionSSZ(t)}, nil
	case *apiv1.ValidatorRegistration:
		return &proto.ValidatorRegistration{
			FeeRecipient: proto.Address(t.FeeRecipient), GasLimit: t.GasLimit,
			Timestamp: uint64(t.Timestamp.Unix()), Pubkey: proto.Pubkey(t.Pubkey),
		}, nil
	case *phase0.VoluntaryExit:
		return &proto.VoluntaryExit{Epoch: uint64(t.Epoch), ValidatorIndex: uint64(t.ValidatorIndex)}, nil
	case *gloas.PayloadAttestationData:
		return &proto.PayloadAttestationData{
			BeaconBlockRoot: proto.Root(t.BeaconBlockRoot), Slot: uint64(t.Slot),
			PayloadPresent: t.PayloadPresent, BlobDataAvailable: t.BlobDataAvailable,
		}, nil
	case *signing.PayloadEnvelope:
		p := &t.Payload

		return &proto.PayloadEnvelope{
			Payload: proto.ExecutionPayloadSummary{
				ParentHash: p.ParentHash, FeeRecipient: p.FeeRecipient, StateRoot: p.StateRoot, ReceiptsRoot: p.ReceiptsRoot,
				LogsBloomRoot: p.LogsBloomRoot, PrevRandao: p.PrevRandao, BlockNumber: p.BlockNumber, GasLimit: p.GasLimit,
				GasUsed: p.GasUsed, Timestamp: p.Timestamp, ExtraDataRoot: p.ExtraDataRoot, BaseFeePerGas: p.BaseFeePerGas,
				BlockHash: p.BlockHash, TransactionsRoot: p.TransactionsRoot, WithdrawalsRoot: p.WithdrawalsRoot,
				BlobGasUsed: p.BlobGasUsed, ExcessBlobGas: p.ExcessBlobGas, BlockAccessListRoot: p.BlockAccessListRoot,
				SlotNumber: p.SlotNumber,
			},
			ExecutionRequestsRoot: t.ExecutionRequestsRoot, BuilderIndex: t.BuilderIndex,
			BeaconBlockRoot: t.BeaconBlockRoot, ParentBeaconBlockRoot: t.ParentBeaconBlockRoot,
		}, nil
	case *gloas.ProposerPreferences:
		return &proto.ProposerPreferences{
			DependentRoot: proto.Root(t.DependentRoot), ProposalSlot: uint64(t.ProposalSlot),
			ValidatorIndex: uint64(t.ValidatorIndex), FeeRecipient: proto.Address(t.FeeRecipient), TargetGasLimit: t.TargetGasLimit,
		}, nil
	case *gloas.BuilderRequestAuth:
		if len(t.Data) > proto.MaxBuilderRequestAuthData {
			return nil, &DeniedError{Detail: fmt.Sprintf("builder request auth: %d data bytes, at most %d", len(t.Data), proto.MaxBuilderRequestAuthData)}
		}

		return &proto.BuilderRequestAuth{Data: append([]byte(nil), t.Data...), Slot: uint64(t.Slot)}, nil
	}

	return nil, &DeniedError{Detail: fmt.Sprintf("no signer message for %s (%T)", job.Type, job.Typed)}
}

// The SSZ of the aggregate and contribution messages, which the signer
// core decodes (sc_decode_aggregate_and_proof,
// sc_decode_contribution_and_proof). The bit fields go as they came, so
// the sizes of either preset pass.

type encoder []byte

func (e encoder) u64(v uint64) encoder    { return binary.LittleEndian.AppendUint64(e, v) }
func (e encoder) u32(v uint32) encoder    { return binary.LittleEndian.AppendUint32(e, v) }
func (e encoder) raw(b []byte) encoder    { return append(e, b...) }
func (e encoder) root(r [32]byte) encoder { return append(e, r[:]...) }

// aggregateSSZ is aggregator_index | offset of aggregate | selection_proof
// | aggregate, the aggregate being an Attestation: phase0 without
// committee bits, Electra (and Gloas, the same bytes) with them.
func aggregateSSZ(aggregator uint64, proof phase0.BLSSignature, bits []byte, d *phase0.AttestationData,
	sig phase0.BLSSignature, committeeBits []byte) ([]byte, error) {
	if d == nil || d.Source == nil || d.Target == nil {
		return nil, errors.New("aggregate data incomplete")
	}
	data := encoder(nil).u64(uint64(d.Slot)).u64(uint64(d.Index)).root(d.BeaconBlockRoot).
		u64(uint64(d.Source.Epoch)).root(d.Source.Root).u64(uint64(d.Target.Epoch)).root(d.Target.Root)
	att := encoder(nil).u32(uint32(4 + len(data) + len(sig) + len(committeeBits))).raw(data).raw(sig[:]).raw(committeeBits).raw(bits)

	return encoder(nil).u64(aggregator).u32(8 + 4 + 96).raw(proof[:]).raw(att), nil
}

// contributionSSZ is aggregator_index | SyncCommitteeContribution |
// selection_proof.
func contributionSSZ(m *altair.ContributionAndProof) []byte {
	c := m.Contribution

	return encoder(nil).u64(uint64(m.AggregatorIndex)).u64(uint64(c.Slot)).root(c.BeaconBlockRoot).u64(c.SubcommitteeIndex).
		raw(c.AggregationBits).raw(c.Signature[:]).raw(m.SelectionProof[:])
}
