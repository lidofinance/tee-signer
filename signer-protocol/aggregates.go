package backend

import (
	"encoding/binary"
	"fmt"
)

// Aggregate and sync committee messages with their content. The C core
// decodes each one, computes its root and checks it (sc_sign_aggregate_and_proof
// and the four calls next to it in signer_core.h): the aggregator index
// against the key's bound index, the selection proof against the validator
// key, the slot against the clock horizon, the fork domain, and for
// aggregates the Gloas form. Before these kinds the Dirk adapter hashed the
// messages and sent a RootMessage, so the runner never saw the content.
const (
	KindAggregateAndProof    Kind = 9  // form:u8 | AggregateAndProof SSZ
	KindContributionAndProof Kind = 10 // ContributionAndProof SSZ (preset size)
	KindSelectionProof       Kind = 11 // slot:u64, little endian (the aggregation slot)
	KindSyncCommitteeMessage Kind = 12 // slot:u64 | beacon_block_root[32]
	KindSyncSelectionProof   Kind = 13 // slot:u64 | subcommittee_index:u64
)

// MaxAggregateAndProofBytes is the largest Electra AggregateAndProof under the
// mainnet preset: 2048 x 64 aggregation bits plus the delimiter.
const MaxAggregateAndProofBytes = 8 + 4 + 96 + 4 + 128 + 96 + 8 + 16385

// AggregateForm says how an AggregateAndProof is hashed: phase0, Electra
// (committee_bits) or Gloas (the Electra bytes as a progressive container).
type AggregateForm uint8

const (
	AggregatePhase0  AggregateForm = 0
	AggregateElectra AggregateForm = 1
	AggregateGloas   AggregateForm = 2
)

// AggregateAndProof carries the SSZ of the message; the core parses it.
type AggregateAndProof struct {
	Form AggregateForm `json:"form"`
	SSZ  []byte        `json:"ssz"`
}

// ContributionAndProof carries the SSZ of the message; the core parses it.
type ContributionAndProof struct {
	SSZ []byte `json:"ssz"`
}

// SelectionProof is the aggregation slot an aggregator signs.
type SelectionProof struct {
	Slot uint64 `json:"slot"`
}

// SyncCommitteeMessage is the block root a sync committee member signs.
type SyncCommitteeMessage struct {
	Slot            uint64 `json:"slot"`
	BeaconBlockRoot Root   `json:"beacon_block_root"`
}

// SyncSelectionProof is SyncAggregatorSelectionData.
type SyncSelectionProof struct {
	Slot              uint64 `json:"slot"`
	SubcommitteeIndex uint64 `json:"subcommittee_index"`
}

func (*AggregateAndProof) Kind() Kind    { return KindAggregateAndProof }
func (*ContributionAndProof) Kind() Kind { return KindContributionAndProof }
func (*SelectionProof) Kind() Kind       { return KindSelectionProof }
func (*SyncCommitteeMessage) Kind() Kind { return KindSyncCommitteeMessage }
func (*SyncSelectionProof) Kind() Kind   { return KindSyncSelectionProof }

func aggregateKindName(k Kind) (string, bool) {
	switch k {
	case KindAggregateAndProof:
		return "aggregate_and_proof", true
	case KindContributionAndProof:
		return "contribution_and_proof", true
	case KindSelectionProof:
		return "selection_proof", true
	case KindSyncCommitteeMessage:
		return "sync_committee_message", true
	case KindSyncSelectionProof:
		return "sync_selection_proof", true
	}
	return "", false
}

func encodeAggregate(m Message) ([]byte, bool) {
	le := binary.LittleEndian
	switch v := m.(type) {
	case *AggregateAndProof:
		return append([]byte{byte(v.Form)}, v.SSZ...), true
	case *ContributionAndProof:
		return append([]byte(nil), v.SSZ...), true
	case *SelectionProof:
		return le.AppendUint64(nil, v.Slot), true
	case *SyncCommitteeMessage:
		return append(le.AppendUint64(nil, v.Slot), v.BeaconBlockRoot[:]...), true
	case *SyncSelectionProof:
		return le.AppendUint64(le.AppendUint64(nil, v.Slot), v.SubcommitteeIndex), true
	}
	return nil, false
}

// decodeAggregate checks only the frame: lengths and the form byte. The
// core checks the SSZ itself.
func decodeAggregate(k Kind, b []byte) (Message, bool, error) {
	le := binary.LittleEndian
	switch k {
	case KindAggregateAndProof:
		if len(b) < 2 || len(b) > 1+MaxAggregateAndProofBytes || b[0] > byte(AggregateGloas) {
			return nil, true, fmt.Errorf("%v: form 0 to 2 and 1 to %d SSZ bytes", k, MaxAggregateAndProofBytes)
		}
		return &AggregateAndProof{Form: AggregateForm(b[0]), SSZ: append([]byte(nil), b[1:]...)}, true, nil
	case KindContributionAndProof:
		if len(b) == 0 || len(b) > 4096 {
			return nil, true, fmt.Errorf("%v: 1 to 4096 bytes", k)
		}
		return &ContributionAndProof{SSZ: append([]byte(nil), b...)}, true, nil
	case KindSelectionProof:
		if len(b) != 8 {
			return nil, true, fmt.Errorf("%v: want 8 bytes, got %d", k, len(b))
		}
		return &SelectionProof{Slot: le.Uint64(b)}, true, nil
	case KindSyncCommitteeMessage:
		if len(b) != 40 {
			return nil, true, fmt.Errorf("%v: want 40 bytes, got %d", k, len(b))
		}
		v := &SyncCommitteeMessage{Slot: le.Uint64(b)}
		copy(v.BeaconBlockRoot[:], b[8:])
		return v, true, nil
	case KindSyncSelectionProof:
		if len(b) != 16 {
			return nil, true, fmt.Errorf("%v: want 16 bytes, got %d", k, len(b))
		}
		return &SyncSelectionProof{Slot: le.Uint64(b), SubcommitteeIndex: le.Uint64(b[8:])}, true, nil
	}
	return nil, false, nil
}
