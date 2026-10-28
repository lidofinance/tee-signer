package backend

import (
	"encoding/binary"
	"fmt"
)

// Gloas messages (consensus-specs specs/gloas, commit 460fd37c). The C core
// signs each one (sc_sign_payload_attestation, sc_sign_payload_envelope,
// sc_sign_proposer_preferences) and refuses it before the Gloas fork epoch
// of the chain config.

// Gloas wire kinds.
const (
	KindPayloadAttestation  Kind = 6 // PayloadAttestationData, SSZ, 42 bytes
	KindPayloadEnvelope     Kind = 7 // self-built envelope, the core's layout, 532 bytes
	KindProposerPreferences Kind = 8 // ProposerPreferences, SSZ, 76 bytes
)

// Gloas domain types (beacon-chain.md "Domains").
var (
	DomainBeaconBuilder       = DomainType{0x0b, 0, 0, 0}
	DomainPTCAttester         = DomainType{0x0c, 0, 0, 0}
	DomainProposerPreferences = DomainType{0x0d, 0, 0, 0}
)

// BuilderIndexSelfBuild is BUILDER_INDEX_SELF_BUILD: the proposer built the
// payload and signs the envelope with its validator key.
const BuilderIndexSelfBuild = ^uint64(0)

// SSZ and layout sizes of the Gloas messages.
const (
	SSZPayloadAttestationDataLen = 42
	SSZProposerPreferencesLen    = 76
	PayloadEnvelopeLen           = 532
)

// PayloadAttestationData is the PTC vote.
type PayloadAttestationData struct {
	BeaconBlockRoot   Root   `json:"beacon_block_root"`
	Slot              uint64 `json:"slot"`
	PayloadPresent    bool   `json:"payload_present"`
	BlobDataAvailable bool   `json:"blob_data_available"`
}

// ProposerPreferences is what a proposer publishes for a proposal slot.
type ProposerPreferences struct {
	DependentRoot  Root    `json:"dependent_root"`
	ProposalSlot   uint64  `json:"proposal_slot"`
	ValidatorIndex uint64  `json:"validator_index"`
	FeeRecipient   Address `json:"fee_recipient"`
	TargetGasLimit uint64  `json:"target_gas_limit"`
}

// ExecutionPayloadSummary is the Gloas ExecutionPayload with its
// variable-size fields as their hash_tree_root; BaseFeePerGas is the
// uint256 in little endian.
type ExecutionPayloadSummary struct {
	ParentHash          Root    `json:"parent_hash"`
	FeeRecipient        Address `json:"fee_recipient"`
	StateRoot           Root    `json:"state_root"`
	ReceiptsRoot        Root    `json:"receipts_root"`
	LogsBloomRoot       Root    `json:"logs_bloom_root"`
	PrevRandao          Root    `json:"prev_randao"`
	BlockNumber         uint64  `json:"block_number"`
	GasLimit            uint64  `json:"gas_limit"`
	GasUsed             uint64  `json:"gas_used"`
	Timestamp           uint64  `json:"timestamp"`
	ExtraDataRoot       Root    `json:"extra_data_root"`
	BaseFeePerGas       Root    `json:"base_fee_per_gas"`
	BlockHash           Root    `json:"block_hash"`
	TransactionsRoot    Root    `json:"transactions_root"`
	WithdrawalsRoot     Root    `json:"withdrawals_root"`
	BlobGasUsed         uint64  `json:"blob_gas_used"`
	ExcessBlobGas       uint64  `json:"excess_blob_gas"`
	BlockAccessListRoot Root    `json:"block_access_list_root"`
	SlotNumber          uint64  `json:"slot_number"`
}

// PayloadEnvelope is the ExecutionPayloadEnvelope a self-building proposer
// signs, with the payload as a summary and the requests as their root.
type PayloadEnvelope struct {
	Payload               ExecutionPayloadSummary `json:"payload"`
	ExecutionRequestsRoot Root                    `json:"execution_requests_root"`
	BuilderIndex          uint64                  `json:"builder_index"`
	BeaconBlockRoot       Root                    `json:"beacon_block_root"`
	ParentBeaconBlockRoot Root                    `json:"parent_beacon_block_root"`
}

func (*PayloadAttestationData) Kind() Kind { return KindPayloadAttestation }
func (*PayloadEnvelope) Kind() Kind        { return KindPayloadEnvelope }
func (*ProposerPreferences) Kind() Kind    { return KindProposerPreferences }

func gloasKindName(k Kind) (string, bool) {
	switch k {
	case KindPayloadAttestation:
		return "payload_attestation", true
	case KindPayloadEnvelope:
		return "payload_envelope", true
	case KindProposerPreferences:
		return "proposer_preferences", true
	}
	return "", false
}

func boolByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}

func encodeGloas(m Message) ([]byte, bool) {
	le := binary.LittleEndian
	switch v := m.(type) {
	case *PayloadAttestationData:
		b := append(make([]byte, 0, SSZPayloadAttestationDataLen), v.BeaconBlockRoot[:]...)
		b = le.AppendUint64(b, v.Slot)
		return append(b, boolByte(v.PayloadPresent), boolByte(v.BlobDataAvailable)), true
	case *ProposerPreferences:
		b := append(make([]byte, 0, SSZProposerPreferencesLen), v.DependentRoot[:]...)
		b = le.AppendUint64(b, v.ProposalSlot)
		b = le.AppendUint64(b, v.ValidatorIndex)
		b = append(b, v.FeeRecipient[:]...)
		return le.AppendUint64(b, v.TargetGasLimit), true
	case *PayloadEnvelope:
		p := &v.Payload
		b := make([]byte, 0, PayloadEnvelopeLen)
		for _, f := range []any{p.ParentHash, p.FeeRecipient, p.StateRoot, p.ReceiptsRoot, p.LogsBloomRoot, p.PrevRandao,
			p.BlockNumber, p.GasLimit, p.GasUsed, p.Timestamp, p.ExtraDataRoot, p.BaseFeePerGas, p.BlockHash,
			p.TransactionsRoot, p.WithdrawalsRoot, p.BlobGasUsed, p.ExcessBlobGas, p.BlockAccessListRoot, p.SlotNumber,
			v.ExecutionRequestsRoot, v.BuilderIndex, v.BeaconBlockRoot, v.ParentBeaconBlockRoot} {
			switch x := f.(type) {
			case Root:
				b = append(b, x[:]...)
			case Address:
				b = append(b, x[:]...)
			case uint64:
				b = le.AppendUint64(b, x)
			}
		}
		return b, true
	}
	return nil, false
}

func decodeGloas(k Kind, b []byte) (Message, bool, error) {
	le := binary.LittleEndian
	switch k {
	case KindPayloadAttestation:
		if len(b) != SSZPayloadAttestationDataLen || b[40] > 1 || b[41] > 1 {
			return nil, true, fmt.Errorf("%v: want %d bytes with booleans 0 or 1", k, SSZPayloadAttestationDataLen)
		}
		v := &PayloadAttestationData{Slot: le.Uint64(b[32:]), PayloadPresent: b[40] == 1, BlobDataAvailable: b[41] == 1}
		copy(v.BeaconBlockRoot[:], b)
		return v, true, nil
	case KindProposerPreferences:
		if len(b) != SSZProposerPreferencesLen {
			return nil, true, fmt.Errorf("%v: want %d bytes, got %d", k, SSZProposerPreferencesLen, len(b))
		}
		v := &ProposerPreferences{ProposalSlot: le.Uint64(b[32:]), ValidatorIndex: le.Uint64(b[40:]), TargetGasLimit: le.Uint64(b[68:])}
		copy(v.DependentRoot[:], b)
		copy(v.FeeRecipient[:], b[48:68])
		return v, true, nil
	case KindPayloadEnvelope:
		if len(b) != PayloadEnvelopeLen {
			return nil, true, fmt.Errorf("%v: want %d bytes, got %d", k, PayloadEnvelopeLen, len(b))
		}
		v := &PayloadEnvelope{}
		p := &v.Payload
		at := 0
		root := func(r *Root) { at += copy(r[:], b[at:]) }
		u64 := func() uint64 { at += 8; return le.Uint64(b[at-8:]) }
		root(&p.ParentHash)
		at += copy(p.FeeRecipient[:], b[at:])
		root(&p.StateRoot)
		root(&p.ReceiptsRoot)
		root(&p.LogsBloomRoot)
		root(&p.PrevRandao)
		p.BlockNumber, p.GasLimit, p.GasUsed, p.Timestamp = u64(), u64(), u64(), u64()
		root(&p.ExtraDataRoot)
		root(&p.BaseFeePerGas)
		root(&p.BlockHash)
		root(&p.TransactionsRoot)
		root(&p.WithdrawalsRoot)
		p.BlobGasUsed, p.ExcessBlobGas = u64(), u64()
		root(&p.BlockAccessListRoot)
		p.SlotNumber = u64()
		root(&v.ExecutionRequestsRoot)
		v.BuilderIndex = u64()
		root(&v.BeaconBlockRoot)
		root(&v.ParentBeaconBlockRoot)
		return v, true, nil
	}
	return nil, false, nil
}

// merkleizeProgressive is EIP-7916 merkleize_progressive (remerkleable's
// subtree_fill_progressive): hash(binary tree of the first base chunks,
// progressive rest with base * 4), a zero chunk for none.
func merkleizeProgressive(chunks []Root, base int) Root {
	if len(chunks) == 0 {
		return Root{}
	}
	first := len(chunks)
	if first > base {
		first = base
	}
	left := make([]Root, base)
	copy(left, chunks[:first])
	return hashPair(merkleize(left...), merkleizeProgressive(chunks[first:], base*4))
}

// progressiveContainer is hash_tree_root of a ProgressiveContainer with all
// fields active (EIP-7495).
func progressiveContainer(fields ...Root) Root {
	var active Root
	for i := range fields {
		active[i/8] |= 1 << (i % 8)
	}
	return hashPair(merkleizeProgressive(fields, 1), active)
}

func hashTreeRootGloas(m Message) (Root, bool) {
	switch v := m.(type) {
	case *PayloadAttestationData:
		return merkleize(v.BeaconBlockRoot, u64Root(v.Slot), padRoot([]byte{boolByte(v.PayloadPresent)}),
			padRoot([]byte{boolByte(v.BlobDataAvailable)})), true
	case *ProposerPreferences:
		return merkleize(v.DependentRoot, u64Root(v.ProposalSlot), u64Root(v.ValidatorIndex), padRoot(v.FeeRecipient[:]),
			u64Root(v.TargetGasLimit)), true
	case *PayloadEnvelope:
		p := &v.Payload
		payload := progressiveContainer(p.ParentHash, padRoot(p.FeeRecipient[:]), p.StateRoot, p.ReceiptsRoot,
			p.LogsBloomRoot, p.PrevRandao, u64Root(p.BlockNumber), u64Root(p.GasLimit), u64Root(p.GasUsed),
			u64Root(p.Timestamp), p.ExtraDataRoot, p.BaseFeePerGas, p.BlockHash, p.TransactionsRoot, p.WithdrawalsRoot,
			u64Root(p.BlobGasUsed), u64Root(p.ExcessBlobGas), p.BlockAccessListRoot, u64Root(p.SlotNumber))
		return progressiveContainer(payload, v.ExecutionRequestsRoot, u64Root(v.BuilderIndex), v.BeaconBlockRoot,
			v.ParentBeaconBlockRoot), true
	}
	return Root{}, false
}
