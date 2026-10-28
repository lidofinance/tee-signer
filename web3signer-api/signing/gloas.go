package signing

// Gloas request types (remote-signing-api v1.4.0, Web3Signer PR #1192;
// consensus-specs specs/gloas at 460fd37c). A validator signs a PTC vote,
// the envelope of a payload it built itself, its proposer preferences, and
// the authentication of its requests to an external builder (builder-specs
// BuilderRequestAuth). The gateway parses each one, computes its signing
// root, and passes the typed data on; it is refused before the configured
// Gloas fork epoch. Validators never sign bids (a self-build bid carries the
// point at infinity, validator.md).

import (
	"crypto/sha256"
	"encoding/json"
	"strings"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/lidofinance/tee-signer/web3signer-api/eth2"
)

// Gloas request types.
const (
	TypePayloadAttestationMessage = "PAYLOAD_ATTESTATION_MESSAGE"
	TypeExecutionPayloadEnvelope  = "EXECUTION_PAYLOAD_ENVELOPE"
	TypeProposerPreferences       = "PROPOSER_PREFERENCES"
	TypeExecutionPayloadBid       = "EXECUTION_PAYLOAD_BID"
	TypeBuilderRequestAuth        = "BUILDER_REQUEST_AUTH"

	// TypePayloadAttestation is Grandine's name for a PTC vote (3.0.0-rc.1
	// signer/src/web3signer/types.rs MessageType::PayloadAttestation). Its
	// body carries the bare PayloadAttestationData under
	// "payload_attestation". The job gets TypePayloadAttestationMessage.
	TypePayloadAttestation = "PAYLOAD_ATTESTATION"
)

// ExecutionPayloadSummary is a Gloas ExecutionPayload with its
// variable-size fields as their hash_tree_root (BaseFeePerGas is the
// uint256 in little endian), what the signers take instead of the
// transactions.
type ExecutionPayloadSummary struct {
	ParentHash          [32]byte
	FeeRecipient        [20]byte
	StateRoot           [32]byte
	ReceiptsRoot        [32]byte
	LogsBloomRoot       [32]byte
	PrevRandao          [32]byte
	BlockNumber         uint64
	GasLimit            uint64
	GasUsed             uint64
	Timestamp           uint64
	ExtraDataRoot       [32]byte
	BaseFeePerGas       [32]byte
	BlockHash           [32]byte
	TransactionsRoot    [32]byte
	WithdrawalsRoot     [32]byte
	BlobGasUsed         uint64
	ExcessBlobGas       uint64
	BlockAccessListRoot [32]byte
	SlotNumber          uint64
}

// PayloadEnvelope is the typed data of an EXECUTION_PAYLOAD_ENVELOPE job.
type PayloadEnvelope struct {
	Payload               ExecutionPayloadSummary
	ExecutionRequestsRoot [32]byte
	BuilderIndex          uint64
	BeaconBlockRoot       [32]byte
	ParentBeaconBlockRoot [32]byte
}

// GloasAggregateAndProof is the typed data of an aggregate from the Gloas
// fork on: the Electra bytes, hashed as the Gloas Attestation.
type GloasAggregateAndProof struct{ *gloas.AggregateAndProof }

// One-field containers have their field's root as their own, so these give
// the root of one payload field with the field's SSZ type.
type (
	logsBloomField struct{ V [256]byte }
	extraDataField struct {
		V []byte `ssz-max:"32"`
	}
	transactionsField struct {
		V []bellatrix.Transaction `ssz-type:"progressive-list,progressive-list"`
	}
	withdrawalsField struct {
		V []*capella.Withdrawal `ssz-type:"progressive-list"`
	}
	blockAccessListField struct {
		V gloas.BlockAccessList `ssz-type:"progressive-list"`
	}
)

// gloasRefusal names why a Gloas message must not be signed at epoch, or "".
func gloasRefusal(chain Chain, epoch phase0.Epoch) string {
	if chain.GloasForkEpoch == nil {
		return "Gloas is not in the configured chain (chain.gloas_fork_epoch)"
	}
	if epoch < *chain.GloasForkEpoch {
		return "Gloas message for an epoch before the Gloas fork"
	}

	return ""
}

// gloasData unmarshals the {"version":"GLOAS","data":...} object of name,
// or the bare data object when it has no "version" key. Grandine
// 3.0.0-rc.1 sends the bare object (serde flatten of SigningMessage, with
// no version tag).
func gloasData(name string, raw json.RawMessage, v any) error {
	var w struct {
		Version *string         `json:"version"`
		Data    json.RawMessage `json:"data"`
	}
	if err := unmarshalField(name, raw, &w); err != nil {
		return err
	}
	if w.Version == nil {
		return unmarshalField(name, raw, v)
	}
	if !strings.EqualFold(*w.Version, "GLOAS") {
		return badRequest("%s.version must be GLOAS, got %q", name, *w.Version)
	}

	return unmarshalField(name+".data", w.Data, v)
}

// refused is a job policy refuses (MethodNone) with reason.
func refused(req *requestJSON, reason string) *Job {
	return &Job{Type: req.Type, Method: MethodNone, Refusal: reason}
}

func buildPayloadAttestation(req *requestJSON, chain Chain) (*Job, error) {
	name, raw := "payload_attestation_message", req.PayloadAttestationMessage
	if req.Type == TypePayloadAttestation {
		name, raw = "payload_attestation", req.PayloadAttestation
		req.Type = TypePayloadAttestationMessage
	}
	data := &gloas.PayloadAttestationData{}
	if err := gloasData(name, raw, data); err != nil {
		return nil, err
	}
	epoch := eth2.EpochAtSlot(data.Slot, chain.SlotsPerEpoch)
	if why := gloasRefusal(chain, epoch); why != "" {
		return refused(req, why), nil
	}
	objectRoot, err := chain.Hasher.Root(data)
	if err != nil {
		return nil, badRequest("payload attestation data root: %v", err)
	}
	// validator.md get_payload_attestation_message_signature: epoch of data.slot.
	domain, err := domainFor(req, chain, eth2.DomainPTCAttester, epoch)
	if err != nil {
		return nil, err
	}

	return finish(&Job{Type: req.Type, Method: MethodTyped, Domain: domain, ObjectRoot: objectRoot, Typed: data})
}

func buildProposerPreferences(req *requestJSON, chain Chain) (*Job, error) {
	pref := &gloas.ProposerPreferences{}
	if err := gloasData("proposer_preferences", req.ProposerPreferences, pref); err != nil {
		return nil, err
	}
	epoch := eth2.EpochAtSlot(pref.ProposalSlot, chain.SlotsPerEpoch)
	if why := gloasRefusal(chain, epoch); why != "" {
		return refused(req, why), nil
	}
	objectRoot, err := chain.Hasher.Root(pref)
	if err != nil {
		return nil, badRequest("proposer preferences root: %v", err)
	}
	// validator.md: compute_domain(DOMAIN_PROPOSER_PREFERENCES,
	// compute_fork_version(proposal_epoch), genesis_validators_root). The
	// fork comes from the proposal epoch, not from the state that fork_info
	// describes: preferences for the first Gloas epoch are signed in the
	// epoch before the fork. fork_info must still name this chain.
	fi, err := req.forkInfo()
	if err != nil {
		return nil, err
	}
	var domain phase0.Domain
	if p := chain.Pin; p != nil {
		if fi.gvr != p.GenesisValidatorsRoot || !p.knows(fi.fork) {
			return nil, badRequest("fork_info does not name the configured chain")
		}
		domain, err = eth2.ComputeDomain(eth2.DomainProposerPreferences, p.versionAt(epoch), p.GenesisValidatorsRoot)
	} else {
		domain, err = eth2.ForkDomain(eth2.DomainProposerPreferences, fi.fork, fi.gvr, epoch)
	}
	if err != nil {
		return nil, err
	}

	return finish(&Job{Type: req.Type, Method: MethodTyped, Domain: domain, ObjectRoot: objectRoot, Typed: pref})
}

// MaxBuilderRequestAuthData is the limit of BuilderRequestAuth.data,
// ByteList[4096].
const MaxBuilderRequestAuthData = 4096

// buildBuilderRequestAuth signs builder API authentication (builder-specs
// specs/gloas/builder.md). The request has no fork_info: the domain is
// compute_domain(DOMAIN_BUILDER_REQUEST_AUTH) with the genesis fork version
// and a zero root, as for a validator registration. Which data a key signs
// is the signer's choice (the cloud runner's setup lists the allowed data
// roots), not the gateway's.
func buildBuilderRequestAuth(req *requestJSON, chain Chain) (*Job, error) {
	auth := &gloas.BuilderRequestAuth{}
	// go-eth2-client refuses empty data and data over 4096 bytes here.
	if err := gloasData("builder_request_auth", req.BuilderRequestAuth, auth); err != nil {
		return nil, err
	}
	if len(auth.Data) > MaxBuilderRequestAuthData {
		return nil, badRequest("builder_request_auth.data.data: %d bytes, at most %d", len(auth.Data), MaxBuilderRequestAuthData)
	}
	if why := gloasRefusal(chain, eth2.EpochAtSlot(auth.Slot, chain.SlotsPerEpoch)); why != "" {
		return refused(req, why), nil
	}
	objectRoot, err := auth.HashTreeRoot()
	if err != nil {
		return nil, badRequest("builder request auth root: %v", err)
	}
	domain, err := eth2.ComputeDomain(eth2.DomainBuilderRequestAuth, chain.GenesisForkVersion, phase0.Root{})
	if err != nil {
		return nil, err
	}

	return finish(&Job{Type: req.Type, Method: MethodTyped, Domain: domain, ObjectRoot: objectRoot, Typed: auth})
}

func buildPayloadEnvelope(req *requestJSON, chain Chain) (*Job, error) {
	env := &gloas.ExecutionPayloadEnvelope{}
	if err := gloasData("execution_payload_envelope", req.ExecutionPayloadEnvelope, env); err != nil {
		return nil, err
	}
	if env.Payload == nil || env.ExecutionRequests == nil {
		return nil, badRequest("execution_payload_envelope.data needs payload and execution_requests")
	}
	epoch := eth2.EpochAtSlot(phase0.Slot(env.Payload.SlotNumber), chain.SlotsPerEpoch)
	if why := gloasRefusal(chain, epoch); why != "" {
		return refused(req, why), nil
	}
	// Our keys are validators, never builders: only a self-built payload.
	if env.BuilderIndex != gloas.BuilderIndexSelfBuild {
		return refused(req, "envelope of a builder: validator keys sign only self-built envelopes"), nil
	}
	objectRoot, err := chain.Hasher.Root(env)
	if err != nil {
		return nil, badRequest("execution payload envelope root: %v", err)
	}
	summary, err := envelopeSummary(chain.Hasher, env)
	if err != nil {
		return nil, badRequest("execution payload envelope: %v", err)
	}
	// The signers hash the summary; it must give the root of the full envelope.
	if summary.Root() != objectRoot {
		return nil, badRequest("execution payload envelope: summary root %#x differs from the envelope root %#x", summary.Root(), objectRoot)
	}
	// builder.md get_execution_payload_envelope_signature: the block's epoch.
	domain, err := domainFor(req, chain, eth2.DomainBeaconBuilder, epoch)
	if err != nil {
		return nil, err
	}

	return finish(&Job{Type: req.Type, Method: MethodTyped, Domain: domain, ObjectRoot: objectRoot, Typed: summary})
}

func envelopeSummary(h *eth2.Hasher, env *gloas.ExecutionPayloadEnvelope) (*PayloadEnvelope, error) {
	p := env.Payload
	if p.BaseFeePerGas == nil {
		return nil, badRequest("payload.base_fee_per_gas missing")
	}
	s := &PayloadEnvelope{BuilderIndex: uint64(env.BuilderIndex), BeaconBlockRoot: env.BeaconBlockRoot, ParentBeaconBlockRoot: env.ParentBeaconBlockRoot}
	q := &s.Payload
	q.ParentHash, q.FeeRecipient, q.StateRoot, q.ReceiptsRoot, q.PrevRandao = p.ParentHash, p.FeeRecipient, p.StateRoot, p.ReceiptsRoot, p.PrevRandao
	q.BlockNumber, q.GasLimit, q.GasUsed, q.Timestamp = p.BlockNumber, p.GasLimit, p.GasUsed, p.Timestamp
	q.BlockHash, q.BlobGasUsed, q.ExcessBlobGas, q.SlotNumber = p.BlockHash, p.BlobGasUsed, p.ExcessBlobGas, p.SlotNumber
	fee := p.BaseFeePerGas.Bytes32() // big endian
	for i := range fee {
		q.BaseFeePerGas[i] = fee[31-i]
	}
	var err error
	for _, f := range []struct {
		dst *[32]byte
		v   any
	}{
		{&q.LogsBloomRoot, &logsBloomField{V: p.LogsBloom}},
		{&q.ExtraDataRoot, &extraDataField{V: p.ExtraData}},
		{&q.TransactionsRoot, &transactionsField{V: p.Transactions}},
		{&q.WithdrawalsRoot, &withdrawalsField{V: p.Withdrawals}},
		{&q.BlockAccessListRoot, &blockAccessListField{V: p.BlockAccessList}},
		{&s.ExecutionRequestsRoot, env.ExecutionRequests},
	} {
		var r phase0.Root
		if r, err = h.Root(f.v); err != nil {
			return nil, err
		}
		*f.dst = r
	}

	return s, nil
}

func hashPair(a, b [32]byte) [32]byte { return sha256.Sum256(append(a[:], b[:]...)) }

// merkleize is the root of chunks padded with zero chunks to width (a power of two).
func merkleize(chunks [][32]byte, width int) [32]byte {
	layer := make([][32]byte, width)
	copy(layer, chunks)
	for len(layer) > 1 {
		next := make([][32]byte, len(layer)/2)
		for i := range next {
			next[i] = hashPair(layer[2*i], layer[2*i+1])
		}
		layer = next
	}

	return layer[0]
}

// progressive is EIP-7916 merkleize_progressive (remerkleable's
// subtree_fill_progressive): hash(binary tree of the first base chunks,
// progressive rest with base * 4), a zero chunk for none.
func progressive(chunks [][32]byte, base int) [32]byte {
	if len(chunks) == 0 {
		return [32]byte{}
	}
	first := min(len(chunks), base)

	return hashPair(merkleize(chunks[:first], base), progressive(chunks[first:], base*4))
}

// progressiveContainer is hash_tree_root of a ProgressiveContainer with all
// fields active (EIP-7495).
func progressiveContainer(fields ...[32]byte) [32]byte {
	var active [32]byte
	for i := range fields {
		active[i/8] |= 1 << (i % 8)
	}

	return hashPair(progressive(fields, 1), active)
}

func u64Chunk(v uint64) [32]byte { return eth2.Uint64Root(v) }

func addressChunk(a [20]byte) [32]byte {
	var c [32]byte
	copy(c[:], a[:])

	return c
}

// Root is the envelope's hash_tree_root computed from the summary, as the
// signers compute it.
func (e *PayloadEnvelope) Root() [32]byte {
	p := &e.Payload
	payload := progressiveContainer(p.ParentHash, addressChunk(p.FeeRecipient), p.StateRoot, p.ReceiptsRoot,
		p.LogsBloomRoot, p.PrevRandao, u64Chunk(p.BlockNumber), u64Chunk(p.GasLimit), u64Chunk(p.GasUsed),
		u64Chunk(p.Timestamp), p.ExtraDataRoot, p.BaseFeePerGas, p.BlockHash, p.TransactionsRoot, p.WithdrawalsRoot,
		u64Chunk(p.BlobGasUsed), u64Chunk(p.ExcessBlobGas), p.BlockAccessListRoot, u64Chunk(p.SlotNumber))

	return progressiveContainer(payload, e.ExecutionRequestsRoot, u64Chunk(e.BuilderIndex), e.BeaconBlockRoot, e.ParentBeaconBlockRoot)
}
