// Package signing turns a Web3Signer eth2 signing request body into a Job: the
// signer call to make, its domain, and the signing root the result must cover.
//
// Request format: github.com/Consensys/web3signer openapi-specs/eth2/signing
// (checked against tag 26.9.0).
package signing

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/lidofinance/tee-signer/web3signer-api/eth2"
)

// Request types handled by the gateway.
const (
	TypeAttestation                       = "ATTESTATION"
	TypeBlockV2                           = "BLOCK_V2"
	TypeRandaoReveal                      = "RANDAO_REVEAL"
	TypeAggregationSlot                   = "AGGREGATION_SLOT"
	TypeAggregateAndProof                 = "AGGREGATE_AND_PROOF"
	TypeAggregateAndProofV2               = "AGGREGATE_AND_PROOF_V2"
	TypeSyncCommitteeMessage              = "SYNC_COMMITTEE_MESSAGE"
	TypeSyncCommitteeSelectionProof       = "SYNC_COMMITTEE_SELECTION_PROOF"
	TypeSyncCommitteeContributionAndProof = "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF"
	TypeValidatorRegistration             = "VALIDATOR_REGISTRATION"
	TypeVoluntaryExit                     = "VOLUNTARY_EXIT"
)

// Method says which call of the eth2 signer gRPC API signs a job.
type Method int

const (
	// MethodGeneric is Signer.Sign: the signer signs (root, domain) with no slashing checks.
	MethodGeneric Method = iota
	// MethodAttestation is Signer.SignBeaconAttestation: the signer applies attestation slashing protection.
	MethodAttestation
	// MethodProposal is Signer.SignBeaconProposal: the signer applies proposal slashing protection.
	MethodProposal
	// MethodNone marks jobs that policy always refuses; they carry no signing data.
	MethodNone
	// MethodTyped is a typed call only (the Gloas types): a signer without
	// typed calls refuses the job, it never goes out as a bare root.
	MethodTyped
)

func (m Method) String() string {
	switch m {
	case MethodGeneric:
		return "Sign"
	case MethodAttestation:
		return "SignBeaconAttestation"
	case MethodProposal:
		return "SignBeaconProposal"
	case MethodTyped:
		return "typed"
	default:
		return "none"
	}
}

// Chain holds the network constants a request does not carry.
type Chain struct {
	// Hasher computes hash_tree_root with the network's preset (list limits).
	Hasher             *eth2.Hasher
	SlotsPerEpoch      uint64
	GenesisForkVersion phase0.Version
	// Pin is the chain the gateway signs for. With a pin, domains come from
	// the pinned fork schedule and genesis_validators_root, and a request
	// whose fork_info disagrees is a bad request. Without one (tests of the
	// Web3Signer examples), domains come from fork_info as in Web3Signer.
	Pin *Pin
	// VoluntaryExitForkVersion is the fork version exits are signed with
	// (EIP-7044: Capella's, from Deneb on). Nil, as in the gateway, leaves
	// exits without a domain: they are refused by policy. Needs Pin.
	VoluntaryExitForkVersion *phase0.Version
	// GloasForkEpoch is the chain's GLOAS_FORK_EPOCH. Nil: Gloas is not
	// scheduled and every Gloas-only type is refused. From this epoch on,
	// aggregates hash as Gloas aggregates.
	GloasForkEpoch *phase0.Epoch
}

// gloasAt reports whether epoch is at or past the configured Gloas fork.
func (c Chain) gloasAt(epoch phase0.Epoch) bool {
	return c.GloasForkEpoch != nil && epoch >= *c.GloasForkEpoch
}

// ForkEpoch is one entry of a fork schedule: the fork version from Epoch on.
type ForkEpoch struct {
	Epoch   phase0.Epoch
	Version phase0.Version
}

// Pin is a chain's identity: its genesis_validators_root and fork schedule.
type Pin struct {
	GenesisValidatorsRoot phase0.Root
	// Forks starts with the genesis fork version at epoch 0, then each fork
	// in order of epoch (several may share one epoch, as on devnets).
	Forks []ForkEpoch
}

// versionAt is the fork version the schedule gives for epoch.
func (p *Pin) versionAt(epoch phase0.Epoch) phase0.Version {
	v := p.Forks[0].Version
	for _, f := range p.Forks {
		if f.Epoch <= epoch {
			v = f.Version
		}
	}

	return v
}

// knows reports whether fork is one a beacon state of this chain can carry:
// a schedule entry with the entry before it as previous_version (the genesis
// entry is its own previous version), or the genesis state's fork. A chain
// that starts at a later fork (a devnet with several forks at epoch 0) has
// that fork as previous and current version at epoch 0.
//
// The fork's epoch may be any epoch in the entry's period, not only its first:
// Lodestar v1.49.0 sends the current epoch there on a devnet whose forks all
// start at epoch 0. The domain does not use the epoch, and domain() below
// still checks the version against the pinned schedule.
func (p *Pin) knows(fork *phase0.Fork) bool {
	if fork.Epoch == 0 && fork.PreviousVersion == fork.CurrentVersion && fork.CurrentVersion == p.versionAt(0) {
		return true
	}
	for i, f := range p.Forks {
		prev := f.Version
		if i > 0 {
			prev = p.Forks[i-1].Version
		}
		inPeriod := fork.Epoch >= f.Epoch && (i+1 == len(p.Forks) || fork.Epoch < p.Forks[i+1].Epoch)
		if inPeriod && fork.CurrentVersion == f.Version && fork.PreviousVersion == prev {
			return true
		}
	}

	return false
}

// domain checks fork_info against the pin and returns the domain the pinned
// schedule gives for domainType at epoch.
func (p *Pin) domain(fi *forkInfo, domainType phase0.DomainType, epoch phase0.Epoch) (phase0.Domain, error) {
	if fi.gvr != p.GenesisValidatorsRoot {
		return phase0.Domain{}, badRequest("fork_info.genesis_validators_root %#x is not the configured chain's %#x",
			fi.gvr, p.GenesisValidatorsRoot)
	}
	if !p.knows(fi.fork) {
		return phase0.Domain{}, badRequest("fork_info.fork (previous_version %#x, current_version %#x, epoch %d) is not in the configured fork schedule",
			fi.fork.PreviousVersion, fi.fork.CurrentVersion, fi.fork.Epoch)
	}
	asked := fi.fork.CurrentVersion
	if epoch < fi.fork.Epoch {
		asked = fi.fork.PreviousVersion
	}
	if want := p.versionAt(epoch); asked != want {
		return phase0.Domain{}, badRequest("fork_info gives fork version %#x for epoch %d; the configured chain has %#x",
			asked, epoch, want)
	}

	return eth2.ComputeDomain(domainType, asked, p.GenesisValidatorsRoot)
}

// Job is a parsed, validated signing request.
type Job struct {
	Type   string
	Method Method
	// Domain and ObjectRoot are what the signer signs for MethodGeneric. For the
	// typed methods the signer derives the object root from the typed data itself.
	Domain      phase0.Domain
	ObjectRoot  phase0.Root
	SigningRoot phase0.Root

	Attestation   *phase0.AttestationData
	Proposal      *phase0.BeaconBlockHeader
	Registration  *apiv1.ValidatorRegistration
	VoluntaryExit *phase0.VoluntaryExit
	// Typed is the request data for a MethodGeneric job, for a signer with
	// typed calls (the signing client). It is one of *RandaoReveal,
	// *AggregationSlot, *phase0.AggregateAndProof, *electra.AggregateAndProof,
	// *SyncCommitteeMessage, *altair.SyncAggregatorSelectionData,
	// *altair.ContributionAndProof, *apiv1.ValidatorRegistration, or
	// *phase0.VoluntaryExit (MethodNone unless Chain.VoluntaryExitForkVersion is set),
	// *GloasAggregateAndProof, or for MethodTyped *gloas.PayloadAttestationData,
	// *PayloadEnvelope, *gloas.ProposerPreferences or *gloas.BuilderRequestAuth.
	Typed any
	// Refusal says why policy refuses a MethodNone job, when parsing knows.
	Refusal string
}

// RandaoReveal is the data of a RANDAO_REVEAL request.
type RandaoReveal struct{ Epoch phase0.Epoch }

// AggregationSlot is the data of an AGGREGATION_SLOT request.
type AggregationSlot struct{ Slot phase0.Slot }

// SyncCommitteeMessage is the data of a SYNC_COMMITTEE_MESSAGE request.
type SyncCommitteeMessage struct {
	Slot            phase0.Slot
	BeaconBlockRoot phase0.Root
}

// BadRequestError means the body is malformed or inconsistent (HTTP 400).
type BadRequestError struct{ msg string }

func (e *BadRequestError) Error() string { return e.msg }

func badRequest(format string, args ...any) error {
	return &BadRequestError{msg: fmt.Sprintf(format, args...)}
}

// IsBadRequest reports whether err is a *BadRequestError.
func IsBadRequest(err error) bool {
	var e *BadRequestError

	return errors.As(err, &e)
}

type forkInfoJSON struct {
	Fork                  *phase0.Fork `json:"fork"`
	GenesisValidatorsRoot string       `json:"genesis_validators_root"`
}

type requestJSON struct {
	Type string `json:"type"`
	// Web3Signer reads signing_root and accepts signingRoot as an alias.
	SigningRoot      string        `json:"signing_root"`
	SigningRootAlias string        `json:"signingRoot"`
	ForkInfo         *forkInfoJSON `json:"fork_info"`

	Attestation                 json.RawMessage `json:"attestation"`
	BeaconBlock                 json.RawMessage `json:"beacon_block"`
	RandaoReveal                json.RawMessage `json:"randao_reveal"`
	AggregationSlot             json.RawMessage `json:"aggregation_slot"`
	AggregateAndProof           json.RawMessage `json:"aggregate_and_proof"`
	SyncCommitteeMessage        json.RawMessage `json:"sync_committee_message"`
	SyncAggregatorSelectionData json.RawMessage `json:"sync_aggregator_selection_data"`
	ContributionAndProof        json.RawMessage `json:"contribution_and_proof"`
	ValidatorRegistration       json.RawMessage `json:"validator_registration"`
	VoluntaryExit               json.RawMessage `json:"voluntary_exit"`
	// Gloas, each {"version":"GLOAS","data":...} or the bare data.
	PayloadAttestationMessage json.RawMessage `json:"payload_attestation_message"`
	// Grandine's PAYLOAD_ATTESTATION: the bare PayloadAttestationData.
	PayloadAttestation       json.RawMessage `json:"payload_attestation"`
	ExecutionPayloadEnvelope json.RawMessage `json:"execution_payload_envelope"`
	ProposerPreferences      json.RawMessage `json:"proposer_preferences"`
	ExecutionPayloadBid      json.RawMessage `json:"execution_payload_bid"`
	BuilderRequestAuth       json.RawMessage `json:"builder_request_auth"`
}

type forkInfo struct {
	fork *phase0.Fork
	gvr  phase0.Root
}

// Parse validates body and builds the Job. All errors are *BadRequestError.
func Parse(body []byte, chain Chain) (*Job, error) {
	var req requestJSON
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, badRequest("invalid JSON body: %v", err)
	}
	if req.Type == "" {
		return nil, badRequest("missing type")
	}
	if chain.SlotsPerEpoch == 0 || chain.Hasher == nil {
		return nil, errors.New("chain is not configured")
	}

	job, err := build(&req, chain)
	if err != nil {
		return nil, err
	}

	claimed := req.SigningRoot
	if claimed == "" {
		claimed = req.SigningRootAlias
	}
	if claimed != "" && job.Method != MethodNone {
		root, err := parseRoot(claimed)
		if err != nil {
			return nil, badRequest("signing_root: %v", err)
		}
		if root != job.SigningRoot {
			return nil, badRequest("signing root %#x must match signing root %#x computed from data", root, job.SigningRoot)
		}
	}

	return job, nil
}

func build(req *requestJSON, chain Chain) (*Job, error) {
	switch req.Type {
	case TypeAttestation:
		return buildAttestation(req, chain)
	case TypeBlockV2:
		return buildBlockV2(req, chain)
	case TypeRandaoReveal:
		return buildRandao(req, chain)
	case TypeAggregationSlot:
		return buildAggregationSlot(req, chain)
	case TypeAggregateAndProof, TypeAggregateAndProofV2:
		return buildAggregateAndProof(req, chain)
	case TypeSyncCommitteeMessage:
		return buildSyncCommitteeMessage(req, chain)
	case TypeSyncCommitteeSelectionProof:
		return buildSyncSelectionProof(req, chain)
	case TypeSyncCommitteeContributionAndProof:
		return buildContributionAndProof(req, chain)
	case TypeValidatorRegistration:
		return buildValidatorRegistration(req, chain)
	case TypeVoluntaryExit:
		return buildVoluntaryExit(req, chain)
	case TypePayloadAttestationMessage, TypePayloadAttestation:
		return buildPayloadAttestation(req, chain)
	case TypeExecutionPayloadEnvelope:
		return buildPayloadEnvelope(req, chain)
	case TypeProposerPreferences:
		return buildProposerPreferences(req, chain)
	case TypeExecutionPayloadBid:
		return refused(req, "validators never sign bids: a self-build bid carries the point at infinity (consensus-specs gloas validator.md)"), nil
	case TypeBuilderRequestAuth:
		return buildBuilderRequestAuth(req, chain)
	default:
		return nil, badRequest("unsupported signing type %q", req.Type)
	}
}

func (req *requestJSON) forkInfo() (*forkInfo, error) {
	if req.ForkInfo == nil || req.ForkInfo.Fork == nil {
		return nil, badRequest("fork_info with fork is required for %s", req.Type)
	}
	gvr, err := parseRoot(req.ForkInfo.GenesisValidatorsRoot)
	if err != nil {
		return nil, badRequest("fork_info.genesis_validators_root: %v", err)
	}

	return &forkInfo{fork: req.ForkInfo.Fork, gvr: gvr}, nil
}

// domainFor is the domain for domainType at epoch: from the chain pin when
// there is one (fork_info must agree with it), else from fork_info.
func domainFor(req *requestJSON, chain Chain, domainType phase0.DomainType, epoch phase0.Epoch) (phase0.Domain, error) {
	fi, err := req.forkInfo()
	if err != nil {
		return phase0.Domain{}, err
	}
	if chain.Pin != nil {
		return chain.Pin.domain(fi, domainType, epoch)
	}

	return eth2.ForkDomain(domainType, fi.fork, fi.gvr, epoch)
}

// generic builds a MethodGeneric job for objectRoot under domainType at
// epoch, with typed, the request data for typed calls.
func generic(req *requestJSON, chain Chain, domainType phase0.DomainType, epoch phase0.Epoch, objectRoot phase0.Root, typed any) (*Job, error) {
	domain, err := domainFor(req, chain, domainType, epoch)
	if err != nil {
		return nil, err
	}

	return finish(&Job{Type: req.Type, Method: MethodGeneric, Domain: domain, ObjectRoot: objectRoot, Typed: typed})
}

func finish(job *Job) (*Job, error) {
	root, err := eth2.SigningRoot(job.ObjectRoot, job.Domain)
	if err != nil {
		return nil, err
	}
	job.SigningRoot = root

	return job, nil
}

func unmarshalField(name string, raw json.RawMessage, v any) error {
	if len(raw) == 0 || string(raw) == "null" {
		return badRequest("%s must be specified", name)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return badRequest("%s: %v", name, err)
	}

	return nil
}

func buildAttestation(req *requestJSON, chain Chain) (*Job, error) {
	data := &phase0.AttestationData{}
	if err := unmarshalField("attestation", req.Attestation, data); err != nil {
		return nil, err
	}
	domain, err := domainFor(req, chain, eth2.DomainBeaconAttester, data.Target.Epoch)
	if err != nil {
		return nil, err
	}
	objectRoot, err := chain.Hasher.Root(data)
	if err != nil {
		return nil, badRequest("attestation root: %v", err)
	}

	return finish(&Job{
		Type: req.Type, Method: MethodAttestation, Domain: domain, ObjectRoot: objectRoot,
		Attestation: data,
	})
}

type blockRequestJSON struct {
	Version     string          `json:"version"`
	Block       json.RawMessage `json:"block"`
	BlockHeader json.RawMessage `json:"block_header"`
}

func buildBlockV2(req *requestJSON, chain Chain) (*Job, error) {
	var br blockRequestJSON
	if err := unmarshalField("beacon_block", req.BeaconBlock, &br); err != nil {
		return nil, err
	}

	header := &phase0.BeaconBlockHeader{}
	switch strings.ToUpper(br.Version) {
	case "PHASE0":
		block := &phase0.BeaconBlock{}
		if err := unmarshalField("beacon_block.block", br.Block, block); err != nil {
			return nil, err
		}
		bodyRoot, err := chain.Hasher.Root(block.Body)
		if err != nil {
			return nil, badRequest("block body root: %v", err)
		}
		header = &phase0.BeaconBlockHeader{
			Slot: block.Slot, ProposerIndex: block.ProposerIndex,
			ParentRoot: block.ParentRoot, StateRoot: block.StateRoot, BodyRoot: bodyRoot,
		}
	case "ALTAIR":
		block := &altair.BeaconBlock{}
		if err := unmarshalField("beacon_block.block", br.Block, block); err != nil {
			return nil, err
		}
		bodyRoot, err := chain.Hasher.Root(block.Body)
		if err != nil {
			return nil, badRequest("block body root: %v", err)
		}
		header = &phase0.BeaconBlockHeader{
			Slot: block.Slot, ProposerIndex: block.ProposerIndex,
			ParentRoot: block.ParentRoot, StateRoot: block.StateRoot, BodyRoot: bodyRoot,
		}
	case "BELLATRIX", "CAPELLA", "DENEB", "ELECTRA", "FULU", "GLOAS":
		if err := unmarshalField("beacon_block.block_header", br.BlockHeader, header); err != nil {
			return nil, err
		}
	case "":
		return nil, badRequest("beacon_block.version must be specified")
	default:
		return nil, badRequest("unsupported beacon_block.version %q", br.Version)
	}

	domain, err := domainFor(req, chain, eth2.DomainBeaconProposer, eth2.EpochAtSlot(header.Slot, chain.SlotsPerEpoch))
	if err != nil {
		return nil, err
	}
	// hash_tree_root(BeaconBlock) == hash_tree_root(BeaconBlockHeader) by construction.
	objectRoot, err := chain.Hasher.Root(header)
	if err != nil {
		return nil, badRequest("block header root: %v", err)
	}

	return finish(&Job{
		Type: req.Type, Method: MethodProposal, Domain: domain, ObjectRoot: objectRoot,
		Proposal: header,
	})
}

type epochJSON struct {
	Epoch string `json:"epoch"`
}

type slotJSON struct {
	Slot string `json:"slot"`
}

func buildRandao(req *requestJSON, chain Chain) (*Job, error) {
	var r epochJSON
	if err := unmarshalField("randao_reveal", req.RandaoReveal, &r); err != nil {
		return nil, err
	}
	epoch, err := parseUint("randao_reveal.epoch", r.Epoch)
	if err != nil {
		return nil, err
	}

	return generic(req, chain, eth2.DomainRandao, phase0.Epoch(epoch), eth2.Uint64Root(epoch), &RandaoReveal{Epoch: phase0.Epoch(epoch)})
}

func buildAggregationSlot(req *requestJSON, chain Chain) (*Job, error) {
	var s slotJSON
	if err := unmarshalField("aggregation_slot", req.AggregationSlot, &s); err != nil {
		return nil, err
	}
	slot, err := parseUint("aggregation_slot.slot", s.Slot)
	if err != nil {
		return nil, err
	}

	return generic(req, chain, eth2.DomainSelectionProof, eth2.EpochAtSlot(phase0.Slot(slot), chain.SlotsPerEpoch), eth2.Uint64Root(slot),
		&AggregationSlot{Slot: phase0.Slot(slot)})
}

type versionedJSON struct {
	Version string          `json:"version"`
	Data    json.RawMessage `json:"data"`
}

// hasCommitteeBits reports whether an unversioned aggregate_and_proof object
// is in the Electra form: its aggregate carries committee_bits.
func hasCommitteeBits(raw json.RawMessage) bool {
	var ap struct {
		Aggregate struct {
			CommitteeBits *string `json:"committee_bits"`
		} `json:"aggregate"`
	}

	return json.Unmarshal(raw, &ap) == nil && ap.Aggregate.CommitteeBits != nil
}

func buildAggregateAndProof(req *requestJSON, chain Chain) (*Job, error) {
	if len(req.AggregateAndProof) == 0 || string(req.AggregateAndProof) == "null" {
		return nil, badRequest("aggregate_and_proof must be specified")
	}
	// Like Web3Signer, accept both {"version","data"} (V2) and the bare phase0 object (V1).
	var v versionedJSON
	_ = json.Unmarshal(req.AggregateAndProof, &v)
	version, raw := "PHASE0", json.RawMessage(req.AggregateAndProof)
	if v.Version != "" && len(v.Data) > 0 {
		version, raw = strings.ToUpper(v.Version), v.Data
	} else if hasCommitteeBits(raw) {
		// Lighthouse v8 sends type AGGREGATE_AND_PROOF with the bare Electra object
		// (an aggregate with committee_bits) and signs its Electra root. The signing
		// client's typed call picks the form the same way.
		version = "ELECTRA"
	}

	var (
		slot       phase0.Slot
		objectRoot phase0.Root
		typed      any
		err        error
	)
	switch version {
	case "PHASE0", "ALTAIR", "BELLATRIX", "CAPELLA", "DENEB":
		ap := &phase0.AggregateAndProof{}
		if err := unmarshalField("aggregate_and_proof", raw, ap); err != nil {
			return nil, err
		}
		if ap.Aggregate == nil || ap.Aggregate.Data == nil {
			return nil, badRequest("aggregate_and_proof.aggregate.data must be specified")
		}
		slot = ap.Aggregate.Data.Slot
		objectRoot, err = chain.Hasher.Root(ap)
		typed = ap
	case "ELECTRA", "FULU", "GLOAS":
		ap := &electra.AggregateAndProof{}
		if err := unmarshalField("aggregate_and_proof", raw, ap); err != nil {
			return nil, err
		}
		if ap.Aggregate == nil || ap.Aggregate.Data == nil {
			return nil, badRequest("aggregate_and_proof.aggregate.data must be specified")
		}
		slot = ap.Aggregate.Data.Slot
		// Gloas hashes the same bytes as a progressive Attestation
		// (consensus-specs specs/gloas/beacon-chain.md "Attestation"). The
		// aggregate's epoch decides; a version that disagrees is an error.
		isGloas := chain.gloasAt(eth2.EpochAtSlot(slot, chain.SlotsPerEpoch))
		switch {
		case version == "GLOAS" && !isGloas:
			return nil, badRequest("aggregate_and_proof version GLOAS for slot %d, before the configured Gloas fork", slot)
		case isGloas && v.Version != "":
			if version != "GLOAS" {
				return nil, badRequest("aggregate_and_proof version %s for slot %d, after the Gloas fork", version, slot)
			}
		}
		if isGloas {
			// Bare objects (Lighthouse's AGGREGATE_AND_PROOF) take the form of their epoch too.
			g := &gloas.AggregateAndProof{AggregatorIndex: ap.AggregatorIndex, SelectionProof: ap.SelectionProof,
				Aggregate: &gloas.Attestation{AggregationBits: ap.Aggregate.AggregationBits, Data: ap.Aggregate.Data,
					Signature: ap.Aggregate.Signature, CommitteeBits: ap.Aggregate.CommitteeBits}}
			objectRoot, err = chain.Hasher.Root(g)
			typed = &GloasAggregateAndProof{g}

			break
		}
		objectRoot, err = chain.Hasher.Root(ap)
		typed = ap
	default:
		return nil, badRequest("unsupported aggregate_and_proof.version %q", version)
	}
	if err != nil {
		return nil, badRequest("aggregate_and_proof root: %v", err)
	}

	return generic(req, chain, eth2.DomainAggregateAndProof, eth2.EpochAtSlot(slot, chain.SlotsPerEpoch), objectRoot, typed)
}

type syncCommitteeMessageJSON struct {
	BeaconBlockRoot string `json:"beacon_block_root"`
	Slot            string `json:"slot"`
}

func buildSyncCommitteeMessage(req *requestJSON, chain Chain) (*Job, error) {
	var m syncCommitteeMessageJSON
	if err := unmarshalField("sync_committee_message", req.SyncCommitteeMessage, &m); err != nil {
		return nil, err
	}
	slot, err := parseUint("sync_committee_message.slot", m.Slot)
	if err != nil {
		return nil, err
	}
	root, err := parseRoot(m.BeaconBlockRoot)
	if err != nil {
		return nil, badRequest("sync_committee_message.beacon_block_root: %v", err)
	}

	// The signed object is the block root itself (hash_tree_root(Root) == Root).
	return generic(req, chain, eth2.DomainSyncCommittee, eth2.EpochAtSlot(phase0.Slot(slot), chain.SlotsPerEpoch), root,
		&SyncCommitteeMessage{Slot: phase0.Slot(slot), BeaconBlockRoot: root})
}

// syncAggregatorSelectionDataJSON names the fields explicitly:
// altair.SyncAggregatorSelectionData has no JSON tags, so a plain unmarshal
// drops subcommittee_index and signs for subcommittee 0.
type syncAggregatorSelectionDataJSON struct {
	Slot              string `json:"slot"`
	SubcommitteeIndex string `json:"subcommittee_index"`
}

func buildSyncSelectionProof(req *requestJSON, chain Chain) (*Job, error) {
	var m syncAggregatorSelectionDataJSON
	if err := unmarshalField("sync_aggregator_selection_data", req.SyncAggregatorSelectionData, &m); err != nil {
		return nil, err
	}
	slot, err := parseUint("sync_aggregator_selection_data.slot", m.Slot)
	if err != nil {
		return nil, err
	}
	index, err := parseUint("sync_aggregator_selection_data.subcommittee_index", m.SubcommitteeIndex)
	if err != nil {
		return nil, err
	}
	data := &altair.SyncAggregatorSelectionData{Slot: phase0.Slot(slot), SubcommitteeIndex: index}
	objectRoot, err := chain.Hasher.Root(data)
	if err != nil {
		return nil, badRequest("sync_aggregator_selection_data root: %v", err)
	}

	return generic(req, chain, eth2.DomainSyncCommitteeSelectionProof, eth2.EpochAtSlot(data.Slot, chain.SlotsPerEpoch), objectRoot, data)
}

func buildContributionAndProof(req *requestJSON, chain Chain) (*Job, error) {
	cp := &altair.ContributionAndProof{}
	if err := unmarshalField("contribution_and_proof", req.ContributionAndProof, cp); err != nil {
		return nil, err
	}
	if cp.Contribution == nil {
		return nil, badRequest("contribution_and_proof.contribution must be specified")
	}
	objectRoot, err := chain.Hasher.Root(cp)
	if err != nil {
		return nil, badRequest("contribution_and_proof root: %v", err)
	}

	return generic(req, chain, eth2.DomainContributionAndProof, eth2.EpochAtSlot(cp.Contribution.Slot, chain.SlotsPerEpoch), objectRoot, cp)
}

func buildValidatorRegistration(req *requestJSON, chain Chain) (*Job, error) {
	reg := &apiv1.ValidatorRegistration{}
	if err := unmarshalField("validator_registration", req.ValidatorRegistration, reg); err != nil {
		return nil, err
	}
	objectRoot, err := chain.Hasher.Root(reg)
	if err != nil {
		return nil, badRequest("validator_registration root: %v", err)
	}
	// Builder spec: compute_domain(DOMAIN_APPLICATION_BUILDER) with the genesis
	// fork version and a zero genesis_validators_root; fork_info is not used.
	domain, err := eth2.ComputeDomain(eth2.DomainApplicationBuilder, chain.GenesisForkVersion, phase0.Root{})
	if err != nil {
		return nil, err
	}

	return finish(&Job{
		Type: req.Type, Method: MethodGeneric, Domain: domain, ObjectRoot: objectRoot,
		Registration: reg, Typed: reg,
	})
}

func buildVoluntaryExit(req *requestJSON, chain Chain) (*Job, error) {
	exit := &phase0.VoluntaryExit{}
	if err := unmarshalField("voluntary_exit", req.VoluntaryExit, exit); err != nil {
		return nil, err
	}
	// Without a configured exit fork version the gateway computes no domain:
	// its policy refuses every exit.
	if chain.VoluntaryExitForkVersion == nil || chain.Pin == nil {
		return &Job{Type: req.Type, Method: MethodNone, VoluntaryExit: exit, Typed: exit}, nil
	}
	// fork_info must still name this chain: the state's fork (Teku), or the
	// EIP-7044 fork Lighthouse sends for exits, previous and current version
	// both the exit fork version, at any epoch. The domain below does not
	// depend on it.
	fi, err := req.forkInfo()
	if err != nil {
		return nil, err
	}
	eip7044 := fi.fork.PreviousVersion == *chain.VoluntaryExitForkVersion && fi.fork.CurrentVersion == *chain.VoluntaryExitForkVersion
	if fi.gvr != chain.Pin.GenesisValidatorsRoot || !eip7044 {
		if _, err := domainFor(req, chain, eth2.DomainVoluntaryExit, exit.Epoch); err != nil {
			return nil, err
		}
	}
	// EIP-7044: from Deneb on, exits use the Capella fork version at any epoch.
	domain, err := eth2.ComputeDomain(eth2.DomainVoluntaryExit, *chain.VoluntaryExitForkVersion, chain.Pin.GenesisValidatorsRoot)
	if err != nil {
		return nil, err
	}
	objectRoot, err := exit.HashTreeRoot()
	if err != nil {
		return nil, badRequest("voluntary_exit root: %v", err)
	}

	return finish(&Job{
		Type: req.Type, Method: MethodGeneric, Domain: domain, ObjectRoot: objectRoot,
		VoluntaryExit: exit, Typed: exit,
	})
}

func parseUint(name, s string) (uint64, error) {
	if s == "" {
		return 0, badRequest("%s must be specified", name)
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, badRequest("%s: %v", name, err)
	}

	return v, nil
}

func parseRoot(s string) (phase0.Root, error) {
	var root phase0.Root
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		return root, fmt.Errorf("invalid hex: %w", err)
	}
	if len(b) != len(root) {
		return root, fmt.Errorf("want 32 bytes, got %d", len(b))
	}
	copy(root[:], b)

	return root, nil
}
