package backend

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Fixed-size byte types. They marshal to and from 0x-prefixed hex.
type (
	Pubkey    [48]byte
	Signature [96]byte
	Root      [32]byte
	Version   [4]byte
	Address   [20]byte
	// DomainType is the first 4 bytes of a domain, e.g. 0x01000000 for attestations.
	DomainType [4]byte
)

func hexText(b []byte) ([]byte, error) { return []byte("0x" + hex.EncodeToString(b)), nil }

func parseHex(dst []byte, text []byte) error {
	s := strings.TrimPrefix(string(text), "0x")
	if len(s) != 2*len(dst) {
		return fmt.Errorf("want %d hex bytes, got %q", len(dst), text)
	}
	_, err := hex.Decode(dst, []byte(s))
	return err
}

func (v Pubkey) MarshalText() ([]byte, error)     { return hexText(v[:]) }
func (v *Pubkey) UnmarshalText(t []byte) error    { return parseHex(v[:], t) }
func (v Signature) MarshalText() ([]byte, error)  { return hexText(v[:]) }
func (v *Signature) UnmarshalText(t []byte) error { return parseHex(v[:], t) }
func (v Root) MarshalText() ([]byte, error)       { return hexText(v[:]) }
func (v *Root) UnmarshalText(t []byte) error      { return parseHex(v[:], t) }
func (v Version) MarshalText() ([]byte, error)    { return hexText(v[:]) }
func (v *Version) UnmarshalText(t []byte) error   { return parseHex(v[:], t) }
func (v Address) MarshalText() ([]byte, error)    { return hexText(v[:]) }
func (v *Address) UnmarshalText(t []byte) error   { return parseHex(v[:], t) }

func (v Pubkey) String() string { return "0x" + hex.EncodeToString(v[:]) }
func (v Root) String() string   { return "0x" + hex.EncodeToString(v[:]) }

// Domain types from the consensus specs.
var (
	DomainBeaconProposer              = DomainType{0x00, 0, 0, 0}
	DomainBeaconAttester              = DomainType{0x01, 0, 0, 0}
	DomainRandao                      = DomainType{0x02, 0, 0, 0}
	DomainVoluntaryExit               = DomainType{0x04, 0, 0, 0}
	DomainSelectionProof              = DomainType{0x05, 0, 0, 0}
	DomainAggregateAndProof           = DomainType{0x06, 0, 0, 0}
	DomainSyncCommittee               = DomainType{0x07, 0, 0, 0}
	DomainSyncCommitteeSelectionProof = DomainType{0x08, 0, 0, 0}
	DomainContributionAndProof        = DomainType{0x09, 0, 0, 0}
	DomainApplicationBuilder          = DomainType{0x00, 0, 0, 0x01}
)

// Kind tags a message on the wire.
type Kind uint8

const (
	KindAttestation           Kind = 1
	KindBlock                 Kind = 2
	KindVoluntaryExit         Kind = 3
	KindValidatorRegistration Kind = 4
	KindRoot                  Kind = 5
)

func (k Kind) String() string {
	switch k {
	case KindAttestation:
		return "attestation"
	case KindBlock:
		return "block"
	case KindVoluntaryExit:
		return "voluntary_exit"
	case KindValidatorRegistration:
		return "validator_registration"
	case KindRoot:
		return "root"
	}
	if name, ok := gloasKindName(k); ok {
		return name
	}
	if name, ok := aggregateKindName(k); ok {
		return name
	}
	if name, ok := builderAuthKindName(k); ok {
		return name
	}
	return fmt.Sprintf("kind(%d)", uint8(k))
}

// Message is one of the signable types below.
type Message interface {
	Kind() Kind
}

type Checkpoint struct {
	Epoch uint64 `json:"epoch"`
	Root  Root   `json:"root"`
}

// AttestationData is the phase0 container (index is 0 since Electra).
type AttestationData struct {
	Slot            uint64     `json:"slot"`
	Index           uint64     `json:"index"`
	BeaconBlockRoot Root       `json:"beacon_block_root"`
	Source          Checkpoint `json:"source"`
	Target          Checkpoint `json:"target"`
}

// BeaconBlockHeader is what gets signed for a block proposal: the signing
// root of a block equals the signing root of its header.
type BeaconBlockHeader struct {
	Slot          uint64 `json:"slot"`
	ProposerIndex uint64 `json:"proposer_index"`
	ParentRoot    Root   `json:"parent_root"`
	StateRoot     Root   `json:"state_root"`
	BodyRoot      Root   `json:"body_root"`
}

type VoluntaryExit struct {
	Epoch          uint64 `json:"epoch"`
	ValidatorIndex uint64 `json:"validator_index"`
}

// ValidatorRegistration is builder-specs ValidatorRegistrationV1.
type ValidatorRegistration struct {
	FeeRecipient Address `json:"fee_recipient"`
	GasLimit     uint64  `json:"gas_limit"`
	Timestamp    uint64  `json:"timestamp"`
	Pubkey       Pubkey  `json:"pubkey"`
}

// RootType names the Web3Signer message types that carry no slashing risk
// and reach the backend as an object root plus domain.
type RootType uint8

const (
	RootRandaoReveal                      RootType = 1 // RANDAO_REVEAL
	RootAggregationSlot                   RootType = 2 // AGGREGATION_SLOT (selection proof)
	RootAggregateAndProof                 RootType = 3 // AGGREGATE_AND_PROOF, AGGREGATE_AND_PROOF_V2
	RootSyncCommitteeMessage              RootType = 4 // SYNC_COMMITTEE_MESSAGE
	RootSyncCommitteeSelectionProof       RootType = 5 // SYNC_COMMITTEE_SELECTION_PROOF
	RootSyncCommitteeContributionAndProof RootType = 6 // SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF
	// Gloas, for stock clients that send them as a generic Sign (Vouch). The
	// core signs them from the Gloas fork epoch on. None is slashable.
	RootPayloadAttestation  RootType = 7 // PAYLOAD_ATTESTATION (PTC vote), DOMAIN_PTC_ATTESTER
	RootPayloadEnvelope     RootType = 8 // EXECUTION_PAYLOAD_ENVELOPE, DOMAIN_BEACON_BUILDER
	RootProposerPreferences RootType = 9 // PROPOSER_PREFERENCES, DOMAIN_PROPOSER_PREFERENCES
)

// DomainType returns the domain type a root message of this type must use.
func (t RootType) DomainType() (DomainType, bool) {
	switch t {
	case RootRandaoReveal:
		return DomainRandao, true
	case RootAggregationSlot:
		return DomainSelectionProof, true
	case RootAggregateAndProof:
		return DomainAggregateAndProof, true
	case RootSyncCommitteeMessage:
		return DomainSyncCommittee, true
	case RootSyncCommitteeSelectionProof:
		return DomainSyncCommitteeSelectionProof, true
	case RootSyncCommitteeContributionAndProof:
		return DomainContributionAndProof, true
	case RootPayloadAttestation:
		return DomainPTCAttester, true
	case RootPayloadEnvelope:
		return DomainBeaconBuilder, true
	case RootProposerPreferences:
		return DomainProposerPreferences, true
	}
	return DomainType{}, false
}

// Unverified reports whether the backend signs a root of this type without
// being able to check the object behind it: every type but RANDAO, whose
// root the core checks against the epoch. Aggregates and contributions
// reach it as the root the Dirk adapter computed; a selection proof, a sync
// committee message and a sync selection proof carry a slot, a block root
// or a subcommittee the root message does not hold. The Gloas roots skip
// the typed kinds' checks: one PTC vote and one envelope per slot, the
// envelope's block and builder index, and the fee recipient and gas limit
// of an envelope or proposer preferences. Only the switch
// allow_unverified_nonslashable lets them through; the typed kinds carry
// the whole message.
func (t RootType) Unverified() bool {
	switch t {
	case RootAggregationSlot, RootAggregateAndProof, RootSyncCommitteeMessage,
		RootSyncCommitteeSelectionProof, RootSyncCommitteeContributionAndProof,
		RootPayloadAttestation, RootPayloadEnvelope, RootProposerPreferences:
		return true
	}
	return false
}

// RootMessage is the tagged generic request. The backend recomputes the
// domain from Type and Epoch with its own chain config and refuses the
// request if Domain differs, so a caller cannot pick the fork or chain.
type RootMessage struct {
	Type       RootType `json:"type"`
	Epoch      uint64   `json:"epoch"` // epoch the domain is computed for
	ObjectRoot Root     `json:"object_root"`
	Domain     Root     `json:"domain"`
}

func (*AttestationData) Kind() Kind       { return KindAttestation }
func (*BeaconBlockHeader) Kind() Kind     { return KindBlock }
func (*VoluntaryExit) Kind() Kind         { return KindVoluntaryExit }
func (*ValidatorRegistration) Kind() Kind { return KindValidatorRegistration }
func (*RootMessage) Kind() Kind           { return KindRoot }
