// Package eth2 computes consensus-spec domains and signing roots.
package eth2

import (
	"encoding/binary"
	"fmt"

	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// Domain types from the consensus specs (phase0, altair) and the builder spec.
var (
	DomainBeaconProposer              = phase0.DomainType{0x00, 0x00, 0x00, 0x00}
	DomainBeaconAttester              = phase0.DomainType{0x01, 0x00, 0x00, 0x00}
	DomainRandao                      = phase0.DomainType{0x02, 0x00, 0x00, 0x00}
	DomainDeposit                     = phase0.DomainType{0x03, 0x00, 0x00, 0x00}
	DomainVoluntaryExit               = phase0.DomainType{0x04, 0x00, 0x00, 0x00}
	DomainSelectionProof              = phase0.DomainType{0x05, 0x00, 0x00, 0x00}
	DomainAggregateAndProof           = phase0.DomainType{0x06, 0x00, 0x00, 0x00}
	DomainSyncCommittee               = phase0.DomainType{0x07, 0x00, 0x00, 0x00}
	DomainSyncCommitteeSelectionProof = phase0.DomainType{0x08, 0x00, 0x00, 0x00}
	DomainContributionAndProof        = phase0.DomainType{0x09, 0x00, 0x00, 0x00}
	DomainApplicationBuilder          = phase0.DomainType{0x00, 0x00, 0x00, 0x01}
	// Gloas (consensus-specs specs/gloas/beacon-chain.md "Domains").
	DomainBeaconBuilder       = phase0.DomainType{0x0b, 0x00, 0x00, 0x00}
	DomainPTCAttester         = phase0.DomainType{0x0c, 0x00, 0x00, 0x00}
	DomainProposerPreferences = phase0.DomainType{0x0d, 0x00, 0x00, 0x00}
	// DOMAIN_BUILDER_REQUEST_AUTH (builder-specs specs/gloas/builder.md).
	DomainBuilderRequestAuth = phase0.DomainType{0x0b, 0x00, 0x00, 0x01}
)

// ComputeDomain is compute_domain(domain_type, fork_version, genesis_validators_root).
func ComputeDomain(domainType phase0.DomainType, forkVersion phase0.Version, genesisValidatorsRoot phase0.Root) (phase0.Domain, error) {
	forkData := &phase0.ForkData{
		CurrentVersion:        forkVersion,
		GenesisValidatorsRoot: genesisValidatorsRoot,
	}
	forkDataRoot, err := forkData.HashTreeRoot()
	if err != nil {
		return phase0.Domain{}, fmt.Errorf("fork data root: %w", err)
	}
	var domain phase0.Domain
	copy(domain[:4], domainType[:])
	copy(domain[4:], forkDataRoot[:28])

	return domain, nil
}

// ForkDomain is get_domain() with the fork taken from the request instead of a
// beacon state: previous_version before fork.epoch, current_version from it on.
func ForkDomain(domainType phase0.DomainType, fork *phase0.Fork, genesisValidatorsRoot phase0.Root, epoch phase0.Epoch) (phase0.Domain, error) {
	version := fork.CurrentVersion
	if epoch < fork.Epoch {
		version = fork.PreviousVersion
	}

	return ComputeDomain(domainType, version, genesisValidatorsRoot)
}

// SigningRoot is compute_signing_root: hash_tree_root(SigningData(object_root, domain)).
func SigningRoot(objectRoot phase0.Root, domain phase0.Domain) (phase0.Root, error) {
	data := &phase0.SigningData{ObjectRoot: objectRoot, Domain: domain}
	root, err := data.HashTreeRoot()
	if err != nil {
		return phase0.Root{}, fmt.Errorf("signing data root: %w", err)
	}

	return root, nil
}

// Uint64Root is hash_tree_root(uint64): the value little-endian, zero-padded to 32 bytes.
func Uint64Root(v uint64) phase0.Root {
	var root phase0.Root
	binary.LittleEndian.PutUint64(root[:8], v)

	return root
}

// EpochAtSlot is compute_epoch_at_slot.
func EpochAtSlot(slot phase0.Slot, slotsPerEpoch uint64) phase0.Epoch {
	return phase0.Epoch(uint64(slot) / slotsPerEpoch)
}
