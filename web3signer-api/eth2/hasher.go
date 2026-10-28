package eth2

import (
	"fmt"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	dynssz "github.com/pk910/dynamic-ssz"
)

// Preset values that change SSZ list limits or vector sizes of the objects the
// gateway hashes. Values not listed fall back to the mainnet ssz tags in
// go-eth2-client.
var presets = map[string]map[string]any{
	"mainnet": {
		"SLOTS_PER_EPOCH":              uint64(32),
		"MAX_VALIDATORS_PER_COMMITTEE": uint64(2048),
		"MAX_COMMITTEES_PER_SLOT":      uint64(64),
		"SYNC_COMMITTEE_SIZE":          uint64(512),
	},
	"minimal": {
		"SLOTS_PER_EPOCH":              uint64(8),
		"MAX_VALIDATORS_PER_COMMITTEE": uint64(2048),
		"MAX_COMMITTEES_PER_SLOT":      uint64(4),
		"SYNC_COMMITTEE_SIZE":          uint64(32),
	},
}

// Hasher computes hash_tree_root for a consensus preset. The Web3Signer spec
// examples use the minimal preset; real networks use mainnet.
type Hasher struct {
	preset        string
	slotsPerEpoch uint64
	ds            *dynssz.DynSsz
}

// NewHasher returns a hasher for "mainnet" or "minimal".
func NewHasher(preset string) (*Hasher, error) {
	spec, ok := presets[preset]
	if !ok {
		return nil, fmt.Errorf("unknown preset %q (want mainnet or minimal)", preset)
	}

	return &Hasher{preset: preset, slotsPerEpoch: spec["SLOTS_PER_EPOCH"].(uint64), ds: dynssz.NewDynSsz(spec)}, nil
}

// Preset names the preset.
func (h *Hasher) Preset() string { return h.preset }

// SlotsPerEpoch is the preset's SLOTS_PER_EPOCH.
func (h *Hasher) SlotsPerEpoch() uint64 { return h.slotsPerEpoch }

// Root is hash_tree_root(v) for a go-eth2-client spec object.
func (h *Hasher) Root(v any) (phase0.Root, error) {
	r, err := h.ds.HashTreeRoot(v)
	if err != nil {
		return phase0.Root{}, err
	}

	return r, nil
}
