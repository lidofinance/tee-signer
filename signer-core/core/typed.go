package core

/*
#include <stdlib.h>
#include "signer_core.h"
*/
import "C"

import (
	"fmt"
	"unsafe"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

func cPreset(name string) *C.sc_preset {
	if name == "minimal" {
		return &C.SC_PRESET_MINIMAL
	}
	return &C.SC_PRESET_MAINNET
}

// AggregateObjectRoot is hash_tree_root(AggregateAndProof) of m under the
// named preset, computed by the C core (sc_decode_aggregate_and_proof), and
// the slot of its attestation data.
func AggregateObjectRoot(m *backend.AggregateAndProof, preset string) (backend.Root, uint64, error) {
	var info C.sc_aggregate_info
	if len(m.SSZ) == 0 {
		return backend.Root{}, 0, fmt.Errorf("core: empty aggregate")
	}
	scratch := C.malloc(C.SC_TYPED_SCRATCH_LEN)
	defer C.free(scratch)
	ssz := C.CBytes(m.SSZ)
	defer C.free(ssz)
	rc := C.sc_decode_aggregate_and_proof((*C.uint8_t)(ssz), C.size_t(len(m.SSZ)), C.int(m.Form),
		cPreset(preset), (*C.uint8_t)(scratch), &info)
	if rc != C.SC_OK {
		return backend.Root{}, 0, &backend.RefusedError{Code: backend.Status(rc)}
	}
	var r backend.Root
	copy(r[:], C.GoBytes(unsafe.Pointer(&info.object_root[0]), 32))
	return r, uint64(info.data.slot), nil
}

// ContributionObjectRoot is hash_tree_root(ContributionAndProof) of m and
// its slot, computed by the C core.
func ContributionObjectRoot(m *backend.ContributionAndProof, preset string) (backend.Root, uint64, error) {
	var info C.sc_contribution_info
	if len(m.SSZ) == 0 {
		return backend.Root{}, 0, fmt.Errorf("core: empty contribution")
	}
	ssz := C.CBytes(m.SSZ)
	defer C.free(ssz)
	rc := C.sc_decode_contribution_and_proof((*C.uint8_t)(ssz), C.size_t(len(m.SSZ)), cPreset(preset), &info)
	if rc != C.SC_OK {
		return backend.Root{}, 0, &backend.RefusedError{Code: backend.Status(rc)}
	}
	var r backend.Root
	copy(r[:], C.GoBytes(unsafe.Pointer(&info.object_root[0]), 32))
	return r, uint64(info.slot), nil
}

// SyncSelectionRoot is hash_tree_root(SyncAggregatorSelectionData).
func SyncSelectionRoot(slot, subcommitteeIndex uint64) backend.Root {
	var r backend.Root
	C.sc_htr_sync_aggregator_selection_data(C.uint64_t(slot), C.uint64_t(subcommitteeIndex), u8(r[:]))
	return r
}

// typedParts returns the object root, domain type and slot of a message of
// backend/aggregates.go; ok is false for any other message.
func (c *Config) typedParts(m backend.Message) (obj backend.Root, dt backend.DomainType, slot uint64, ok bool, err error) {
	switch v := m.(type) {
	case *backend.SelectionProof:
		obj, dt, slot = backend.HashTreeRootUint64(v.Slot), backend.DomainSelectionProof, v.Slot
	case *backend.SyncCommitteeMessage:
		obj, dt, slot = v.BeaconBlockRoot, backend.DomainSyncCommittee, v.Slot
	case *backend.SyncSelectionProof:
		obj, dt, slot = SyncSelectionRoot(v.Slot, v.SubcommitteeIndex), backend.DomainSyncCommitteeSelectionProof, v.Slot
	case *backend.AggregateAndProof:
		dt = backend.DomainAggregateAndProof
		obj, slot, err = AggregateObjectRoot(v, c.PresetName())
	case *backend.ContributionAndProof:
		dt = backend.DomainContributionAndProof
		obj, slot, err = ContributionObjectRoot(v, c.PresetName())
	default:
		return obj, dt, 0, false, nil
	}
	return obj, dt, slot, true, err
}

// typedSigningRoot is SigningRoot for the kinds of backend/aggregates.go.
func (c *Config) typedSigningRoot(m backend.Message) (backend.Root, bool, error) {
	obj, dt, slot, ok, err := c.typedParts(m)
	if !ok || err != nil {
		return backend.Root{}, ok, err
	}
	return backend.SigningRoot(obj, c.Domain(dt, slot/c.SlotsPerEpoch)), true, nil
}
