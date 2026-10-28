package backend

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// SSZ sizes of the fixed-size containers.
const (
	SSZAttestationDataLen       = 128
	SSZBeaconBlockHeaderLen     = 112
	SSZVoluntaryExitLen         = 16
	SSZValidatorRegistrationLen = 84
)

// EncodeSSZ serializes a container message. RootMessage has no SSZ form.
func EncodeSSZ(m Message) ([]byte, error) {
	switch v := m.(type) {
	case *AttestationData:
		b := make([]byte, 0, SSZAttestationDataLen)
		b = binary.LittleEndian.AppendUint64(b, v.Slot)
		b = binary.LittleEndian.AppendUint64(b, v.Index)
		b = append(b, v.BeaconBlockRoot[:]...)
		b = binary.LittleEndian.AppendUint64(b, v.Source.Epoch)
		b = append(b, v.Source.Root[:]...)
		b = binary.LittleEndian.AppendUint64(b, v.Target.Epoch)
		b = append(b, v.Target.Root[:]...)
		return b, nil
	case *BeaconBlockHeader:
		b := make([]byte, 0, SSZBeaconBlockHeaderLen)
		b = binary.LittleEndian.AppendUint64(b, v.Slot)
		b = binary.LittleEndian.AppendUint64(b, v.ProposerIndex)
		b = append(b, v.ParentRoot[:]...)
		b = append(b, v.StateRoot[:]...)
		b = append(b, v.BodyRoot[:]...)
		return b, nil
	case *VoluntaryExit:
		b := make([]byte, 0, SSZVoluntaryExitLen)
		b = binary.LittleEndian.AppendUint64(b, v.Epoch)
		b = binary.LittleEndian.AppendUint64(b, v.ValidatorIndex)
		return b, nil
	case *ValidatorRegistration:
		b := make([]byte, 0, SSZValidatorRegistrationLen)
		b = append(b, v.FeeRecipient[:]...)
		b = binary.LittleEndian.AppendUint64(b, v.GasLimit)
		b = binary.LittleEndian.AppendUint64(b, v.Timestamp)
		b = append(b, v.Pubkey[:]...)
		return b, nil
	}
	if b, ok := encodeGloas(m); ok {
		return b, nil
	}
	if b, ok := encodeAggregate(m); ok {
		return b, nil
	}
	if b, ok := encodeBuilderAuth(m); ok {
		return b, nil
	}
	return nil, fmt.Errorf("no SSZ encoding for %T", m)
}

// DecodeSSZ parses a container of the given kind. The length must match exactly.
func DecodeSSZ(k Kind, b []byte) (Message, error) {
	le := binary.LittleEndian
	if m, ok, err := decodeGloas(k, b); ok {
		return m, err
	}
	if m, ok, err := decodeAggregate(k, b); ok {
		return m, err
	}
	if m, ok, err := decodeBuilderAuth(k, b); ok {
		return m, err
	}
	want := map[Kind]int{
		KindAttestation:           SSZAttestationDataLen,
		KindBlock:                 SSZBeaconBlockHeaderLen,
		KindVoluntaryExit:         SSZVoluntaryExitLen,
		KindValidatorRegistration: SSZValidatorRegistrationLen,
	}[k]
	if want == 0 {
		return nil, fmt.Errorf("no SSZ encoding for %v", k)
	}
	if len(b) != want {
		return nil, fmt.Errorf("%v: want %d bytes, got %d", k, want, len(b))
	}
	switch k {
	case KindAttestation:
		v := &AttestationData{Slot: le.Uint64(b[0:]), Index: le.Uint64(b[8:])}
		copy(v.BeaconBlockRoot[:], b[16:48])
		v.Source.Epoch = le.Uint64(b[48:])
		copy(v.Source.Root[:], b[56:88])
		v.Target.Epoch = le.Uint64(b[88:])
		copy(v.Target.Root[:], b[96:128])
		return v, nil
	case KindBlock:
		v := &BeaconBlockHeader{Slot: le.Uint64(b[0:]), ProposerIndex: le.Uint64(b[8:])}
		copy(v.ParentRoot[:], b[16:48])
		copy(v.StateRoot[:], b[48:80])
		copy(v.BodyRoot[:], b[80:112])
		return v, nil
	case KindVoluntaryExit:
		return &VoluntaryExit{Epoch: le.Uint64(b[0:]), ValidatorIndex: le.Uint64(b[8:])}, nil
	default: // KindValidatorRegistration
		v := &ValidatorRegistration{GasLimit: le.Uint64(b[20:]), Timestamp: le.Uint64(b[28:])}
		copy(v.FeeRecipient[:], b[0:20])
		copy(v.Pubkey[:], b[36:84])
		return v, nil
	}
}

func hashPair(a, b Root) Root {
	h := sha256.New()
	h.Write(a[:])
	h.Write(b[:])
	var out Root
	h.Sum(out[:0])
	return out
}

// merkleize hashes chunks pairwise, padding with zero chunks to a power of two.
func merkleize(chunks ...Root) Root {
	n := 1
	for n < len(chunks) {
		n <<= 1
	}
	layer := make([]Root, n)
	copy(layer, chunks)
	for len(layer) > 1 {
		next := make([]Root, len(layer)/2)
		for i := range next {
			next[i] = hashPair(layer[2*i], layer[2*i+1])
		}
		layer = next
	}
	return layer[0]
}

func u64Root(v uint64) Root {
	var r Root
	binary.LittleEndian.PutUint64(r[:], v)
	return r
}

func padRoot(b []byte) Root {
	var r Root
	copy(r[:], b)
	return r
}

func pubkeyRoot(p Pubkey) Root { return merkleize(padRoot(p[:32]), padRoot(p[32:])) }

func checkpointRoot(c Checkpoint) Root { return merkleize(u64Root(c.Epoch), c.Root) }

// HashTreeRoot of a container message.
func HashTreeRoot(m Message) (Root, error) {
	switch v := m.(type) {
	case *AttestationData:
		return merkleize(u64Root(v.Slot), u64Root(v.Index), v.BeaconBlockRoot,
			checkpointRoot(v.Source), checkpointRoot(v.Target)), nil
	case *BeaconBlockHeader:
		return merkleize(u64Root(v.Slot), u64Root(v.ProposerIndex), v.ParentRoot, v.StateRoot,
			v.BodyRoot), nil
	case *VoluntaryExit:
		return merkleize(u64Root(v.Epoch), u64Root(v.ValidatorIndex)), nil
	case *ValidatorRegistration:
		return merkleize(padRoot(v.FeeRecipient[:]), u64Root(v.GasLimit), u64Root(v.Timestamp),
			pubkeyRoot(v.Pubkey)), nil
	case *RootMessage:
		return v.ObjectRoot, nil
	}
	if r, ok := hashTreeRootGloas(m); ok {
		return r, nil
	}
	if r, ok := hashTreeRootBuilderAuth(m); ok {
		return r, nil
	}
	return Root{}, fmt.Errorf("no hash_tree_root for %T", m)
}

// HashTreeRootUint64 is hash_tree_root(uint64), the RANDAO object root.
func HashTreeRootUint64(v uint64) Root { return u64Root(v) }

// ComputeDomain is consensus-specs compute_domain.
func ComputeDomain(dt DomainType, forkVersion Version, genesisValidatorsRoot Root) Root {
	forkDataRoot := merkleize(padRoot(forkVersion[:]), genesisValidatorsRoot)
	var d Root
	copy(d[:4], dt[:])
	copy(d[4:], forkDataRoot[:28])
	return d
}

// SigningRoot is hash_tree_root(SigningData(object_root, domain)).
func SigningRoot(objectRoot, domain Root) Root { return merkleize(objectRoot, domain) }
