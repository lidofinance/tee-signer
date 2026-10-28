package backend

import (
	"encoding/binary"
	"fmt"
)

// BuilderRequestAuth (builder-specs, gloas builder.md) authenticates a
// validator to an external builder: data agreed with that builder and the
// proposal slot, signed under DOMAIN_BUILDER_REQUEST_AUTH with the genesis
// fork version and a zero root. It never reaches the chain and is not
// slashable. The C core signs it only when the root of its data is on the
// signer's builder_request_auth_roots (sc_sign_builder_request_auth).

// KindBuilderRequestAuth is its wire kind: the SSZ of the container,
// offset:u32 (12) slot:u64 data, 12 to 4108 bytes.
const KindBuilderRequestAuth Kind = 14

// DomainBuilderRequestAuth is DOMAIN_BUILDER_REQUEST_AUTH.
var DomainBuilderRequestAuth = DomainType{0x0b, 0, 0, 1}

// MaxBuilderRequestAuthData is the limit of the data field, ByteList[4096].
const MaxBuilderRequestAuthData = 4096

// BuilderRequestAuth is the message a validator signs for a builder.
type BuilderRequestAuth struct {
	Data []byte `json:"data"`
	Slot uint64 `json:"slot"`
}

func (*BuilderRequestAuth) Kind() Kind { return KindBuilderRequestAuth }

func builderAuthKindName(k Kind) (string, bool) {
	if k == KindBuilderRequestAuth {
		return "builder_request_auth", true
	}
	return "", false
}

func encodeBuilderAuth(m Message) ([]byte, bool) {
	v, ok := m.(*BuilderRequestAuth)
	if !ok {
		return nil, false
	}
	b := binary.LittleEndian.AppendUint32(make([]byte, 0, 12+len(v.Data)), 12)
	b = binary.LittleEndian.AppendUint64(b, v.Slot)
	return append(b, v.Data...), true
}

// decodeBuilderAuth is strict: first offset 12, at most 4096 data bytes.
func decodeBuilderAuth(k Kind, b []byte) (Message, bool, error) {
	if k != KindBuilderRequestAuth {
		return nil, false, nil
	}
	if len(b) < 12 || len(b) > 12+MaxBuilderRequestAuthData || binary.LittleEndian.Uint32(b) != 12 {
		return nil, true, fmt.Errorf("%v: want offset 12, slot and at most %d data bytes", k, MaxBuilderRequestAuthData)
	}
	return &BuilderRequestAuth{Slot: binary.LittleEndian.Uint64(b[4:]), Data: append([]byte{}, b[12:]...)}, true, nil
}

// BuilderRequestAuthDataRoot is hash_tree_root of data as ByteList[4096]:
// the value builder_request_auth_roots lists.
func BuilderRequestAuthDataRoot(data []byte) Root {
	chunks := make([]Root, MaxBuilderRequestAuthData/32)
	for i := 0; i*32 < len(data); i++ {
		copy(chunks[i][:], data[i*32:])
	}
	return hashPair(merkleize(chunks...), u64Root(uint64(len(data))))
}

// hashTreeRootBuilderAuth: builder-specs gloas has a plain Container of two
// fields, so the root is hash(root(data), slot chunk). go-eth2-client
// v0.30.1 hashes it as a ProgressiveContainer, which gives another root.
func hashTreeRootBuilderAuth(m Message) (Root, bool) {
	v, ok := m.(*BuilderRequestAuth)
	if !ok {
		return Root{}, false
	}
	return hashPair(BuilderRequestAuthDataRoot(v.Data), u64Root(v.Slot)), true
}
