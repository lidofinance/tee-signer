package charonlock

import (
	"crypto/sha256"
	"encoding/binary"
	"math/bits"
)

// A small SSZ hash tree root builder: chunks of 32 bytes, merkleized to a
// power of two (or to a given limit) with zero subtrees, and a length mixin
// for lists. Written from the SSZ spec; the field layout of the lock is in
// hash.go.

type root = [32]byte

var zeroHashes = func() [64]root {
	var z [64]root
	for i := 1; i < len(z); i++ {
		z[i] = pair(z[i-1], z[i-1])
	}
	return z
}()

func pair(a, b root) root {
	var buf [64]byte
	copy(buf[:32], a[:])
	copy(buf[32:], b[:])
	return sha256.Sum256(buf[:])
}

// merkleize hashes chunks to a tree of limit leaves (limit 0: the next power
// of two of len(chunks)).
func merkleize(chunks []root, limit uint64) root {
	n := uint64(len(chunks))
	if limit == 0 {
		limit = n
	}
	if n > limit {
		panic("charonlock: more chunks than the limit")
	}
	depth := 0
	if limit > 1 {
		depth = bits.Len64(limit - 1)
	}
	layer := append([]root(nil), chunks...)
	for d := 0; d < depth; d++ {
		if len(layer)%2 == 1 {
			layer = append(layer, zeroHashes[d])
		}
		next := make([]root, len(layer)/2)
		for i := range next {
			next[i] = pair(layer[2*i], layer[2*i+1])
		}
		layer = next
	}
	if len(layer) == 0 {
		return zeroHashes[depth]
	}
	return layer[0]
}

func mixin(r root, length uint64) root {
	var l root
	binary.LittleEndian.PutUint64(l[:], length)
	return pair(r, l)
}

// pack splits b into zero-padded chunks.
func pack(b []byte) []root {
	out := make([]root, (len(b)+31)/32)
	for i := range out {
		copy(out[i][:], b[32*i:])
	}
	return out
}

// fixedBytes is the root of a byte vector: one padded chunk up to 32 bytes,
// else the merkleized chunks.
func fixedBytes(b []byte) root {
	if len(b) <= 32 {
		var r root
		copy(r[:], b)
		return r
	}
	return merkleize(pack(b), 0)
}

// byteList is the root of a byte list with a limit in bytes.
func byteList(b []byte, limitBytes uint64) root {
	return mixin(merkleize(pack(b), (limitBytes+31)/32), uint64(len(b)))
}

func u64(v uint64) root {
	var r root
	binary.LittleEndian.PutUint64(r[:], v)
	return r
}

func boolean(v bool) root {
	var r root
	if v {
		r[0] = 1
	}
	return r
}

// list is the root of a list of element roots with a limit in elements.
func list(elems []root, limit uint64) root {
	return mixin(merkleize(elems, limit), uint64(len(elems)))
}

// u64List is the root of a packed list of uint64 with a limit in elements.
func u64List(vs []uint64, limit uint64) root {
	b := make([]byte, 0, 8*len(vs))
	for _, v := range vs {
		b = binary.LittleEndian.AppendUint64(b, v)
	}
	return mixin(merkleize(pack(b), (limit*8+31)/32), uint64(len(vs)))
}

// container is the root of a container's field roots.
func container(fields ...root) root { return merkleize(fields, 0) }
