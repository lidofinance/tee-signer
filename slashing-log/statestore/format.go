package statestore

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"sort"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform"
)

// Every object starts with the same header, which is part of the AES-GCM
// AAD: magic, version (0 for a chunk), time, the wrapped object key.
const (
	magicCommit = "SSTATE1" // a commit, format version 1
	magicChunk  = "SCHUNK1" // a piece of a segment, format version 1
)

// object is one decoded object of the copy.
type object struct {
	magic   string
	version uint64
	time    time.Time
	raw     []byte
	sum     [32]byte    // sha256 of raw
	body    *commitBody // commit
	ops     []entryOp   // chunk
}

// op is one change of a key: a new value, or a delete.
type op struct {
	val []byte
	del bool
}

// entryOp is an op with its key, as the encodings list them.
type entryOp struct {
	key string
	op
}

// size is the encoded size of a change of key k.
func (o op) size(k string) int {
	if o.del {
		return 3 + len(k)
	}
	return 7 + len(k) + len(o.val)
}

// commitBody is the encrypted part of a commit.
type commitBody struct {
	prevVersion uint64   // the commit before this one (0: none)
	prevSum     [32]byte // sha256 of that commit's object
	// chain counts the commits whose changes are not in a segment, this
	// one included. 0: this commit wrote its changes into a segment.
	chain int
	sum   stateSum // the state after this commit
	segs  []*segment
	ops   []entryOp // this commit's changes when chain > 0, sorted by key
}

// segment is one layer of the state: its chunks hold puts and deletes
// sorted by key. Segment 0 holds every key of the state at the time it
// was written and no deletes; each later one holds the keys changed since
// the one before, with their values at the time it was written.
type segment struct {
	created int64 // unix seconds when its chunks were written
	count   int   // its entries, deletes included
	size    int64 // bytes of its encoded entries
	chunks  []chunkRef
	// keys are the keys it holds; nil for segment 0, which holds them all.
	keys map[string]bool
	// fresh: planned by this process and not written yet.
	fresh bool
}

type chunkRef struct {
	sum  [32]byte // sha256 of the chunk object: its name
	size uint32
}

// stateSum sums up a state: its entries, their bytes (keys and values) and
// the sum mod 2^256 of every entry's SHA-256. Each commit carries it, so a
// restore checks what it rebuilt against what the writer held.
type stateSum struct {
	count uint64
	bytes uint64
	hash  [4]uint64 // little-endian 64-bit limbs
}

func entryHash(k string, v []byte) [4]uint64 {
	h := sha256.New()
	var n [6]byte
	binary.BigEndian.PutUint16(n[:], uint16(len(k)))
	binary.BigEndian.PutUint32(n[2:], uint32(len(v)))
	h.Write(n[:2])
	h.Write([]byte(k))
	h.Write(n[2:])
	h.Write(v)
	d := h.Sum(nil)
	return [4]uint64{binary.BigEndian.Uint64(d[24:]), binary.BigEndian.Uint64(d[16:]), binary.BigEndian.Uint64(d[8:]), binary.BigEndian.Uint64(d)}
}

func (s *stateSum) add(k string, v []byte) {
	h := entryHash(k, v)
	var c uint64
	for i := range s.hash {
		s.hash[i], c = bits.Add64(s.hash[i], h[i], c)
	}
	s.count++
	s.bytes += uint64(len(k) + len(v))
}

func (s *stateSum) sub(k string, v []byte) {
	h := entryHash(k, v)
	var b uint64
	for i := range s.hash {
		s.hash[i], b = bits.Sub64(s.hash[i], h[i], b)
	}
	s.count--
	s.bytes -= uint64(len(k) + len(v))
}

func sumOf(state map[string][]byte) stateSum {
	var s stateSum
	for k, v := range state {
		s.add(k, v)
	}
	return s
}

func (s stateSum) append(out []byte) []byte {
	out = binary.BigEndian.AppendUint64(out, s.count)
	out = binary.BigEndian.AppendUint64(out, s.bytes)
	for i := 3; i >= 0; i-- {
		out = binary.BigEndian.AppendUint64(out, s.hash[i])
	}
	return out
}

// reader decodes big-endian fields; the first short read sets err.
type reader struct {
	b   []byte
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil || n < 0 || len(r.b) < n {
		if r.err == nil {
			r.err = errors.New("short")
		}
		// Zeros for the fixed-size reads that follow; never n bytes, which
		// the input declares and need not hold.
		return make([]byte, min(max(n, 0), 8))
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) u8() byte    { return r.take(1)[0] }
func (r *reader) u16() int    { return int(binary.BigEndian.Uint16(r.take(2))) }
func (r *reader) u32() uint32 { return binary.BigEndian.Uint32(r.take(4)) }
func (r *reader) u64() uint64 { return binary.BigEndian.Uint64(r.take(8)) }

// appendOps encodes changes, sorted by key: count:u32, then per change
// key_len:u16 key kind:u8 (0 put, 1 delete) and for a put value_len:u32 value.
func appendOps(out []byte, ops []entryOp) []byte {
	out = binary.BigEndian.AppendUint32(out, uint32(len(ops)))
	for _, e := range ops {
		out = binary.BigEndian.AppendUint16(out, uint16(len(e.key)))
		out = append(out, e.key...)
		if e.del {
			out = append(out, 1)
			continue
		}
		out = append(out, 0)
		out = binary.BigEndian.AppendUint32(out, uint32(len(e.val)))
		out = append(out, e.val...)
	}
	return out
}

// readOps decodes appendOps. Keys must be durable and strictly ascending.
func readOps(r *reader) ([]entryOp, error) {
	n := r.u32()
	if r.err != nil || uint64(n) > uint64(len(r.b))/3 {
		return nil, errors.New("bad change count")
	}
	out := make([]entryOp, 0, n)
	for i := uint32(0); i < n; i++ {
		k := string(r.take(r.u16()))
		kind := r.u8()
		var e entryOp
		e.key = k
		switch kind {
		case 0:
			e.val = append([]byte(nil), r.take(int(r.u32()))...)
		case 1:
			e.del = true
		default:
			return nil, fmt.Errorf("bad change kind %d", kind)
		}
		if r.err != nil {
			return nil, errors.New("short change")
		}
		if !Durable(k) || strings.Contains(k, "..") {
			return nil, fmt.Errorf("bad key %q", k)
		}
		if i > 0 && k <= out[i-1].key {
			return nil, fmt.Errorf("key %q out of order", k)
		}
		out = append(out, e)
	}
	return out, nil
}

// sortedOps lists a change set sorted by key.
func sortedOps(m map[string]op) []entryOp {
	out := make([]entryOp, 0, len(m))
	for k, o := range m {
		out = append(out, entryOp{key: k, op: o})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out
}

func encodeBody(b *commitBody) []byte {
	out := binary.BigEndian.AppendUint64(nil, b.prevVersion)
	out = append(out, b.prevSum[:]...)
	out = binary.BigEndian.AppendUint16(out, uint16(b.chain))
	out = b.sum.append(out)
	out = binary.BigEndian.AppendUint16(out, uint16(len(b.segs)))
	for _, sg := range b.segs {
		out = binary.BigEndian.AppendUint64(out, uint64(sg.created))
		out = binary.BigEndian.AppendUint32(out, uint32(sg.count))
		out = binary.BigEndian.AppendUint64(out, uint64(sg.size))
		out = binary.BigEndian.AppendUint32(out, uint32(len(sg.chunks)))
		for _, c := range sg.chunks {
			out = append(out, c.sum[:]...)
			out = binary.BigEndian.AppendUint32(out, c.size)
		}
	}
	return appendOps(out, b.ops)
}

func decodeBody(plain []byte, version uint64) (*commitBody, error) {
	r := &reader{b: plain}
	b := &commitBody{prevVersion: r.u64()}
	copy(b.prevSum[:], r.take(32))
	b.chain = r.u16()
	b.sum.count, b.sum.bytes = r.u64(), r.u64()
	for i := 3; i >= 0; i-- {
		b.sum.hash[i] = r.u64()
	}
	nseg := r.u16()
	for i := 0; i < nseg && r.err == nil; i++ {
		sg := &segment{created: int64(r.u64()), count: int(r.u32()), size: int64(r.u64())}
		n := r.u32()
		if uint64(n)*36 > uint64(len(r.b)) {
			return nil, errors.New("bad chunk count")
		}
		for j := uint32(0); j < n; j++ {
			var c chunkRef
			copy(c.sum[:], r.take(32))
			c.size = r.u32()
			if c.size > MaxObject {
				return nil, errors.New("chunk over the object limit")
			}
			sg.chunks = append(sg.chunks, c)
		}
		b.segs = append(b.segs, sg)
	}
	if r.err != nil {
		return nil, errors.New("short commit")
	}
	ops, err := readOps(r)
	if err != nil {
		return nil, err
	}
	b.ops = ops
	switch {
	case len(r.b) != 0:
		return nil, errors.New("trailing bytes")
	case b.prevVersion >= version:
		return nil, fmt.Errorf("previous version %d is not below %d", b.prevVersion, version)
	case b.chain == 0 && len(b.ops) != 0, b.chain > maxChain:
		return nil, fmt.Errorf("chain of %d with %d changes", b.chain, len(b.ops))
	case b.chain > 1 && b.prevVersion == 0:
		return nil, errors.New("chain without a previous commit")
	}
	return b, nil
}

// aad is an object's AES-GCM AAD: the setup, the signer and the object's
// header.
func (s *Store) aad(header []byte) []byte {
	return setupwire.CtxState.Message(s.setup[:], []byte{byte(len(s.signer))}, []byte(s.signer), header)
}

// keyAAD is what the object keys are bound to in the key release.
func (s *Store) keyAAD() []byte { return setupwire.CtxStateKey.Message(s.setup[:], []byte(s.signer)) }

func gcm(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("statestore: want a 32-byte key")
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// ensureKey makes this process's object key at its first write.
func (s *Store) ensureKey(ctx context.Context) error {
	if s.key != nil {
		return nil
	}
	key, blob, err := s.keys.NewKey(ctx, s.keyAAD())
	if err != nil {
		return fmt.Errorf("statestore: new object key: %w", err)
	}
	if len(key) != 32 || len(blob) == 0 || len(blob) > 0xffff {
		return fmt.Errorf("statestore: key release gave a %d-byte key and a %d-byte blob", len(key), len(blob))
	}
	s.key, s.blob = key, blob
	s.opened[string(blob)] = key
	return nil
}

// seal encrypts plain into an object with this header.
func (s *Store) seal(magic string, version uint64, plain []byte) ([]byte, error) {
	header := []byte(magic)
	header = binary.BigEndian.AppendUint64(header, version)
	header = binary.BigEndian.AppendUint64(header, uint64(s.opt.Now().Unix()))
	header = binary.BigEndian.AppendUint16(header, uint16(len(s.blob)))
	header = append(header, s.blob...)
	g, err := gcm(s.key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append(append(header, nonce...), g.Seal(nil, nonce, plain, s.aad(header))...)
	if len(out) > MaxObject {
		return nil, fmt.Errorf("statestore: object of %d bytes is over the %d-byte limit", len(out), MaxObject)
	}
	return out, nil
}

// open decodes and decrypts one object. version is the version its name
// carries (0 for a chunk). platform.ErrNotAuthentic: not an object of this
// signer under this key release at that name. Any other error: the key
// release did not answer.
func (s *Store) open(ctx context.Context, b []byte, version uint64) (*object, error) {
	bad := func(why string) (*object, error) { return nil, fmt.Errorf("%w: %s", platform.ErrNotAuthentic, why) }
	const hdr = 7 + 8 + 8 + 2
	if len(b) < hdr {
		return bad("no header")
	}
	magic := string(b[:7])
	switch {
	case magic == magicChunk && version == 0:
	case magic == magicCommit && version != 0:
	default:
		return bad("not an object of this kind or name")
	}
	ver := binary.BigEndian.Uint64(b[7:])
	when := binary.BigEndian.Uint64(b[15:])
	n := int(binary.BigEndian.Uint16(b[23:]))
	if ver != version {
		return bad(fmt.Sprintf("version %d inside, %d in the name", ver, version))
	}
	if n == 0 || len(b) < hdr+n+nonceLen+16 {
		return bad("short object")
	}
	blob := b[hdr : hdr+n]
	key, ok := s.opened[string(blob)]
	if !ok {
		if s.bad[string(blob)] {
			return bad("key blob does not open")
		}
		k, err := s.keys.OpenKey(ctx, blob, s.keyAAD())
		if errors.Is(err, platform.ErrNotAuthentic) {
			s.bad[string(blob)] = true
			return nil, err
		}
		if err != nil {
			return nil, fmt.Errorf("statestore: key release: %w", err)
		}
		key = k
		s.opened[string(blob)] = k
	}
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	p := b[hdr+n:]
	plain, err := g.Open(nil, p[:nonceLen], p[nonceLen:], s.aad(b[:hdr+n]))
	if err != nil {
		return bad("does not decrypt")
	}
	defer clear(plain)
	o := &object{magic: magic, version: ver, time: time.Unix(int64(when), 0), raw: b, sum: sha256.Sum256(b)}
	switch magic {
	case magicCommit:
		o.body, err = decodeBody(plain, ver)
	case magicChunk:
		o.ops, err = readOps(&reader{b: plain})
	}
	if err != nil {
		return bad(err.Error())
	}
	return o, nil
}
