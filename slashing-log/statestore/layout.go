package statestore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"

	"github.com/lidofinance/tee-signer/slashing-log"
)

// How a commit lays out the state.
//
// A commit with small changes carries them inline and keeps the segments
// of the commit before. Once the inline changes since the last segment
// grow past maxTail, or maxChain commits carry theirs, or one commit's
// changes are larger than maxInline, the commit writes them all as a new
// last segment. Then, while the segment before the last is at most twice
// the size of the last, the two are merged into one. A merge into
// segment 0 writes the whole state, without deletes. So each segment is
// more than twice the size of the next: a state of S bytes whose newest
// segment has L bytes is in at most log2(S/L) + 1 segments, and a byte is
// written again about that many times. Refresh and the first commit of a
// state write everything as segment 0.

// plan is a commit before it is written.
type plan struct {
	ops    map[string]op // the commit's changes
	inline bool          // they ride in the commit object
	segs   []*segment    // the segments after the commit; fresh ones are written first
	after  stateSum      // the state after the commit
}

// valueAfter is k's value once ops apply.
func (s *Store) valueAfter(ops map[string]op, k string) ([]byte, bool) {
	if o, ok := ops[k]; ok {
		return o.val, !o.del
	}
	v, ok := s.state[k]
	return v, ok
}

// plan lays out a commit of ops. full writes the whole state as segment 0.
func (s *Store) plan(ops map[string]op, full bool) *plan {
	p := &plan{ops: ops, after: s.sum}
	opsSize := 0
	tail := s.tailBytes
	for k, o := range ops {
		if old, ok := s.state[k]; ok {
			p.after.sub(k, old)
		}
		if !o.del {
			p.after.add(k, o.val)
		}
		opsSize += o.size(k)
		if t, ok := s.tail[k]; ok {
			tail -= t.size(k)
		}
		tail += o.size(k)
	}
	if !full && opsSize <= maxInline && tail <= maxTail && s.chain < maxChain {
		p.inline, p.segs = true, s.segs
		return p
	}
	if full || len(s.segs) == 0 {
		p.segs = []*segment{s.base(p.after)}
		return p
	}
	keys := map[string]bool{}
	for k := range s.tail {
		keys[k] = true
	}
	for k := range ops {
		keys[k] = true
	}
	segs := append(append([]*segment(nil), s.segs...), s.layer(ops, keys))
	for n := len(segs); n >= 2 && segs[n-2].size <= 2*segs[n-1].size; n = len(segs) {
		if n == 2 {
			segs = []*segment{s.base(p.after)}
			break
		}
		union := map[string]bool{}
		for k := range segs[n-2].keys {
			union[k] = true
		}
		for k := range segs[n-1].keys {
			union[k] = true
		}
		segs = append(segs[:n-2], s.layer(ops, union))
	}
	p.segs = segs
	return p
}

// base plans segment 0: the whole state after the commit.
func (s *Store) base(after stateSum) *segment {
	return &segment{fresh: true, count: int(after.count), size: int64(after.bytes) + 7*int64(after.count)}
}

// layer plans a later segment: keys with their values after ops, or
// deletes.
func (s *Store) layer(ops map[string]op, keys map[string]bool) *segment {
	sg := &segment{fresh: true, keys: keys, count: len(keys)}
	for k := range keys {
		v, ok := s.valueAfter(ops, k)
		sg.size += int64(op{val: v, del: !ok}.size(k))
	}
	return sg
}

// entries lists a fresh segment's entries, sorted by key.
func (s *Store) entries(ops map[string]op, sg *segment) []entryOp {
	var out []entryOp
	if sg.keys == nil {
		out = make([]entryOp, 0, sg.count)
		for k, v := range s.state {
			if _, changed := ops[k]; !changed {
				out = append(out, entryOp{key: k, op: op{val: v}})
			}
		}
		for k, o := range ops {
			if !o.del {
				out = append(out, entryOp{key: k, op: o})
			}
		}
	} else {
		out = make([]entryOp, 0, len(sg.keys))
		for k := range sg.keys {
			v, ok := s.valueAfter(ops, k)
			out = append(out, entryOp{key: k, op: op{val: v, del: !ok}})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out
}

// chunkLimit is the most plaintext a chunk holds: chunkPlain, or what the
// header, nonce and tag leave of MaxObject.
func (s *Store) chunkLimit() int {
	return min(chunkPlain, MaxObject-(25+len(s.blob)+nonceLen+16))
}

// writeSegment seals a fresh segment's entries into chunks of at most
// chunkLimit bytes and creates them.
func (s *Store) writeSegment(ctx context.Context, ops map[string]op, sg *segment) (objects int, n int64, err error) {
	es := s.entries(ops, sg)
	sg.created = s.opt.Now().Unix()
	limit := s.chunkLimit()
	for len(es) > 0 {
		size, i := 4, 0
		for i < len(es) && (i == 0 || size+es[i].size(es[i].key) <= limit) {
			size += es[i].size(es[i].key)
			i++
		}
		plain := appendOps(make([]byte, 0, size), es[:i])
		obj, err := s.seal(magicChunk, 0, plain)
		clear(plain)
		if err != nil {
			return objects, n, err
		}
		ref, err := s.putChunk(ctx, obj)
		if err != nil {
			return objects, n, err
		}
		sg.chunks = append(sg.chunks, ref)
		objects, n, es = objects+1, n+int64(len(obj)), es[i:]
	}
	return objects, n, nil
}

// putChunk creates a chunk under the name of its hash. A chunk of that
// name with the same bytes is this process's own write whose reply was
// lost.
func (s *Store) putChunk(ctx context.Context, obj []byte) (chunkRef, error) {
	sum := sha256.Sum256(obj)
	name := ChunkName(s.setup, s.signer, sum)
	err := s.log.Create(ctx, name, obj)
	if errors.Is(err, markstore.ErrExists) {
		b, gerr := s.log.Get(ctx, markstore.Entry{Name: name})
		if gerr != nil || !bytes.Equal(b, obj) {
			return chunkRef{}, fmt.Errorf("statestore: chunk %s exists with other bytes", name)
		}
		err = nil
	}
	if err != nil {
		return chunkRef{}, fmt.Errorf("statestore: write chunk: %w", err)
	}
	return chunkRef{sum: sum, size: uint32(len(obj))}, nil
}

// commitLocked writes one commit of ops (full: the whole state as segment
// 0): the chunks of its fresh segments, then the commit object at the next
// free version. Only then does the store's state change. Callers hold mu.
func (s *Store) commitLocked(ctx context.Context, ops map[string]op, full bool) error {
	if s.lost != nil {
		return s.lost
	}
	if s.broken != nil {
		return s.broken
	}
	if err := s.ensureKey(ctx); err != nil {
		return err
	}
	p := s.plan(ops, full)
	objects, nbytes := 0, int64(0)
	for _, sg := range p.segs {
		if !sg.fresh {
			continue
		}
		o, n, err := s.writeSegment(ctx, ops, sg)
		objects, nbytes = objects+o, nbytes+n
		if err != nil {
			return err
		}
	}
	body := &commitBody{prevVersion: s.head, prevSum: s.headSum, sum: p.after, segs: p.segs}
	if p.inline {
		body.chain, body.ops = s.chain+1, sortedOps(ops)
	}
	plain := encodeBody(body)
	defer clear(plain)
	v, obj, err := s.createCommit(ctx, plain)
	if err != nil {
		return err
	}
	objects, nbytes = objects+1, nbytes+int64(len(obj))

	for k, o := range ops {
		if o.del {
			delete(s.state, k)
		} else {
			s.state[k] = o.val
		}
	}
	s.sum = p.after
	if p.inline {
		for k, o := range ops {
			if t, ok := s.tail[k]; ok {
				s.tailBytes -= t.size(k)
			}
			s.tail[k] = o
			s.tailBytes += o.size(k)
		}
		if s.chain == 0 {
			s.chainSince = s.opt.Now()
		}
		s.chain++
	} else {
		for _, sg := range p.segs {
			sg.fresh = false
		}
		s.segs, s.tail, s.tailBytes, s.chain = p.segs, map[string]op{}, 0, 0
	}
	s.head, s.headSum = v, sha256.Sum256(obj)
	s.version, s.written = v, s.opt.Now()
	s.writes++
	s.objects += uint64(objects)
	s.bytesOut += uint64(nbytes)
	s.opt.Log.Info("state copy: wrote", "version", v, "changes", len(ops), "inline", p.inline, "objects", objects, "bytes", nbytes,
		"segments", len(s.segs), "chain", s.chain, "entries", len(s.state))
	return nil
}

// createCommit writes a commit at the next free version.
func (s *Store) createCommit(ctx context.Context, plain []byte) (uint64, []byte, error) {
	for v, skips := s.version+1, 0; ; v, skips = v+1, skips+1 {
		if skips > maxSkips {
			return 0, nil, fmt.Errorf("statestore: %d names after version %d are taken by objects that are not commits", maxSkips, s.version)
		}
		obj, err := s.seal(magicCommit, v, plain)
		if err != nil {
			return 0, nil, err
		}
		name := Name(s.setup, s.signer, v)
		err = s.log.Create(ctx, name, obj)
		if errors.Is(err, markstore.ErrExists) {
			es, lerr := s.log.List(ctx, name)
			if lerr != nil {
				return 0, nil, fmt.Errorf("statestore: version %d exists and cannot be read back: %w", v, lerr)
			}
			var mine []markstore.Entry
			for _, e := range es {
				if e.Name == name {
					mine = append(mine, e)
				}
			}
			found, gerr := s.validAt(ctx, v, mine)
			if gerr != nil {
				return 0, nil, fmt.Errorf("statestore: version %d exists and cannot be read back: %w", v, gerr)
			}
			if len(found) == 0 {
				s.opt.Log.Warn("state copy: name taken by an object that is not a commit; skipping it", "version", v)
				continue
			}
			for _, f := range found {
				if bytes.Equal(f.raw, obj) {
					err = nil // our own write; its reply was lost
				}
			}
			if err != nil {
				s.lost = ErrLost
				s.opt.Log.Error("state copy: another instance wrote this signer's copy; refusing further changes", "version", v)
				return 0, nil, s.lost
			}
		}
		if err != nil && s.landed(ctx, name, obj) {
			err = nil // the store took it and the reply was lost
		}
		if err != nil {
			return 0, nil, fmt.Errorf("statestore: write version %d: %w", v, err)
		}
		return v, obj, nil
	}
}

// landed reports whether obj is under name after a create that failed
// without an answer. If the create lands only later, the next commit's
// create at that version finds it and stops this process (ErrLost); a
// restart then restores it.
func (s *Store) landed(ctx context.Context, name string, obj []byte) bool {
	es, err := s.log.List(ctx, name)
	if err != nil {
		return false
	}
	for _, e := range es {
		if e.Name != name {
			continue
		}
		if b, err := s.log.Get(ctx, e); err == nil && bytes.Equal(b, obj) {
			return true
		}
	}
	return false
}
