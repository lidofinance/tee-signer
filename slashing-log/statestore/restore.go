package statestore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/slashing-log"
)

// errBroken: a commit opens but names a chunk or an earlier commit that is
// missing or changed. The restore then tries the commit before it.
var errBroken = errors.New("statestore: an object the commit needs is missing or changed")

// listing is one listing of a signer's copy.
type listing struct {
	versions map[uint64][]markstore.Entry
	chunks   map[string][]markstore.Entry // by name
	top      uint64                       // highest version name with an object
	// present counts the versions tried that gave no state, broken those
	// of them whose commit opened but named missing or changed objects.
	present, broken int
	opened          map[uint64][]*object // the valid objects of each version read
	badChunks       map[[32]byte]bool
}

func (s *Store) list(ctx context.Context) (*listing, error) {
	ents, err := s.log.List(ctx, s.prefix)
	if err != nil {
		return nil, err
	}
	idx := &listing{versions: map[uint64][]markstore.Entry{}, chunks: map[string][]markstore.Entry{},
		opened: map[uint64][]*object{}, badChunks: map[[32]byte]bool{}}
	for _, e := range ents {
		if v, ok := versionOf(s.prefix, e.Name); ok {
			idx.versions[v] = append(idx.versions[v], e)
			idx.top = max(idx.top, v)
		} else if strings.HasPrefix(e.Name, s.prefix+"c/") {
			idx.chunks[e.Name] = append(idx.chunks[e.Name], e)
		}
	}
	return idx, nil
}

// restored is the state one commit describes.
type restored struct {
	version    uint64
	time       time.Time
	state      map[string][]byte
	deleted    map[string]bool // keys whose last change in the copy is a delete
	sum        stateSum
	segs       []*segment
	tail       map[string]op
	chain      int
	chainSince time.Time
	headSum    [32]byte
}

// newest finds the highest version whose object opens and gives a state.
// nil with no error: none does (idx.present and idx.broken say why).
func (s *Store) newest(ctx context.Context, idx *listing) (*restored, error) {
	vs := make([]uint64, 0, len(idx.versions))
	for v := range idx.versions {
		vs = append(vs, v)
	}
	sort.Slice(vs, func(i, j int) bool { return vs[i] > vs[j] })
	for _, v := range vs {
		found, err := s.at(ctx, idx, v)
		if err != nil {
			return nil, err
		}
		switch len(found) {
		case 0:
			idx.present++
			continue
		case 1:
		default:
			return nil, fmt.Errorf("%d different commits at version %d: two writers with this signer's key (refusing)", len(found), v)
		}
		r, err := s.build(ctx, idx, found[0])
		if errors.Is(err, errBroken) {
			s.opt.Log.Warn("state copy: the commit names objects that are missing or changed; trying the one before", "version", v, "why", err)
			idx.present++
			idx.broken++
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("version %d: %w", v, err)
		}
		return r, nil
	}
	return nil, nil
}

// at returns the valid objects at version v, read once per listing.
func (s *Store) at(ctx context.Context, idx *listing, v uint64) ([]*object, error) {
	if found, ok := idx.opened[v]; ok {
		return found, nil
	}
	found, err := s.validAt(ctx, v, idx.versions[v])
	if err != nil {
		return nil, err
	}
	idx.opened[v] = found
	return found, nil
}

// validAt reads the objects under version v and returns those that open,
// without duplicates.
func (s *Store) validAt(ctx context.Context, v uint64, es []markstore.Entry) ([]*object, error) {
	var out []*object
	for _, e := range es {
		b, err := s.log.Get(ctx, e)
		if errors.Is(err, markstore.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		o, err := s.open(ctx, b, v)
		if errors.Is(err, platform.ErrNotAuthentic) {
			s.opt.Log.Warn("state copy: object is not a commit of this signer, skipped", "name", e.Name, "ref", e.Ref, "why", err)
			continue
		}
		if err != nil {
			return nil, err
		}
		dup := false
		for _, x := range out {
			dup = dup || bytes.Equal(x.raw, b)
		}
		if !dup {
			out = append(out, o)
		}
	}
	return out, nil
}

// build rebuilds the state of head: its segments in order, then the
// inline changes of the chain of commits that ends in head, oldest first.
// errBroken: an object it needs is missing or changed.
func (s *Store) build(ctx context.Context, idx *listing, head *object) (*restored, error) {
	r := &restored{version: head.version, time: head.time, headSum: head.sum, deleted: map[string]bool{}, tail: map[string]op{}}
	b := head.body
	r.state = map[string][]byte{}
	for i, ref := range b.segs {
		sg := &segment{created: ref.created, count: ref.count, size: ref.size, chunks: ref.chunks}
		if i > 0 {
			sg.keys = map[string]bool{}
		}
		n, last := 0, ""
		for _, c := range ref.chunks {
			ops, err := s.chunk(ctx, idx, c)
			if err != nil {
				return nil, err
			}
			for _, e := range ops {
				if n > 0 && e.key <= last {
					return nil, fmt.Errorf("segment %d: key %q out of order", i, e.key)
				}
				n, last = n+1, e.key
				if sg.keys != nil {
					sg.keys[e.key] = true
				}
				if e.del {
					if i == 0 {
						return nil, errors.New("segment 0 holds a delete")
					}
					delete(r.state, e.key)
					r.deleted[e.key] = true
					continue
				}
				r.state[e.key] = e.val
				delete(r.deleted, e.key)
			}
		}
		if n != ref.count {
			return nil, fmt.Errorf("segment %d holds %d entries, the commit says %d", i, n, ref.count)
		}
		r.segs = append(r.segs, sg)
	}
	chain := []*object{head}
	for cur := head; len(chain) < b.chain; {
		prev, err := s.commitAt(ctx, idx, cur.body.prevVersion, cur.body.prevSum)
		if err != nil {
			return nil, err
		}
		if prev.body.chain != cur.body.chain-1 || !sameSegments(prev.body.segs, b.segs) {
			return nil, fmt.Errorf("commit %d does not continue the chain of commit %d", prev.version, cur.version)
		}
		chain, cur = append(chain, prev), prev
	}
	for i := len(chain) - 1; i >= 0; i-- {
		for _, e := range chain[i].body.ops {
			r.tail[e.key] = e.op
			if e.del {
				delete(r.state, e.key)
				r.deleted[e.key] = true
			} else {
				r.state[e.key] = e.val
				delete(r.deleted, e.key)
			}
		}
	}
	r.chain = b.chain
	if r.chain > 0 {
		r.chainSince = chain[len(chain)-1].time
	}
	r.sum = sumOf(r.state)
	if r.sum != b.sum {
		// Every object opened, so this is no forgery: the writer and this
		// reader disagree. Stop rather than restore a state nobody wrote.
		return nil, fmt.Errorf("the rebuilt state (%d entries, %d bytes) is not the one the commit sums up (%d entries, %d bytes)",
			r.sum.count, r.sum.bytes, b.sum.count, b.sum.bytes)
	}
	return r, nil
}

func sameSegments(a, b []*segment) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].created != b[i].created || a[i].count != b[i].count || a[i].size != b[i].size || len(a[i].chunks) != len(b[i].chunks) {
			return false
		}
		for j := range a[i].chunks {
			if a[i].chunks[j] != b[i].chunks[j] {
				return false
			}
		}
	}
	return true
}

// commitAt finds the commit at version v whose object hashes to sum.
func (s *Store) commitAt(ctx context.Context, idx *listing, v uint64, sum [32]byte) (*object, error) {
	found, err := s.at(ctx, idx, v)
	if err != nil {
		return nil, err
	}
	for _, o := range found {
		if o.sum == sum && o.magic == magicCommit {
			return o, nil
		}
	}
	return nil, fmt.Errorf("%w: commit %d of the chain", errBroken, v)
}

// chunk reads the chunk ref names: any object under its name (every
// version the listing has) whose hash matches.
func (s *Store) chunk(ctx context.Context, idx *listing, ref chunkRef) ([]entryOp, error) {
	name := ChunkName(s.setup, s.signer, ref.sum)
	if idx.badChunks[ref.sum] {
		return nil, fmt.Errorf("%w: chunk %s", errBroken, name)
	}
	es := idx.chunks[name]
	if len(es) == 0 {
		// A store whose listing does not go into c/ (FileLog).
		es = []markstore.Entry{{Name: name}}
	}
	for _, e := range es {
		b, err := s.log.Get(ctx, e)
		if errors.Is(err, markstore.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if sha256.Sum256(b) != ref.sum {
			s.opt.Log.Warn("state copy: object under a chunk name has other bytes, skipped", "name", e.Name, "ref", e.Ref)
			continue
		}
		o, err := s.open(ctx, b, 0)
		if errors.Is(err, platform.ErrNotAuthentic) {
			break
		}
		if err != nil {
			return nil, err
		}
		return o.ops, nil
	}
	idx.badChunks[ref.sum] = true
	return nil, fmt.Errorf("%w: chunk %s", errBroken, name)
}
