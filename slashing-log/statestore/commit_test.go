package statestore

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/slashing-log"
)

// memLog is a markstore.Log in memory that lists as the cloud stores do:
// every object under a prefix, c/ included, every version of a name.
type memLog struct {
	mu   sync.Mutex
	objs map[string][][]byte
}

func newMemLog() *memLog { return &memLog{objs: map[string][][]byte{}} }

func (m *memLog) Create(_ context.Context, name string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.objs[name]) > 0 {
		return markstore.ErrExists
	}
	m.objs[name] = append(m.objs[name], bytes.Clone(data))
	return nil
}

func (m *memLog) List(_ context.Context, prefix string) ([]markstore.Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []markstore.Entry
	for name, vs := range m.objs {
		if strings.HasPrefix(name, prefix) {
			for i := range vs {
				out = append(out, markstore.Entry{Name: name, Ref: strconv.Itoa(i)})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name+out[i].Ref < out[j].Name+out[j].Ref })
	return out, nil
}

func (m *memLog) Get(_ context.Context, e markstore.Entry) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	vs := m.objs[e.Name]
	if len(vs) == 0 {
		return nil, markstore.ErrNotFound
	}
	if e.Ref == "" {
		return bytes.Clone(vs[len(vs)-1]), nil
	}
	i, err := strconv.Atoi(e.Ref)
	if err != nil || i >= len(vs) {
		return nil, markstore.ErrNotFound
	}
	return bytes.Clone(vs[i]), nil
}

func (m *memLog) String() string { return "mem" }

// usage counts the objects and bytes stored and the largest object.
func (m *memLog) usage() (objects, total, largest int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, vs := range m.objs {
		for _, v := range vs {
			objects, total, largest = objects+1, total+len(v), max(largest, len(v))
		}
	}
	return
}

// faultLog fails its failAt-th Create: the store refuses it, or (lost)
// takes it and the reply is lost.
type faultLog struct {
	markstore.Log
	creates, failAt int
	lost            bool
}

func (f *faultLog) Create(ctx context.Context, name string, data []byte) error {
	f.creates++
	if f.creates != f.failAt {
		return f.Log.Create(ctx, name, data)
	}
	if f.lost {
		if err := f.Log.Create(ctx, name, data); err != nil {
			return err
		}
		return errors.New("injected: the reply was lost")
	}
	return errors.New("injected: the store refused")
}

// memLocal is a local store in memory that can delete.
type memLocal struct {
	mu sync.Mutex
	m  map[string][]byte
}

func newMemLocal() *memLocal { return &memLocal{m: map[string][]byte{}} }

func (s *memLocal) Get(k string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[k]
	if !ok {
		return nil, platform.ErrNotFound
	}
	return bytes.Clone(v), nil
}

func (s *memLocal) Put(k string, v []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[k] = bytes.Clone(v)
	return nil
}

func (s *memLocal) Delete(k string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, k)
	return nil
}

func (s *memLocal) List(prefix string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for k := range s.m {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out, nil
}

// durableOf is the durable part of a local store.
func durableOf(t *testing.T, local platform.Store) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, p := range Prefixes {
		keys, err := local.List(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range keys {
			v, err := local.Get(k)
			if err != nil {
				t.Fatal(err)
			}
			out[k] = v
		}
	}
	return out
}

// restoreFrom opens the copy with an empty local store, as a restart on a
// new disk does, and returns what it restored.
func restoreFrom(t *testing.T, l markstore.Log) map[string][]byte {
	t.Helper()
	local := newMemLocal()
	s, err := open(t, local, l, keysOf("image-a"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := durableOf(t, local)
	if !maps.EqualFunc(got, s.state, bytes.Equal) {
		t.Fatal("restored local store and the store's own state differ")
	}
	return got
}

func filled(n int, prefix string, size int, seed byte) map[string][]byte {
	out := map[string][]byte{}
	for i := range n {
		out[fmt.Sprintf("%s%06d", prefix, i)] = bytes.Repeat([]byte{seed, byte(i), byte(i >> 8)}, size/3)
	}
	return out
}

func changeOf(puts map[string][]byte, dels []string) *platform.Change {
	c := &platform.Change{}
	for _, k := range slices.Sorted(maps.Keys(puts)) {
		c.Put(k, puts[k])
	}
	for _, k := range dels {
		c.Delete(k)
	}
	return c
}

// A change lands whole or not at all, whichever of its writes fails: the
// store refuses one (the copy restores the state before), or takes it and
// the reply is lost (the commit itself: read back, the change landed; a
// chunk: the change did not). The same process then writes the change.
func TestApplyAllOrNothing(t *testing.T) {
	base := filled(600, "shares/", 1024, 1)
	// The change: 400 new key records, 300 new shares, 200 changed shares and
	// 10 deletes. It is larger than maxInline, so it writes a segment, and
	// the merge into segment 0 makes it the whole state: two chunks.
	puts := filled(400, "shares/k/", 1500, 2)
	maps.Copy(puts, filled(300, "shares/n", 224, 3))
	for i := range 200 {
		puts[fmt.Sprintf("shares/%06d", i)] = []byte("changed")
	}
	var dels []string
	for i := 590; i < 600; i++ {
		dels = append(dels, fmt.Sprintf("shares/%06d", i))
	}
	after := maps.Clone(base)
	maps.Copy(after, puts)
	for _, k := range dels {
		delete(after, k)
	}

	fresh := func() (*memLog, *faultLog, *memLocal, *Store) {
		ml := newMemLog()
		fl := &faultLog{Log: ml}
		local := newMemLocal()
		s, err := open(t, local, fl, keysOf("image-a"), Options{})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Apply(changeOf(base, nil)); err != nil {
			t.Fatal(err)
		}
		fl.creates = 0
		return ml, fl, local, s
	}
	_, fl, _, s := fresh()
	if err := s.Apply(changeOf(puts, dels)); err != nil {
		t.Fatal(err)
	}
	steps := fl.creates
	if steps < 3 || len(s.segs[0].chunks) < 2 {
		t.Fatalf("the change took %d writes; the test wants chunks and a commit", steps)
	}
	for _, lost := range []bool{false, true} {
		for k := 1; k <= steps; k++ {
			ml, fl, local, s := fresh()
			fl.failAt, fl.lost = k, lost
			err := s.Apply(changeOf(puts, dels))
			last := k == steps // the commit object is the last write
			want := base
			if lost && last {
				want = after
				if err != nil {
					t.Fatalf("lost reply of the commit object: %v", err)
				}
			} else if err == nil {
				t.Fatalf("step %d (lost %v) failed and Apply reported nothing", k, lost)
			}
			if got := restoreFrom(t, ml); !maps.EqualFunc(got, want, bytes.Equal) {
				t.Fatalf("step %d (lost %v): the copy holds %d entries, want %d (before %d, after %d)", k, lost, len(got), len(want), len(base), len(after))
			}
			if got := durableOf(t, local); !maps.EqualFunc(got, want, bytes.Equal) {
				t.Fatalf("step %d (lost %v): the local store holds %d entries, want %d", k, lost, len(got), len(want))
			}
			fl.failAt = 0
			if err := s.Apply(changeOf(puts, dels)); err != nil {
				t.Fatalf("step %d (lost %v): retry: %v", k, lost, err)
			}
			if got := restoreFrom(t, ml); !maps.EqualFunc(got, after, bytes.Equal) {
				t.Fatalf("step %d (lost %v): after the retry the copy holds %d entries, want %d", k, lost, len(got), len(after))
			}
		}
	}
}

// Random puts and deletes over many commits, with restarts from the copy
// alone: every restore gives the model's state, and the process that
// restored goes on writing from it (inline chain, segments, merges).
func TestCommitsAgainstModel(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 11))
	model := map[string][]byte{}
	l := newMemLog()
	local := newMemLocal()
	s, err := open(t, local, l, keysOf("image-a"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	maxSegs := 0
	for i := range 4000 {
		c := &platform.Change{}
		n := 1 + rng.IntN(6)
		if rng.IntN(40) == 0 {
			n = 300 // larger than maxInline
		}
		for range n {
			k := fmt.Sprintf("shares/k/%05d", rng.IntN(3000))
			if rng.IntN(4) == 0 {
				c.Delete(k)
				delete(model, k)
				continue
			}
			v := make([]byte, 50+rng.IntN(1000))
			for j := range v {
				v[j] = byte(rng.Uint32())
			}
			c.Put(k, v)
			model[k] = v
		}
		c.Put(fmt.Sprintf("rr/%d", rng.IntN(10)), []byte("repeat roots stay local"))
		if err := s.Apply(c); err != nil {
			t.Fatalf("commit %d: %v", i, err)
		}
		maxSegs = max(maxSegs, len(s.segs))
		if i%500 == 250 {
			local = newMemLocal()
			if s, err = open(t, local, l, keysOf("image-a"), Options{}); err != nil {
				t.Fatalf("restart after commit %d: %v", i, err)
			}
			if got := durableOf(t, local); !maps.EqualFunc(got, model, bytes.Equal) {
				t.Fatalf("restart after commit %d: %d entries, the model has %d", i, len(got), len(model))
			}
		}
	}
	bound := int(math.Log2(float64(s.sum.bytes+7*s.sum.count)/maxTail)) + 2
	if maxSegs > bound {
		t.Fatalf("%d segments at most, want at most %d", maxSegs, bound)
	}
	_, _, largest := l.usage()
	if largest > MaxObject {
		t.Fatalf("an object of %d bytes", largest)
	}
	t.Logf("%d entries, %d commits, %d objects, %d bytes written, segments at most %d", len(model), s.writes, s.objects, s.bytesOut, maxSegs)
}

// Key generation at scale: sessions of 64 keys up to 8,192, each written as
// the runner writes it (pending record, one change with 64 shares and key
// records, the committed record, 64 key record updates for the deposits,
// the expired record deleted). The upload per session stays flat while
// the state grows, every object stays under the read limit, a small change
// is one small object, and the copy restores the state.
func TestWriteCostPerSessionIsFlat(t *testing.T) {
	if testing.Short() {
		t.Skip("8,192 keys")
	}
	l := newMemLog()
	s, err := open(t, newMemLocal(), l, keysOf("image-a"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	var perSession []uint64
	key := 0
	for sess := 0; sess < 128; sess++ {
		before := s.bytesOut
		pend := fmt.Sprintf("handover/pd/%064d", sess)
		if err := s.Put(pend, bytes.Repeat([]byte{'p'}, 16982)); err != nil {
			t.Fatal(err)
		}
		c := &platform.Change{}
		var recs []string
		for range 64 {
			pk := fmt.Sprintf("%096x", key)
			key++
			c.Put("shares/k/"+pk, bytes.Repeat([]byte{'r'}, 661))
			c.Put("shares/"+pk, bytes.Repeat([]byte{'s'}, 224))
			recs = append(recs, "shares/k/"+pk)
		}
		if err := s.Apply(c); err != nil {
			t.Fatal(err)
		}
		if err := s.Put(pend, bytes.Repeat([]byte{'c'}, 4300)); err != nil {
			t.Fatal(err)
		}
		for _, r := range recs {
			if err := s.Put(r, bytes.Repeat([]byte{'d'}, 713)); err != nil {
				t.Fatal(err)
			}
		}
		if sess > 0 {
			if err := s.Delete(fmt.Sprintf("handover/pd/%064d", sess-1)); err != nil {
				t.Fatal(err)
			}
		}
		perSession = append(perSession, s.bytesOut-before)
	}
	avg := func(xs []uint64) float64 {
		var sum uint64
		for _, x := range xs {
			sum += x
		}
		return float64(sum) / float64(len(xs))
	}
	first, second := avg(perSession[16:64]), avg(perSession[64:])
	t.Logf("upload per session: %.0f bytes (sessions 16-63), %.0f bytes (64-127); %d entries, %d segments", first, second, len(s.state), len(s.segs))
	if second > 2*first {
		t.Fatalf("upload per session grew from %.0f to %.0f bytes", first, second)
	}
	_, _, largest := l.usage()
	if largest > MaxObject {
		t.Fatalf("an object of %d bytes", largest)
	}
	objs, b := s.objects, s.bytesOut
	if err := s.Put("handover/key", []byte("one small change")); err != nil {
		t.Fatal(err)
	}
	if s.objects-objs != 1 || s.bytesOut-b > 8<<10 {
		t.Fatalf("a small change at %d keys wrote %d objects, %d bytes", key, s.objects-objs, s.bytesOut-b)
	}
	if got := restoreFrom(t, l); !maps.EqualFunc(got, s.state, bytes.Equal) || len(got) != 2*8192+2 {
		t.Fatalf("restored %d entries", len(got))
	}
}

// A chunk the store lost: the commits that need it give no state. The
// restore takes the newest commit whose objects are all there (here the
// one before the refresh, same state), and with none it refuses, unless
// AllowCreate.
func TestMissingChunk(t *testing.T) {
	dir := t.TempDir()
	l, _ := markstore.NewFileLog(dir)
	now := time.Unix(1_800_000_000, 0)
	s, _ := open(t, newMemLocal(), l, keysOf("image-a"), Options{Now: func() time.Time { return now }})
	state := filled(400, "shares/", 1024, 5) // over maxInline: segment 0 in chunks
	if err := s.Apply(changeOf(state, nil)); err != nil {
		t.Fatal(err)
	}
	if err := s.Put("handover/key", []byte("k")); err != nil {
		t.Fatal(err)
	}
	state["handover/key"] = []byte("k")
	first := s.segs[0].chunks[0].sum
	now = now.Add(48 * time.Hour)
	if err := s.Refresh(context.Background(), 24*time.Hour); err != nil || s.segs[0].chunks[0].sum == first {
		t.Fatalf("refresh: %v", err)
	}
	second := s.segs[0].chunks[0].sum
	rm := func(sum [32]byte) {
		p := filepath.Join(dir, filepath.FromSlash(ChunkName(setupA, "signer-1", sum)))
		os.Chmod(p, 0o600)
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
	}
	rm(second)
	if got := restoreFrom(t, l); !maps.EqualFunc(got, state, bytes.Equal) {
		t.Fatal("did not fall back to the commit before the refresh")
	}
	rm(first)
	if _, err := open(t, newMemLocal(), l, keysOf("image-a"), Options{}); err == nil || !strings.Contains(err.Error(), "missing or changed") {
		t.Fatalf("every commit lacks a chunk: %v", err)
	}
	if _, err := open(t, newMemLocal(), l, keysOf("image-a"), Options{AllowCreate: true}); err != nil {
		t.Fatal(err)
	}
}

// A delete in the copy whose local delete never happened (a crash between
// the two) is finished at the next start; a local key the copy never had
// still stops it.
func TestDeleteFinishedAtStart(t *testing.T) {
	l := newMemLog()
	local := newMemLocal()
	s, _ := open(t, local, l, keysOf("image-a"), Options{})
	s.Put("handover/pd/01", []byte("committed"))
	s.Put("shares/aa", []byte("share"))
	if err := s.Delete("handover/pd/01"); err != nil {
		t.Fatal(err)
	}
	if _, err := local.Get("handover/pd/01"); !errors.Is(err, platform.ErrNotFound) {
		t.Fatal("the local delete did not happen")
	}
	local.Put("handover/pd/01", []byte("committed")) // as if the crash came first
	if _, err := open(t, local, l, keysOf("image-a"), Options{}); err != nil {
		t.Fatal(err)
	}
	if _, err := local.Get("handover/pd/01"); !errors.Is(err, platform.ErrNotFound) {
		t.Fatal("the start did not finish the delete")
	}
	local.Put("handover/pd/02", []byte("never in the copy"))
	if _, err := open(t, local, l, keysOf("image-a"), Options{}); err == nil || !strings.Contains(err.Error(), "handover/pd/02") {
		t.Fatalf("a local key the copy never had: %v", err)
	}
}

// Repeat roots and the mark hint, written on every vote and every mark
// record, never reach the object store.
func TestPerVoteKeysStayLocal(t *testing.T) {
	l := newMemLog()
	local := newMemLocal()
	s, _ := open(t, local, l, keysOf("image-a"), Options{})
	s.Put("shares/aa", []byte("share"))
	objs, _, _ := l.usage()
	for i := range 1000 {
		s.Put(fmt.Sprintf("rr/%04d", i%244), []byte{byte(i)})
		s.Put("mark-hint/signer-1", []byte{byte(i)})
	}
	if n, _, _ := l.usage(); n != objs {
		t.Fatalf("%d objects written for repeat roots and hints", n-objs)
	}
}

// Refresh writes everything as segment 0 once the oldest object the newest
// commit needs is older than maxAge.
func TestRefreshCompacts(t *testing.T) {
	l := newMemLog()
	now := time.Unix(1_800_000_000, 0)
	s, _ := open(t, newMemLocal(), l, keysOf("image-a"), Options{Now: func() time.Time { return now }})
	for i := range 2000 {
		c := &platform.Change{}
		c.Put(fmt.Sprintf("shares/k/%04d", i%700), bytes.Repeat([]byte{byte(i)}, 700))
		if err := s.Apply(c); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Second)
	}
	if len(s.segs) < 2 || s.chain == 0 {
		t.Fatalf("want several segments and a chain before the refresh: %d, %d", len(s.segs), s.chain)
	}
	state := maps.Clone(s.state)
	if err := s.Refresh(context.Background(), 2*time.Hour); err != nil || s.writes != 2000 {
		t.Fatalf("refresh with everything younger than maxAge: %v, %d writes", err, s.writes)
	}
	now = now.Add(2 * time.Hour)
	if err := s.Refresh(context.Background(), time.Hour); err != nil || len(s.segs) != 1 || s.chain != 0 {
		t.Fatalf("refresh: %v, %d segments, chain %d", err, len(s.segs), s.chain)
	}
	if err := s.Refresh(context.Background(), time.Hour); err != nil || s.writes != 2001 {
		t.Fatalf("a second refresh right after: %v, %d writes", err, s.writes)
	}
	if got := restoreFrom(t, l); !maps.EqualFunc(got, state, bytes.Equal) {
		t.Fatal("refresh changed the state")
	}
}

// bigBlobKeys wraps keys in a blob of almost 64 KiB, the most the header
// holds.
type bigBlobKeys struct{ platform.Keys }

const blobPad = 65000

func (k bigBlobKeys) NewKey(ctx context.Context, aad []byte) ([]byte, []byte, error) {
	key, blob, err := k.Keys.NewKey(ctx, aad)
	if err != nil {
		return nil, nil, err
	}
	return key, append(binary.BigEndian.AppendUint16(nil, uint16(len(blob))), append(blob, make([]byte, blobPad)...)...), nil
}

func (k bigBlobKeys) OpenKey(ctx context.Context, blob, aad []byte) ([]byte, error) {
	if len(blob) < 2 || len(blob) < 2+int(binary.BigEndian.Uint16(blob)) {
		return nil, platform.ErrNotAuthentic
	}
	return k.Keys.OpenKey(ctx, blob[2:2+int(binary.BigEndian.Uint16(blob))], aad)
}

// With the largest wrapped key the header can hold, chunks still stay
// under the read limit.
func TestChunksFitWithALargeKeyBlob(t *testing.T) {
	l := newMemLog()
	keys := bigBlobKeys{keysOf("image-a")}
	s, err := Open(context.Background(), newMemLocal(), l, "signer-1", keys, Options{SetupHash: setupA, Log: quiet})
	if err != nil {
		t.Fatal(err)
	}
	state := filled(2000, "shares/", 1024, 9)
	if err := s.Apply(changeOf(state, nil)); err != nil {
		t.Fatal(err)
	}
	if _, _, largest := l.usage(); largest > MaxObject || len(s.segs[0].chunks) < 3 {
		t.Fatalf("largest object %d bytes, %d chunks", largest, len(s.segs[0].chunks))
	}
	local := newMemLocal()
	if _, err := Open(context.Background(), local, l, "signer-1", keys, Options{SetupHash: setupA, Log: quiet}); err != nil {
		t.Fatal(err)
	}
	if got := durableOf(t, local); !maps.EqualFunc(got, state, bytes.Equal) {
		t.Fatal("restore differs")
	}
}
