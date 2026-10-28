// Package statestore keeps a durable copy of the runner's local state in an
// object store outside the host: the wrapped sealing key, the sealed shares,
// key generation state and the operator key (Prefixes). On Azure ACI and in
// a Confidential Space VM that local state lives on the container's or the
// VM's own disk and is gone after a restart; with key generation inside the
// runner (runner/keygen) there is no other copy of the share.
//
// The copy is a log of commits (docs/durable-state.md). Each
// change of that state is one commit, one object:
//
//	state/<setup_hash hex>/<signer>/<version, 20 digits>
//
// A commit lists the segments that hold the state, each in chunk objects
// of at most 1 MiB (state/<setup_hash hex>/<signer>/c/<sha256 of the
// chunk>), and carries its own changes, or moves them, with those of the
// commits before it since the last segment, into a new segment. So a
// change uploads about its own size, not the whole state. Segments of
// similar size are merged (layout.go), which keeps their number
// logarithmic in the state's size.
//
// The invariant: a change is in the copy if and only if its commit object
// exists. A commit is written after every chunk it names, a restore reads
// the state only through a commit, and Apply puts a whole set of changes
// into one commit. So a failed or interrupted write leaves the copy at the
// commit before, and a key generation commit's shares and key records
// land together or not at all.
//
// Every object is encrypted and authenticated with AES-256-GCM under a key
// from the platform's key release (platform.Keys, the same release as the
// mark log's record keys), with the setup and the signer in the AAD. The
// store's admin reads nothing and cannot change an object undetected. Names
// are created once, as in the mark log, through the same clients
// (markstore.Log). At start Open takes the newest commit whose objects are
// all there and open, writes its entries into the local store and only
// then lets the platform read its sealing key; the mark log claims after
// that.
//
// What the copy does not resist: an admin of a store without a lock can
// delete the newest commits or a chunk, so a restart restores an older
// state (fewer shares, the shares before a reshare). That is no slashing
// risk, because the mark lives in the locked mark log, not here;
// docs/durable-state.md has the argument and the case where it matters.
// Put the copy under the mark log's locked bucket to rule it out.
package statestore

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/slashing-log"
)

// Prefixes are the parts of the platform store that the copy holds. A
// build hook may add one (runner/hooks.go). handover/ holds the sealed
// bodies of a source's handover orders: without one the source reads its
// own pending order as an import and signs nothing (SHO-01). Not in
// it: rr/ (repeat roots, written on every vote; a missing one costs a
// refused exact repeat), wm/ (persisted marks, not used with the mark log)
// and mark-hint/ (written on every mark record; without it the claim
// compares nothing, as on any restart with lost state).
var Prefixes = []string{"sealing/", "shares/", "dkg/", "operator/", "handover/"}

// Durable reports whether key belongs in the copy.
func Durable(key string) bool {
	for _, p := range Prefixes {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}

const (
	versionWidth = 20
	// MaxObject bounds every object of the copy. The store clients read at
	// most 1 MiB of an object, so a larger one would never open again.
	MaxObject = 1 << 20
	// MaxEntry bounds one value. The largest the runner writes is a key
	// generation session's pending record, about 17 KB for 64 keys of three
	// participants.
	MaxEntry = 256 << 10
	// chunkPlain is the most a chunk holds, less if the header with the
	// wrapped key needs more than the rest of MaxObject (chunkLimit).
	chunkPlain = MaxObject - 64<<10
	// A commit carries its own changes when they take at most maxInline
	// bytes, the changes carried since the last segment at most maxTail,
	// and fewer than maxChain commits carry theirs. Otherwise it writes
	// them all as a new segment. A restore reads at most maxChain commits.
	maxInline = 128 << 10
	maxTail   = 256 << 10
	maxChain  = 64
	maxSkips  = 16
	nonceLen  = 12
)

// ErrLost: another runner process wrote a valid commit under the name this
// one wanted (a clone of this signer). This process changes no durable
// state from then on.
var ErrLost = errors.New("statestore: another runner instance wrote this signer's state copy; this one changes nothing more")

// Prefix is the object name prefix of a signer's copy:
// state/<setup_hash hex>/<signer>/, so a new setup (a handover target
// that keeps the signer name included) never meets the objects of
// another, which it could not open and would refuse to start over. A zero
// setup is the flag path without a setup: state/<signer>/.
func Prefix(setup [32]byte, signer string) string {
	if setup == ([32]byte{}) {
		return "state/" + signer + "/"
	}
	return "state/" + hex.EncodeToString(setup[:]) + "/" + signer + "/"
}

// Name is the object name of version v of a signer's copy: a commit.
func Name(setup [32]byte, signer string, v uint64) string {
	return fmt.Sprintf("%s%0*d", Prefix(setup, signer), versionWidth, v)
}

// ChunkName is the object name of the chunk whose object has SHA-256 sum.
func ChunkName(setup [32]byte, signer string, sum [32]byte) string {
	return Prefix(setup, signer) + "c/" + hex.EncodeToString(sum[:])
}

func versionOf(prefix, name string) (uint64, bool) {
	rest, ok := strings.CutPrefix(name, prefix)
	if !ok || len(rest) != versionWidth {
		return 0, false
	}
	v, err := strconv.ParseUint(rest, 10, 64)
	return v, err == nil && v > 0
}

// Options of a Store.
type Options struct {
	// SetupHash is the signer's setup_hash: the copy's names and its AADs
	// carry it. Zero: the flag path without a setup.
	SetupHash [32]byte
	// AllowCreate starts over when objects lie under commit names but none
	// gives a state (another key release, objects that are not commits,
	// chunks gone).
	AllowCreate bool
	Now         func() time.Time
	Log         *slog.Logger
}

// Store is a platform.Store whose durable keys are copied to the object
// store before they are written locally. Get and List read the local store.
type Store struct {
	local  platform.Store
	log    markstore.Log
	signer string
	setup  [32]byte
	prefix string
	keys   platform.Keys
	opt    Options

	mu      sync.Mutex
	version uint64    // highest version read or written
	written time.Time // time of the newest commit
	key     []byte    // this process's object key, made at the first write
	blob    []byte    // the key, wrapped by the key release
	opened  map[string][]byte
	bad     map[string]bool
	lost    error
	// broken: a commit landed but the local store did not take it. The
	// next start restores it; until then this process changes nothing.
	broken error

	// The state of the newest commit and how the copy holds it.
	state      map[string][]byte
	sum        stateSum
	segs       []*segment
	tail       map[string]op // changes the commits since the last segment carry
	tailBytes  int
	chain      int       // those commits
	chainSince time.Time // time of the oldest of them
	head       uint64    // version of the newest commit; 0: none yet
	headSum    [32]byte

	writes, objects, bytesOut uint64
}

var (
	_ platform.Store   = (*Store)(nil)
	_ platform.Batcher = (*Store)(nil)
	_ platform.Deleter = (*Store)(nil)
)

// Open reads signer's copy and restores the local store from the newest
// commit. Any doubt stops the start: a store or key release that does not
// answer, two different commits at one version, objects under commit names
// of which none gives a state (unless AllowCreate), or a local durable key
// that the newest commit neither holds nor deleted. With no commit at all
// and local durable state (a runner that ran before the copy existed), it
// writes a first one.
func Open(ctx context.Context, local platform.Store, l markstore.Log, signer string, keys platform.Keys, opt Options) (*Store, error) {
	if local == nil || l == nil || keys == nil {
		return nil, errors.New("statestore: local store, object store and key release are required")
	}
	if err := markstore.CheckSigner(signer); err != nil {
		return nil, err
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Log == nil {
		opt.Log = slog.Default()
	}
	s := &Store{local: local, log: l, signer: signer, setup: opt.SetupHash, prefix: Prefix(opt.SetupHash, signer), keys: keys, opt: opt,
		opened: map[string][]byte{}, bad: map[string]bool{}, state: map[string][]byte{}, tail: map[string]op{}}
	s.mu.Lock()
	defer s.mu.Unlock()
	start := time.Now()
	idx, err := s.list(ctx)
	if err != nil {
		return nil, fmt.Errorf("state copy %s: %w", l, err)
	}
	r, err := s.newest(ctx, idx)
	if err != nil {
		return nil, fmt.Errorf("state copy %s: %w", l, err)
	}
	localEntries, err := s.localEntries()
	if err != nil {
		return nil, fmt.Errorf("state copy: local store: %w", err)
	}
	s.version = idx.top
	if r == nil {
		if idx.present > 0 && !opt.AllowCreate {
			return nil, fmt.Errorf("state copy %s: %d commit names hold objects but none opens under this key release with every object it needs "+
				"(%d open but name chunks or commits that are missing or changed; the others: another image or key, and on Azure a new image "+
				"takes over through the handover, docs/durable-state.md); refusing to start, -state-create overrides", l, idx.present, idx.broken)
		}
		if len(localEntries) > 0 {
			ops := map[string]op{}
			for k, v := range localEntries {
				ops[k] = op{val: v}
			}
			if err := s.commitLocked(ctx, ops, true); err != nil {
				return nil, fmt.Errorf("state copy %s: first commit of the local state: %w", l, err)
			}
			opt.Log.Info("state copy: first commit of the local state", "store", l.String(), "signer", signer,
				"version", s.version, "entries", len(localEntries))
		} else {
			opt.Log.Info("state copy: empty, nothing to restore", "store", l.String(), "signer", signer)
		}
		return s, nil
	}
	restored, dropped, err := s.restoreLocal(r, localEntries)
	if err != nil {
		return nil, err
	}
	s.load(r)
	s.version = max(s.version, r.version)
	opt.Log.Info("state copy: newest commit", "store", l.String(), "signer", signer, "version", r.version,
		"entries", len(r.state), "segments", len(r.segs), "chain", r.chain, "restored", restored, "deleted", dropped,
		"written", r.time.UTC().Format(time.RFC3339), "took_ms", time.Since(start).Milliseconds())
	return s, nil
}

// load takes a restored state as the store's own.
func (s *Store) load(r *restored) {
	s.state, s.sum, s.segs = r.state, r.sum, r.segs
	s.tail, s.chain, s.chainSince = r.tail, r.chain, r.chainSince
	s.tailBytes = 0
	for k, o := range s.tail {
		s.tailBytes += o.size(k)
	}
	s.written = r.time
	s.head, s.headSum = r.version, r.headSum
}

// restoreLocal makes the local store hold r's durable entries. A local
// durable key that r lacks stops the start, unless r deleted it.
func (s *Store) restoreLocal(r *restored, local map[string][]byte) (int, int, error) {
	var drop []string
	for k := range local {
		if _, ok := r.state[k]; ok {
			continue
		}
		if !r.deleted[k] {
			return 0, 0, fmt.Errorf("state copy %s: the local store holds %s, the newest commit (version %d) does not: "+
				"the copy lost commits or the local state comes from elsewhere (refusing to start)", s.log, k, r.version)
		}
		drop = append(drop, k)
	}
	put := map[string][]byte{}
	for k, v := range r.state {
		if lv, ok := local[k]; !ok || !bytes.Equal(lv, v) {
			put[k] = v
		}
	}
	if err := s.putLocal(put); err != nil {
		return 0, 0, fmt.Errorf("state copy: restore: %w", err)
	}
	if err := s.deleteLocal(drop); err != nil {
		return 0, 0, fmt.Errorf("state copy: restore: %w", err)
	}
	return len(put), len(drop), nil
}

// bulkStore writes many entries with one sync (filestore.Store.PutMany).
type bulkStore interface {
	PutMany(map[string][]byte) error
}

func (s *Store) putLocal(put map[string][]byte) error {
	if b, ok := s.local.(bulkStore); ok && len(put) > 2 {
		// The copy holds them already: a crash before the sync costs a
		// restore at the next start, not the entries.
		return b.PutMany(put)
	}
	for _, k := range sortedKeys(put) {
		if err := s.local.Put(k, put[k]); err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
	}
	return nil
}

func (s *Store) deleteLocal(keys []string) error {
	if len(keys) == 0 {
		return nil
	}
	d, ok := s.local.(platform.Deleter)
	if !ok {
		return errors.New("the local store cannot delete")
	}
	for _, k := range keys {
		if err := d.Delete(k); err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
	}
	return nil
}

func sortedKeys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// localEntries reads every durable key of the local store.
func (s *Store) localEntries() (map[string][]byte, error) {
	out := map[string][]byte{}
	for _, p := range Prefixes {
		keys, err := s.local.List(p)
		if err != nil {
			return nil, err
		}
		for _, k := range keys {
			v, err := s.local.Get(k)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", k, err)
			}
			out[k] = v
		}
	}
	return out, nil
}

// putTimeout bounds one commit. Put and Apply have no context of their own.
const putTimeout = 60 * time.Second

func (s *Store) Get(key string) ([]byte, error)       { return s.local.Get(key) }
func (s *Store) List(prefix string) ([]string, error) { return s.local.List(prefix) }

// Put writes a durable key to the copy first (one commit) and then to the
// local store; an error leaves the local store as it was. Other keys go to
// the local store only.
func (s *Store) Put(key string, val []byte) error {
	if !Durable(key) {
		return s.local.Put(key, val)
	}
	c := &platform.Change{}
	c.Put(key, val)
	return s.Apply(c)
}

// Delete removes a key, from the copy first for a durable one.
func (s *Store) Delete(key string) error {
	if !Durable(key) {
		return s.deleteLocal([]string{key})
	}
	c := &platform.Change{}
	c.Delete(key)
	return s.Apply(c)
}

// Apply writes the durable keys of c as one commit and then to the local
// store; the rest goes to the local store only. If the commit fails,
// neither the copy nor the local store changes. If the local store fails
// after the commit, the next start restores the change and this process
// changes nothing more.
func (s *Store) Apply(c *platform.Change) error {
	ops := map[string]op{}
	var other []platform.ChangeOp
	for _, o := range c.Ops() {
		if !Durable(o.Key) {
			other = append(other, o)
			continue
		}
		if len(o.Key) > 1024 || strings.Contains(o.Key, "..") {
			return fmt.Errorf("state copy: bad key %q", o.Key)
		}
		if len(o.Value) > MaxEntry {
			return fmt.Errorf("state copy: %s: value of %d bytes is over the %d-byte limit", o.Key, len(o.Value), MaxEntry)
		}
		ops[o.Key] = op{val: bytes.Clone(o.Value), del: o.Delete}
	}
	if len(ops) > 0 {
		if err := s.applyDurable(ops); err != nil {
			return err
		}
	}
	for _, o := range other {
		var err error
		if o.Delete {
			err = s.deleteLocal([]string{o.Key})
		} else {
			err = s.local.Put(o.Key, o.Value)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) applyDurable(ops map[string]op) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var dels []string
	put := map[string][]byte{}
	for k, o := range ops {
		cur, ok := s.state[k]
		switch {
		case o.del && !ok, !o.del && ok && bytes.Equal(cur, o.val):
			delete(ops, k) // no change
		case o.del:
			dels = append(dels, k)
		default:
			put[k] = o.val
		}
	}
	if len(ops) == 0 {
		return nil
	}
	if _, ok := s.local.(platform.Deleter); len(dels) > 0 && !ok {
		return errors.New("state copy: the local store cannot delete")
	}
	// Deletes go to the local store before the commit (RBRSTA-01). A
	// commit that writes a new segment carries no ops, so after it a
	// restart cannot tell a local key it dropped from one the copy never
	// had, and refuses to start. A key the local store lacks and the copy
	// holds is no such doubt: the next start restores it.
	if err := s.deleteLocal(dels); err != nil {
		s.undelete(dels)
		return fmt.Errorf("state copy: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), putTimeout)
	defer cancel()
	if err := s.commitLocked(ctx, ops, false); err != nil {
		s.undelete(dels)
		return fmt.Errorf("state copy: %w", err)
	}
	if err := s.putLocal(put); err != nil {
		s.broken = fmt.Errorf("statestore: the copy holds a change the local store did not take (%v); restart to restore it", err)
		s.opt.Log.Error("state copy: local store failed after a commit; refusing further changes until a restart", "version", s.head, "err", err)
		return s.broken
	}
	return nil
}

// undelete writes the keys of a delete that did not commit back to the
// local store, from the state they still have in the copy. If that fails
// too, the next start restores them.
func (s *Store) undelete(keys []string) {
	back := map[string][]byte{}
	for _, k := range keys {
		if v, ok := s.state[k]; ok {
			back[k] = v
		}
	}
	if err := s.putLocal(back); err != nil {
		s.opt.Log.Warn("state copy: a delete did not commit and its keys did not go back to the local store; the next start restores them", "err", err)
	}
}

// Refresh writes the whole state as a new segment when the oldest object
// the newest commit needs is older than maxAge, so a locked store's
// retention never ends on an object the state still needs.
func (s *Store) Refresh(ctx context.Context, maxAge time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.head == 0 || s.opt.Now().Sub(s.oldest()) < maxAge {
		return nil
	}
	return s.commitLocked(ctx, nil, true)
}

// oldest is the time of the oldest object the newest commit needs.
func (s *Store) oldest() time.Time {
	t := s.written
	for _, sg := range s.segs {
		if c := time.Unix(sg.created, 0); c.Before(t) {
			t = c
		}
	}
	if s.chain > 0 && s.chainSince.Before(t) {
		t = s.chainSince
	}
	return t
}

// Status describes the copy for logs.
func (s *Store) Status() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := fmt.Sprintf("statecopy %s signer=%s version=%d writes=%d objects=%d bytes=%d entries=%d segments=%d chain=%d",
		s.log, s.signer, s.version, s.writes, s.objects, s.bytesOut, len(s.state), len(s.segs), s.chain)
	if s.lost != nil {
		st += " LOST"
	}
	if s.broken != nil {
		st += " BROKEN"
	}
	return st
}
