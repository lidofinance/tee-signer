package markstore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sort"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// ErrLost: another runner instance wrote a valid record at a version this
// one wanted (a clone from the same sealed state). This instance signs
// nothing new from then on.
var ErrLost = errors.New("markstore: another runner instance wrote this signer's log; this one signs nothing new")

// ErrHandedOver: this signer's shares and mark went to a runner of another
// image (HANDOVER, docs/durable-state.md). The log ends with a
// tombstone record and nothing is signed under it again.
var ErrHandedOver = errors.New("markstore: this signer was handed over to another image; it signs nothing new")

// ErrUnreadable: at or above the newest valid record lies a record of this
// signer, under this key release, that this runner cannot parse (a newer
// image wrote it). The runner refuses to start rather than go back to an
// older mark (Claim, the fail-closed reader rule).
var ErrUnreadable = errors.New("markstore: the newest record of this signer is one this runner cannot read")

// ErrTooOld: the newest record is older than half of slashing_log_min_lock_days,
// so update bodies may have expired (section 5, age check). That signer
// needs a new setup and a re-import.
var ErrTooOld = errors.New("markstore: the newest record is older than half the retention; update bodies may have expired")

// ErrBodyMissing: no readable copy of an update body the config state names.
var ErrBodyMissing = errors.New("markstore: no readable copy of the update body")

// Tombstone is the mark of the record that ends a log at a handover: every
// bound at its maximum, so the core refuses every slashable message under
// it, a runner of any version that reads the log included.
var Tombstone = backend.Watermark{HasBlock: true, BlockSlot: math.MaxUint64,
	HasAttestation: true, SourceEpoch: math.MaxUint64, TargetEpoch: math.MaxUint64}

// IsTombstone reports whether wm is the handover's tombstone mark.
func IsTombstone(wm backend.Watermark) bool { return wm == Tombstone }

// Merge raises a to at least b, field by field (state.Merge, the core's
// wm_merge). The log's mark never goes down: a record holds the merge of the
// mark before it and the new one.
func Merge(a, b backend.Watermark) backend.Watermark {
	if b.HasBlock {
		if !a.HasBlock || b.BlockSlot > a.BlockSlot {
			a.BlockSlot = b.BlockSlot
		}
		a.HasBlock = true
	}
	if b.HasAttestation {
		if !a.HasAttestation {
			a.SourceEpoch, a.TargetEpoch = b.SourceEpoch, b.TargetEpoch
		} else {
			a.SourceEpoch = max(a.SourceEpoch, b.SourceEpoch)
			a.TargetEpoch = max(a.TargetEpoch, b.TargetEpoch)
		}
		a.HasAttestation = true
	}
	return a
}

// maxSkips bounds the versions a writer skips over objects that are not
// valid records (an admin may create objects under future names; they cost
// a skip each, never a valid record). Body copies use the same bound.
const maxSkips = 16

// Setup is what the mark log takes from the signer's setup.
type Setup struct {
	Hash          [32]byte    // setup_hash
	Signer        string      // signer_name
	RetentionDays uint32      // slashing_log_min_lock_days
	First         ConfigState // version 0 of both groups, the state of record 1
}

// SetupOf reads the mark log's part of a decoded setup whose setup_hash is
// hash: the first config state is version 0 of both groups, named by the
// setup's group hashes.
func SetupOf(s *setupwire.Setup, hash [32]byte) (*Setup, error) {
	lh, err := s.GroupHash(setupwire.GroupLocked)
	if err != nil {
		return nil, err
	}
	oh, err := s.GroupHash(setupwire.GroupOpen)
	if err != nil {
		return nil, err
	}
	return &Setup{Hash: hash, Signer: s.SignerName, RetentionDays: s.SlashingLogMinLockDays,
		First: ConfigState{Locked: GroupState{Hash: lh}, Open: GroupState{Hash: oh}}}, nil
}

// Retention is slashing_log_min_lock_days as a duration.
func (s *Setup) Retention() time.Duration { return time.Duration(s.RetentionDays) * 24 * time.Hour }

// Options of a MarkLog.
type Options struct {
	// Setup is the signer's setup. nil: the flag path without a setup, with
	// the names marks/<signer>/, a zero config state, no bodies and no age check.
	Setup *Setup
	// Clock is the trusted clock (the NTS clock), required with a Setup:
	// record times, the age check and the body refresh read it. Without a
	// Setup, Now is used.
	Clock func() (time.Time, error)
	// AllowCreate lets Claim start a log that has no valid record although
	// the node holds shares or objects lie under record names (operator
	// override after a lost log, or a key release that no longer opens the
	// old records). Off in setup images.
	AllowCreate bool
	// Hint keeps the version and hash of the last record written, sealed,
	// in the platform store. The host can roll the hint back (then it says
	// less), not forward. A hint above the newest record in the log means
	// the log lost records or the listing is stale: Claim refuses.
	HintStore  platform.Store
	HintSealer platform.Sealer
	Now        func() time.Time
	Log        *slog.Logger
}

// bodyKey names an update body.
type bodyKey struct {
	g setupwire.Group
	v uint64
}

// bodyEntry is an update body the config state names: its hash, its bytes
// (nil when no copy was readable at Claim) and its newest copy.
type bodyEntry struct {
	hash [32]byte
	raw  []byte
	copy BodyCopy
}

// MarkLog is one signer's mark log, as one runner process holds it.
//
// Each process signs its records with a key of its own: a random seed that
// platform.Keys makes and wraps under the attested key release. The
// wrapped seed travels in every record (KeyBlob), so a reader needs no
// local state to check a record: it opens the blob with the key release
// (only a runner of the same image, setup and signer can) and checks the
// signature with the key inside. A runner that lost its state directory
// reads its log as before.
type MarkLog struct {
	log    Log
	signer string
	setup  [32]byte // zero on the flag path
	prefix string
	keys   platform.Keys
	opt    Options

	key  ed25519.PrivateKey // this process's signing key, made at Claim
	blob []byte             // its seed, wrapped
	pubs map[string]ed25519.PublicKey
	bad  map[string]bool // blobs the key release refused as not authentic

	mu      namedMutex[markLogMuName]
	owner   [16]byte
	claimed bool
	version uint64 // newest record this process wrote or read
	hash    [32]byte
	logID   [32]byte
	written time.Time // time of the newest record
	mark    backend.Watermark
	exits   *ExitDay // the day's exits the newest record carries
	// gate is the source gate the next record carries (SetSourceGate); at
	// Claim the newest record's.
	gate    *uint64
	state   ConfigState
	bodies  map[bodyKey]*bodyEntry
	found   bool // a record with a mark existed at Claim
	lost    error
	skipped int
	writes  uint64
	// handedOver: the log ends with a tombstone. handoverMark is the mark
	// before it, the one a handover gives the next image (known when the
	// record before the tombstone was read or written by this process).
	// target is the setup_hash the tombstone names, if any.
	handedOver   bool
	handoverMark backend.Watermark
	hasHandover  bool
	target       *[32]byte
}

// New returns the log of signer, with the platform's key release keys.
func New(l Log, signer string, keys platform.Keys, opt Options) (*MarkLog, error) {
	if l == nil || keys == nil {
		return nil, errors.New("markstore: log and key release are required")
	}
	if err := CheckSigner(signer); err != nil {
		return nil, err
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Log == nil {
		opt.Log = slog.Default()
	}
	m := &MarkLog{log: l, signer: signer, keys: keys, opt: opt, pubs: map[string]ed25519.PublicKey{}, bad: map[string]bool{},
		bodies: map[bodyKey]*bodyEntry{}}
	if s := opt.Setup; s != nil {
		switch {
		case s.Hash == [32]byte{}:
			return nil, errors.New("markstore: setup with a zero setup_hash")
		case s.Signer != signer:
			return nil, fmt.Errorf("markstore: the setup names signer %q, the log is %q", s.Signer, signer)
		case s.RetentionDays == 0:
			return nil, errors.New("markstore: slashing_log_min_lock_days is 0")
		case s.First.Locked.Version != 0 || s.First.Open.Version != 0 || s.First.Locked.Pending != nil ||
			s.First.Open.Pending != nil || s.First.Order != nil:
			return nil, errors.New("markstore: the first config state is version 0 of both groups, with nothing pending")
		case opt.Clock == nil:
			return nil, errors.New("markstore: a log with a setup needs the trusted clock (Options.Clock)")
		}
		m.setup, m.state = s.Hash, s.First.Clone()
	}
	m.prefix = Prefix(m.setup, signer)
	if _, err := rand.Read(m.owner[:]); err != nil {
		return nil, err
	}
	return m, nil
}

// now is the time the log writes and checks against: the trusted clock with
// a setup, Options.Now without.
func (m *MarkLog) now() (time.Time, error) {
	if m.opt.Clock != nil {
		t, err := m.opt.Clock()
		if err != nil {
			return time.Time{}, fmt.Errorf("markstore: trusted clock: %w", err)
		}
		return t, nil
	}
	return m.opt.Now(), nil
}

// version entry: every object stored under one version name.
type versionEntries struct {
	v       uint64
	entries []Entry
}

func (m *MarkLog) listVersions(ctx context.Context) ([]versionEntries, int, error) {
	ents, err := m.log.List(ctx, m.prefix)
	if err != nil {
		return nil, 0, err
	}
	byV := map[uint64][]Entry{}
	odd := 0
	for _, e := range ents {
		v, ok := versionOf(m.prefix, e.Name)
		if !ok {
			odd++
			continue
		}
		byV[v] = append(byV[v], e)
	}
	out := make([]versionEntries, 0, len(byV))
	for v, es := range byV {
		out = append(out, versionEntries{v, es})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].v > out[j].v })
	return out, odd, nil
}

// pubOf opens a key blob with the key release and returns the public key
// of the seed inside. platform.ErrNotAuthentic: the blob was not made by a
// runner of this image for this setup and signer. Any other error means the
// key release could not answer; the caller stops (a record it cannot check
// must not be taken for an invalid one).
func (m *MarkLog) pubOf(ctx context.Context, blob []byte) (ed25519.PublicKey, error) {
	if p, ok := m.pubs[string(blob)]; ok {
		return p, nil
	}
	if m.bad[string(blob)] {
		return nil, platform.ErrNotAuthentic
	}
	seed, err := m.keys.OpenKey(ctx, blob, KeyAAD(m.setup, m.signer))
	if errors.Is(err, platform.ErrNotAuthentic) {
		m.bad[string(blob)] = true
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("markstore: key release: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		m.bad[string(blob)] = true
		return nil, platform.ErrNotAuthentic
	}
	p := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	clear(seed)
	m.pubs[string(blob)] = p
	return p, nil
}

// validAt reads every object stored under version v and returns the valid
// records (a key blob the key release opens for this setup and signer, a
// signature under the key inside, right setup, signer and version) with
// their encodings.
//
// strict is the fail-closed reader rule for the versions at and above the
// newest valid record (Claim): an object this runner cannot parse whose
// header (RecordHeader) names this setup, signer and version and whose key
// blob the key release opens is a record a runner of this key release
// wrote, most likely a newer image with a field this one does not know.
// Skipping it would fall back to an older mark, so validAt fails instead
// and the runner does not start. An object whose key blob does not open
// was not written under this key release and is skipped as before.
func (m *MarkLog) validAt(ctx context.Context, v uint64, es []Entry, strict bool) ([]*Record, [][]byte, error) {
	var recs []*Record
	var encs [][]byte
	for _, e := range es {
		b, err := m.log.Get(ctx, e)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		r, err := Parse(b)
		if err != nil && strict {
			if h, ok := RecordHeader(b); ok && h.Setup == m.setup && h.Signer == m.signer && h.Version == v {
				_, perr := m.pubOf(ctx, h.KeyBlob)
				switch {
				case perr == nil:
					return nil, nil, fmt.Errorf("%w: version %d (%s, magic %q) is a record of this signer under this key release that this runner cannot read (%v); "+
						"a newer image wrote it, and going back to the record below it would lose its mark (refusing to start)", ErrUnreadable, v, e.Name, h.Magic, err)
				case !errors.Is(perr, platform.ErrNotAuthentic):
					return nil, nil, perr
				}
			}
		}
		var pub ed25519.PublicKey
		if err == nil {
			pub, err = m.pubOf(ctx, r.KeyBlob)
			if err != nil && !errors.Is(err, platform.ErrNotAuthentic) {
				return nil, nil, err
			}
		}
		if err == nil {
			err = r.Verify(pub, m.setup, m.signer, v)
		}
		if err != nil {
			m.opt.Log.Warn("mark log: object is not a valid record, skipped", "name", e.Name, "ref", e.Ref, "why", err)
			continue
		}
		dup := false
		for _, x := range encs {
			dup = dup || bytes.Equal(x, b)
		}
		if !dup {
			recs, encs = append(recs, r), append(encs, b)
		}
	}
	return recs, encs, nil
}

// newest finds the highest valid record and checks its link to the record
// it names: no valid record between, the same hash and the same log_id.
// Nil without error: the log holds no valid record; then present is the
// number of record names that hold objects anyway.
func (m *MarkLog) newest(ctx context.Context) (r *Record, enc []byte, present int, err error) {
	vs, odd, err := m.listVersions(ctx)
	if err != nil {
		return nil, nil, 0, err
	}
	if odd > 0 {
		m.opt.Log.Warn("mark log: objects under the prefix that are not record names", "count", odd)
	}
	for i, ve := range vs {
		recs, encs, err := m.validAt(ctx, ve.v, ve.entries, true)
		if err != nil {
			return nil, nil, 0, err
		}
		if len(recs) == 0 {
			continue
		}
		if len(recs) > 1 {
			return nil, nil, 0, fmt.Errorf("markstore: %d different valid records at version %d: two writers with this signer's key (refusing)", len(recs), ve.v)
		}
		r, enc = recs[0], encs[0]
		// The chain: no valid record between the one it names and itself,
		// and the one it names, if still there (records expire oldest
		// first), is the one it hashed and belongs to the same log.
		for _, lower := range vs[i+1:] {
			if lower.v < r.PrevVersion {
				break
			}
			lr, lenc, err := m.validAt(ctx, lower.v, lower.entries, false)
			if err != nil {
				return nil, nil, 0, err
			}
			if lower.v > r.PrevVersion && len(lr) > 0 {
				return nil, nil, 0, fmt.Errorf("markstore: version %d skips the valid record %d below it: a fork (refusing)", r.Version, lower.v)
			}
			if lower.v == r.PrevVersion && len(lr) > 0 {
				var prev *Record
				var prevEnc []byte
				for j, e := range lenc {
					if Hash(e) == r.PrevHash {
						prev, prevEnc = lr[j], e
					}
				}
				if prev == nil {
					return nil, nil, 0, fmt.Errorf("markstore: version %d does not link to the record at version %d: a fork (refusing)", r.Version, lower.v)
				}
				if logIDOf(prev, prevEnc) != r.LogID {
					return nil, nil, 0, fmt.Errorf("markstore: version %d names another log_id than the record it links to (refusing)", r.Version)
				}
			}
		}
		return r, enc, 0, nil
	}
	return nil, nil, len(vs), nil
}

func hintKey(signer string) string { return "mark-hint/" + signer }
func hintAAD(setup [32]byte, signer string) []byte {
	return setupwire.CtxMarkHint.Message(setup[:], []byte(signer))
}
func encodeHint(v uint64, h [32]byte) []byte {
	return append(binary.BigEndian.AppendUint64(nil, v), h[:]...)
}

func (m *MarkLog) readHint() (uint64, [32]byte, bool) {
	var h [32]byte
	if m.opt.HintStore == nil || m.opt.HintSealer == nil {
		return 0, h, false
	}
	blob, err := m.opt.HintStore.Get(hintKey(m.signer))
	if err != nil {
		return 0, h, false
	}
	b, err := m.opt.HintSealer.Unseal(blob, hintAAD(m.setup, m.signer))
	if err != nil || len(b) != 40 {
		m.opt.Log.Warn("mark log: hint does not unseal; ignored")
		return 0, h, false
	}
	copy(h[:], b[8:])
	return binary.BigEndian.Uint64(b), h, true
}

func (m *MarkLog) writeHint() {
	if m.opt.HintStore == nil || m.opt.HintSealer == nil {
		return
	}
	blob, err := m.opt.HintSealer.Seal(encodeHint(m.version, m.hash), hintAAD(m.setup, m.signer))
	if err == nil {
		err = m.opt.HintStore.Put(hintKey(m.signer), blob)
	}
	if err != nil {
		m.opt.Log.Warn("mark log: hint not written", "err", err)
	}
}

// Claim reads the newest valid record and takes the log over for this
// process with a record of its own (the same mark and config state, a new
// owner), so an older instance's next write conflicts. Call it once at
// start, before any validator is loaded; an error means the runner must not
// start. expect says the node holds shares (the list taken once before the
// claim), so an empty log means records were lost: Claim refuses unless
// AllowCreate is set. An empty log without shares is a first start: the
// claim record is record 1, with the setup's first config state, and its
// hash is the log_id.
//
// With a setup, Claim also runs the age check and reads the update bodies
// the newest record names. A body with no readable copy does not stop the
// claim: Body reports ErrBodyMissing for it, and the effective config must
// refuse to sign once it needs it.
func (m *MarkLog) Claim(ctx context.Context, expect bool) (backend.Watermark, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.claimed {
		return backend.Watermark{}, false, errors.New("markstore: already claimed")
	}
	r, enc, present, err := m.newest(ctx)
	if err != nil {
		return backend.Watermark{}, false, fmt.Errorf("mark log %s: %w", m.log, err)
	}
	var h [32]byte
	if r != nil {
		h = Hash(enc)
	}
	hv, hh, hasHint := m.readHint()
	switch {
	case r == nil && hasHint && hv > 0:
		return backend.Watermark{}, false, fmt.Errorf("mark log %s: empty, but this runner wrote version %d before (log replaced or listing stale; refusing)", m.log, hv)
	case r == nil && present > 0 && !m.opt.AllowCreate:
		// Records whose keys this key release does not open (another
		// image, another key version) or objects that are not records.
		// Starting over could drop a mark that exists: refuse.
		return backend.Watermark{}, false, fmt.Errorf("mark log %s: %d record names hold objects but none is a valid record of this signer: the key release does not open their keys, or they are not records (refusing to start; -mark-create overrides)", m.log, present)
	case r == nil && expect && !m.opt.AllowCreate:
		return backend.Watermark{}, false, fmt.Errorf("mark log %s: no valid record, but this node holds shares (log lost; refusing to start)", m.log)
	case r != nil && hasHint && hv > r.Version:
		return backend.Watermark{}, false, fmt.Errorf("mark log %s: newest valid record is version %d, but this runner wrote version %d (records hidden or listing stale; refusing)", m.log, r.Version, hv)
	case r != nil && hasHint && hv == r.Version && hh != h:
		return backend.Watermark{}, false, fmt.Errorf("mark log %s: record %d is not the one this runner wrote (refusing)", m.log, hv)
	}
	if r != nil && m.opt.Setup != nil {
		now, err := m.now()
		if err != nil {
			return backend.Watermark{}, false, fmt.Errorf("mark log %s: %w", m.log, err)
		}
		written := time.Unix(int64(r.Time), 0)
		if age := now.Sub(written); age > m.opt.Setup.Retention()/2 {
			return backend.Watermark{}, false, fmt.Errorf("mark log %s: %w: version %d was written %s ago, the retention is %d days (a new setup and a re-import are needed)",
				m.log, ErrTooOld, r.Version, age.Round(time.Second), m.opt.Setup.RetentionDays)
		}
	}
	if r != nil {
		m.version, m.hash, m.mark = r.Version, h, r.Mark
		m.logID, m.written = logIDOf(r, enc), time.Unix(int64(r.Time), 0)
		m.state, m.target, m.exits = r.State.Clone(), r.Target, r.Exits.Clone()
		m.gate = cloneGate(r.SourceGate)
		m.found = r.Mark.HasAttestation || r.Mark.HasBlock
		if err := m.readBodies(ctx, r); err != nil {
			return backend.Watermark{}, false, fmt.Errorf("mark log %s: update bodies: %w", m.log, err)
		}
		m.opt.Log.Info("mark log: newest record", "store", m.log.String(), "signer", m.signer, "version", r.Version,
			"owner", hex.EncodeToString(r.Owner[:4]), "log_id", hex.EncodeToString(m.logID[:8]),
			"locked_version", r.State.Locked.Version, "open_version", r.State.Open.Version,
			"block_slot", r.Mark.BlockSlot, "source", r.Mark.SourceEpoch, "target", r.Mark.TargetEpoch)
	}
	if r != nil && IsTombstone(r.Mark) {
		// Handed over: no claim record (nothing is signed under the
		// tombstone, so there is nothing to fence), but find the mark before
		// it, so the handover can be repeated after this restart.
		prev, ok, err := m.markBefore(ctx, r)
		if err != nil {
			return backend.Watermark{}, false, fmt.Errorf("mark log %s: the record before the tombstone: %w", m.log, err)
		}
		m.handedOver, m.handoverMark, m.hasHandover = true, prev, ok
		m.lost, m.claimed = ErrHandedOver, true
		m.opt.Log.Warn("mark log: this signer was handed over to another image; nothing is signed", "store", m.log.String(),
			"signer", m.signer, "tombstone_version", r.Version, "mark_before_known", ok,
			"target", prev.TargetEpoch, "source", prev.SourceEpoch, "block", prev.BlockSlot)
		return m.mark, true, nil
	}
	if m.key == nil {
		seed, blob, err := m.keys.NewKey(ctx, KeyAAD(m.setup, m.signer))
		if err != nil {
			return backend.Watermark{}, false, fmt.Errorf("mark log %s: new signing key: %w", m.log, err)
		}
		if len(seed) != ed25519.SeedSize || len(blob) == 0 || len(blob) > maxKeyBlob {
			return backend.Watermark{}, false, fmt.Errorf("mark log %s: key release gave a %d-byte key and a %d-byte blob", m.log, len(seed), len(blob))
		}
		m.key, m.blob = ed25519.NewKeyFromSeed(seed), blob
		clear(seed)
		m.pubs[string(blob)] = m.key.Public().(ed25519.PublicKey)
	}
	if err := m.appendLocked(ctx, m.mark, nil); err != nil {
		return backend.Watermark{}, false, fmt.Errorf("mark log %s: claim: %w", m.log, err)
	}
	m.claimed = true
	m.opt.Log.Info("mark log: claimed", "store", m.log.String(), "signer", m.signer, "version", m.version,
		"owner", hex.EncodeToString(m.owner[:4]), "log_id", hex.EncodeToString(m.logID[:8]), "first_start", r == nil, "had_mark", m.found)
	return m.mark, m.found, nil
}

// readBodies keeps the copy numbers r names and reads one copy of every
// body r's state names.
func (m *MarkLog) readBodies(ctx context.Context, r *Record) error {
	m.bodies = map[bodyKey]*bodyEntry{}
	for _, ref := range refsOf(&r.State) {
		e := &bodyEntry{hash: ref.hash, copy: r.Copies[ref.slot]}
		m.bodies[ref.key] = e
		raw, err := m.findBody(ctx, ref.key, ref.hash)
		if errors.Is(err, ErrBodyMissing) {
			m.opt.Log.Error("mark log: no readable copy of an update body the newest record names", "group", ref.key.g.String(),
				"version", ref.key.v, "hash", hex.EncodeToString(ref.hash[:8]), "copy", e.copy.N)
			continue
		}
		if err != nil {
			return err
		}
		e.raw = raw
	}
	return nil
}

// bodyRef is an update body a config state names, and its slot in
// Record.Copies.
type bodyRef struct {
	key  bodyKey
	hash [32]byte
	slot int
}

func refsOf(st *ConfigState) []bodyRef {
	var out []bodyRef
	for _, g := range []setupwire.Group{setupwire.GroupLocked, setupwire.GroupOpen} {
		gs, _ := st.Group(g)
		if gs.Version > 0 {
			out = append(out, bodyRef{bodyKey{g, gs.Version}, gs.Hash, bodyIndex(g, false)})
		}
		if p := gs.Pending; p != nil {
			out = append(out, bodyRef{bodyKey{g, p.Version}, p.Hash, bodyIndex(g, true)})
		}
	}
	return out
}

// BodyHash decodes a signed CONFIG_UPDATE and returns its group, version
// and hash (the hash the config state names).
func BodyHash(raw []byte) (setupwire.Group, uint64, [32]byte, error) {
	u, err := setupwire.DecodeUpdate(raw)
	if err != nil {
		return 0, 0, [32]byte{}, err
	}
	h, err := u.Body.Hash()
	return u.Body.Group, u.Body.Version, h, err
}

// findBody reads the copies of a body and returns the first that decodes to
// the expected group, version and hash. Anyone with write access can put
// objects under these names, so a copy counts only by its content.
func (m *MarkLog) findBody(ctx context.Context, k bodyKey, want [32]byte) ([]byte, error) {
	es, err := m.log.List(ctx, BodyPrefix(m.setup, k.g, k.v))
	if err != nil {
		return nil, err
	}
	for _, e := range es {
		b, err := m.log.Get(ctx, e)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		g, v, h, err := BodyHash(b)
		if err == nil && g == k.g && v == k.v && h == want {
			return b, nil
		}
		m.opt.Log.Warn("mark log: object under a body name is not that body, skipped", "name", e.Name, "ref", e.Ref)
	}
	return nil, ErrBodyMissing
}

// markBefore walks back from the tombstone r along the chain to the newest
// record that is not a tombstone. ok is false when the chain ends first or a
// link does not hold (that record is gone or was replaced).
func (m *MarkLog) markBefore(ctx context.Context, r *Record) (backend.Watermark, bool, error) {
	cur := r
	for i := 0; i < 64 && cur.PrevVersion > 0; i++ {
		name := Name(m.setup, m.signer, cur.PrevVersion)
		es, err := m.log.List(ctx, name)
		if err != nil {
			return backend.Watermark{}, false, err
		}
		var exact []Entry
		for _, e := range es {
			if e.Name == name {
				exact = append(exact, e)
			}
		}
		recs, encs, err := m.validAt(ctx, cur.PrevVersion, exact, false)
		if err != nil {
			return backend.Watermark{}, false, err
		}
		var next *Record
		for i, e := range encs {
			if Hash(e) == cur.PrevHash {
				next = recs[i]
			}
		}
		if next == nil {
			return backend.Watermark{}, false, nil
		}
		if !IsTombstone(next.Mark) {
			return next.Mark, true, nil
		}
		cur = next
	}
	return backend.Watermark{}, false, nil
}

// Append writes a record with mark wm merged into the log's mark. It
// returns nil only once the record is durable in the log; the core signs
// past the old mark only then.
func (m *MarkLog) Append(ctx context.Context, wm backend.Watermark) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.claimed {
		return errors.New("markstore: not claimed")
	}
	return m.appendLocked(ctx, wm, nil)
}

// Raise makes the log's mark at least wm, with one record if it is not yet.
// A sealed import with interchange maxima (the handover's mark) raises it
// before the share is stored, so a restart reads the raised mark.
func (m *MarkLog) Raise(ctx context.Context, wm backend.Watermark) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.claimed {
		return errors.New("markstore: not claimed")
	}
	if m.lost == nil && Merge(m.mark, wm) == m.mark && m.version > 0 {
		return nil
	}
	return m.appendLocked(ctx, wm, nil)
}

// HandOverTo ends the log for a handover to the runner whose setup_hash is
// target: the tombstone names it (section 10, one target per tombstone).
// Called again for the same target it returns the same mark; for another
// target it refuses.
func (m *MarkLog) HandOverTo(ctx context.Context, target [32]byte) (backend.Watermark, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if target == ([32]byte{}) || target == m.setup {
		return backend.Watermark{}, errors.New("markstore: handover target must be another setup")
	}
	return m.handOverLocked(ctx, &target)
}

func (m *MarkLog) handOverLocked(ctx context.Context, target *[32]byte) (backend.Watermark, error) {
	if !m.claimed {
		return backend.Watermark{}, errors.New("markstore: not claimed")
	}
	if m.handedOver {
		switch {
		case (m.target == nil) != (target == nil) || m.target != nil && *m.target != *target:
			return backend.Watermark{}, errors.New("markstore: handed over to another target; a tombstone names one target only")
		case !m.hasHandover:
			return backend.Watermark{}, errors.New("markstore: handed over, but the mark before the tombstone is not readable; the handover cannot be repeated")
		}
		return m.handoverMark, nil
	}
	if m.lost != nil {
		return backend.Watermark{}, m.lost
	}
	before := m.mark
	if err := m.appendLocked(ctx, Tombstone, target); err != nil {
		return backend.Watermark{}, fmt.Errorf("markstore: tombstone: %w", err)
	}
	m.handedOver, m.handoverMark, m.hasHandover, m.target = true, before, true, target
	m.lost = ErrHandedOver
	m.opt.Log.Warn("mark log: handed over; tombstone written, nothing is signed from now on", "version", m.version,
		"target", before.TargetEpoch, "source", before.SourceEpoch, "block", before.BlockSlot, "named_target", target != nil)
	return before, nil
}

// HandedOver reports whether the log ends with a tombstone, and the mark
// before it if known.
func (m *MarkLog) HandedOver() (backend.Watermark, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.handoverMark, m.handedOver
}

// HandedOverTo returns the setup_hash the tombstone names, if the log ends
// with one that names a target.
func (m *MarkLog) HandedOverTo() ([32]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.handedOver || m.target == nil {
		return [32]byte{}, false
	}
	return *m.target, true
}

// copiesLocked fills a record's body copies from what the log holds for the
// state it writes.
func (m *MarkLog) copiesLocked() [4]BodyCopy {
	var out [4]BodyCopy
	for _, ref := range refsOf(&m.state) {
		if e := m.bodies[ref.key]; e != nil && e.hash == ref.hash {
			out[ref.slot] = e.copy
		}
	}
	return out
}

// sameTarget: both nil, or both name the same setup_hash.
func sameTarget(a, b *[32]byte) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}

func (m *MarkLog) appendLocked(ctx context.Context, wm backend.Watermark, target *[32]byte) error {
	if m.lost != nil {
		return m.lost
	}
	now, err := m.now()
	if err != nil {
		return err
	}
	wm = Merge(m.mark, wm)
	prevV, prevH := m.version, m.hash
	logID := m.logID
	if prevV == 0 {
		logID = [32]byte{} // the first record: its own hash is the log_id
	}
	for v, skips := prevV+1, 0; ; v, skips = v+1, skips+1 {
		if skips > maxSkips {
			return fmt.Errorf("markstore: %d names after version %d are taken by objects that are not records", maxSkips, prevV)
		}
		rec := Record{Setup: m.setup, Signer: m.signer, Version: v, PrevVersion: prevV, PrevHash: prevH, LogID: logID,
			Owner: m.owner, KeyBlob: m.blob, Mark: wm, Time: uint64(now.Unix()), State: m.state.Clone(),
			Copies: m.copiesLocked(), Target: target, Exits: m.exits.Clone(), SourceGate: cloneGate(m.gate)}
		if err := rec.check(); err != nil {
			return fmt.Errorf("markstore: record not written: %w", err)
		}
		enc := rec.Sign(m.key)
		name := Name(m.setup, m.signer, v)
		start := time.Now()
		err := m.log.Create(ctx, name, enc)
		createMS := time.Since(start).Milliseconds()
		if errors.Is(err, ErrExists) {
			es, lerr := m.log.List(ctx, name)
			if lerr != nil {
				return fmt.Errorf("markstore: version %d exists and cannot be read back: %w", v, lerr)
			}
			var mine []Entry
			for _, e := range es {
				if e.Name == name {
					mine = append(mine, e)
				}
			}
			recs, encs, gerr := m.validAt(ctx, v, mine, false)
			if gerr != nil {
				return fmt.Errorf("markstore: version %d exists and cannot be read back: %w", v, gerr)
			}
			if len(recs) == 0 {
				// Not a record: an object someone else put there. Skip the name.
				m.skipped++
				m.opt.Log.Warn("mark log: name taken by an object that is not a record; skipping it", "version", v)
				continue
			}
			// A valid record of another owner at this version is another
			// instance's write, also when this runner's own record lies
			// next to it (a hidden name, then a lost reply): latch first.
			for _, r := range recs {
				if r.Owner != m.owner {
					m.lost = ErrLost
					m.opt.Log.Error("mark log: another instance wrote this signer's log; refusing all signing",
						"version", v, "my_owner", hex.EncodeToString(m.owner[:4]), "other_owner", hex.EncodeToString(r.Owner[:4]),
						"records", len(recs))
					return m.lost
				}
			}
			for i, e := range encs {
				if bytes.Equal(e, enc) {
					// Our own write; its reply was lost.
					err = nil
					break
				}
				r := recs[i]
				if r.Owner != m.owner || r.PrevVersion != prevV || r.PrevHash != prevH || r.LogID != logID {
					continue
				}
				// Our own write from an earlier attempt whose reply was lost: a
				// record with this process's owner, linked to our last record.
				// Its time stamp, and maybe its mark, differ from this attempt's.
				before := m.mark
				m.version, m.hash, m.mark, m.written = v, Hash(e), r.Mark, time.Unix(int64(r.Time), 0)
				if prevV == 0 {
					m.logID = m.hash
				}
				m.writes++
				m.writeHint()
				m.opt.Log.Warn("mark log: found this runner's own record of an attempt whose reply was lost", "version", v)
				if IsTombstone(r.Mark) && !(IsTombstone(wm) && sameTarget(r.Target, target)) {
					// A handover whose reply was lost: the log is ended.
					m.handedOver, m.handoverMark, m.hasHandover, m.target = true, before, true, r.Target
					m.lost = ErrHandedOver
					return m.lost
				}
				if Merge(r.Mark, wm) == r.Mark && r.State.Equal(m.state) && sameTarget(r.Target, target) && exitsEqual(r.Exits, m.exits) &&
					sameGate(r.SourceGate, m.gate) {
					return nil
				}
				// It does not hold what this call writes: write that on top.
				break
			}
			if err != nil && m.version == v {
				wm = Merge(m.mark, wm)
				prevV, prevH, logID = v, m.hash, m.logID
				continue
			}
			if err != nil {
				m.lost = ErrLost
				m.opt.Log.Error("mark log: another instance wrote this signer's log; refusing new slashable signatures",
					"version", v, "my_owner", hex.EncodeToString(m.owner[:4]), "other_owner", hex.EncodeToString(recs[0].Owner[:4]))
				return m.lost
			}
		}
		if errors.Is(err, ErrHidden) {
			m.lost = ErrLost
			m.opt.Log.Error("mark log: a delete marker hid another object at the version this runner wrote; refusing new slashable signatures",
				"version", v, "err", err)
			return fmt.Errorf("%w: %v", ErrLost, err)
		}
		if err != nil {
			m.opt.Log.Warn("mark log: write failed", "version", v, "create_ms", createMS, "err", err)
			return fmt.Errorf("markstore: write version %d: %w", v, err)
		}
		m.version, m.hash, m.mark, m.written = v, Hash(enc), wm, now
		if prevV == 0 {
			m.logID = m.hash
		}
		m.writes++
		m.writeHint()
		// One line per record, for the timing of real stores: create_ms is
		// the conditional create (with a read-back after a lost reply),
		// total_ms adds the sealed hint.
		m.opt.Log.Info("mark log: wrote", "version", v, "target", wm.TargetEpoch, "source", wm.SourceEpoch,
			"block", wm.BlockSlot, "create_ms", createMS, "total_ms", time.Since(start).Milliseconds())
		return nil
	}
}

func cloneGate(g *uint64) *uint64 {
	if g == nil {
		return nil
	}
	c := *g
	return &c
}

func sameGate(a, b *uint64) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }

// SourceGate is the source gate of the newest record this process read or
// wrote, or the one SetSourceGate set since: the floor epoch and whether
// one holds.
func (m *MarkLog) SourceGate() (uint64, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.gate == nil {
		return 0, false
	}
	return *m.gate, true
}

// SetSourceGate sets the source gate the next record carries (on false:
// none). It writes nothing itself: no vote is signed under a new gate
// before a record, since every vote that passes it raises the mark.
func (m *MarkLog) SetSourceGate(floor uint64, on bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gate = nil
	if on {
		m.gate = &floor
	}
}

// Exits returns the day's exits the newest record carries (nil: none).
func (m *MarkLog) Exits() *ExitDay {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.exits.Clone()
}

// RecordExits writes a record that carries d as the day's exits, with the
// mark unchanged. It returns only once the record is durable: the runner
// signs the exit after it. A log that cannot be written, or that another
// instance wrote, refuses (ErrLost latches as for a mark).
func (m *MarkLog) RecordExits(ctx context.Context, d *ExitDay) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.claimed {
		return errors.New("markstore: not claimed")
	}
	if m.lost != nil {
		return m.lost
	}
	if d == nil || len(d.Exits) == 0 || len(d.Exits) > MaxExitsPerDay {
		return errors.New("markstore: exits: none or too many")
	}
	if m.exits != nil && d.Day < m.exits.Day {
		// The day never goes back (SHH-02): that would free the later
		// day's cap and nonces.
		return fmt.Errorf("markstore: exits of day %d under a log at day %d", d.Day, m.exits.Day)
	}
	old := m.exits
	m.exits = d.Clone()
	if err := m.appendLocked(ctx, m.mark, nil); err != nil {
		m.exits = old
		return err
	}
	return nil
}

// LogID is the log's log_id: the hash of its first record (zero before
// Claim). The share AAD binds it (ShareAAD).
func (m *MarkLog) LogID() [32]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.logID
}

// State is the config state of the newest record this process wrote or
// read: the setup's first state on a first start.
func (m *MarkLog) State() ConfigState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state.Clone()
}

// Body returns the signed CONFIG_UPDATE of version v of group g, as stored
// in the log (read at Claim or stored by PutBody), and its hash.
// ErrBodyMissing: no readable copy.
func (m *MarkLog) Body(g setupwire.Group, v uint64) ([]byte, [32]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.bodies[bodyKey{g, v}]
	if e == nil || e.raw == nil {
		return nil, [32]byte{}, fmt.Errorf("%w: %s version %d", ErrBodyMissing, g, v)
	}
	return bytes.Clone(e.raw), e.hash, nil
}

// PutBody stores a signed CONFIG_UPDATE in the log as received, before the
// record that names it (SetState): copy 1 of its group and version, or the
// next free copy when an object that is not this update holds the name.
// Sending the same update again writes nothing. It returns the update's
// group, version and hash. It does not check the update against the config
// state: that is the caller's job.
func (m *MarkLog) PutBody(ctx context.Context, raw []byte) (setupwire.Group, uint64, [32]byte, error) {
	g, v, h, err := BodyHash(raw)
	if err != nil {
		return 0, 0, [32]byte{}, fmt.Errorf("markstore: update body: %w", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case m.opt.Setup == nil:
		return 0, 0, [32]byte{}, errors.New("markstore: update bodies need a setup")
	case !m.claimed:
		return 0, 0, [32]byte{}, errors.New("markstore: not claimed")
	case m.lost != nil:
		return 0, 0, [32]byte{}, m.lost
	}
	k := bodyKey{g, v}
	e := m.bodies[k]
	if e != nil && e.hash == h && e.raw != nil {
		return g, v, h, nil
	}
	if e != nil && e.hash != h {
		for _, ref := range refsOf(&m.state) {
			if ref.key == k {
				return 0, 0, [32]byte{}, fmt.Errorf("markstore: %s version %d is already another update (%x)", g, v, e.hash[:8])
			}
		}
		e = nil
	}
	from := uint32(1)
	if e != nil {
		// Known by hash but unreadable at Claim: a new copy restores it.
		from = e.copy.N + 1
	}
	c, err := m.writeCopyLocked(ctx, k, raw, from)
	if err != nil {
		return 0, 0, [32]byte{}, err
	}
	m.bodies[k] = &bodyEntry{hash: h, raw: bytes.Clone(raw), copy: c}
	return g, v, h, nil
}

// writeCopyLocked writes raw as copy n of body k, from n on, skipping names
// that hold other objects.
func (m *MarkLog) writeCopyLocked(ctx context.Context, k bodyKey, raw []byte, from uint32) (BodyCopy, error) {
	now, err := m.now()
	if err != nil {
		return BodyCopy{}, err
	}
	for n, skips := from, 0; ; n, skips = n+1, skips+1 {
		if skips > maxSkips {
			return BodyCopy{}, fmt.Errorf("markstore: %d body names after copy %d are taken by other objects", maxSkips, from)
		}
		name := BodyName(m.setup, k.g, k.v, n)
		err := m.log.Create(ctx, name, raw)
		if errors.Is(err, ErrExists) {
			es, lerr := m.log.List(ctx, name)
			if lerr != nil {
				return BodyCopy{}, fmt.Errorf("markstore: body copy %s exists and cannot be read back: %w", name, lerr)
			}
			ours := false
			for _, e := range es {
				if e.Name != name {
					continue
				}
				b, gerr := m.log.Get(ctx, e)
				if gerr != nil && !errors.Is(gerr, ErrNotFound) {
					return BodyCopy{}, fmt.Errorf("markstore: body copy %s exists and cannot be read back: %w", name, gerr)
				}
				ours = ours || bytes.Equal(b, raw)
			}
			if !ours {
				m.opt.Log.Warn("mark log: body name taken by another object; skipping it", "name", name)
				continue
			}
			err = nil // our own write; its reply was lost
		}
		if err != nil {
			return BodyCopy{}, fmt.Errorf("markstore: write body copy %s: %w", name, err)
		}
		m.opt.Log.Info("mark log: wrote update body", "group", k.g.String(), "version", k.v, "copy", n)
		return BodyCopy{N: n, At: uint64(now.Unix())}, nil
	}
}

// SetState appends a record with the log's mark and the config state st: a
// new pending update, an update that became active, or a pending one
// replaced or dropped. Every update st names past version 0 must have its
// body in the log first (PutBody, or read at Claim). A group's active
// version never goes down, and version 0 is the setup's.
func (m *MarkLog) SetState(ctx context.Context, st ConfigState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case m.opt.Setup == nil:
		return errors.New("markstore: a config state needs a setup")
	case !m.claimed:
		return errors.New("markstore: not claimed")
	case m.lost != nil:
		return m.lost
	}
	first := m.opt.Setup.First
	for _, g := range []setupwire.Group{setupwire.GroupLocked, setupwire.GroupOpen} {
		ns, _ := st.Group(g)
		cs, _ := m.state.Group(g)
		fs, _ := first.Group(g)
		switch {
		case ns.Version < cs.Version || ns.Version == cs.Version && ns.Hash != cs.Hash:
			return fmt.Errorf("markstore: %s would go from version %d back to %d or to another update", g, cs.Version, ns.Version)
		case ns.Version == 0 && ns.Hash != fs.Hash:
			return fmt.Errorf("markstore: %s version 0 is the setup's group", g)
		case ns.Pending != nil && ns.Pending.Version <= ns.Version:
			return fmt.Errorf("markstore: %s pending version %d is not above the active %d", g, ns.Pending.Version, ns.Version)
		}
	}
	if o := st.Order; o != nil && o.Kind != OrderHandover && o.Kind != OrderDKG {
		return fmt.Errorf("markstore: order kind %d", o.Kind)
	}
	for _, ref := range refsOf(&st) {
		if e := m.bodies[ref.key]; e == nil || e.hash != ref.hash {
			return fmt.Errorf("markstore: %s version %d: the body is not in the log (PutBody first)", ref.key.g, ref.key.v)
		}
	}
	old := m.state
	m.state = st.Clone()
	if err := m.appendLocked(ctx, m.mark, nil); err != nil {
		m.state = old
		return err
	}
	m.pruneBodiesLocked()
	m.opt.Log.Info("mark log: config state", "version", m.version, "locked", st.Locked.Version, "open", st.Open.Version,
		"locked_pending", st.Locked.Pending != nil, "open_pending", st.Open.Pending != nil)
	return nil
}

// pruneBodiesLocked drops bodies the config state no longer names and
// never can: those at or below their group's active version. A body above
// it may be stored for a state that is not written yet.
func (m *MarkLog) pruneBodiesLocked() {
	keep := map[bodyKey]bool{}
	for _, ref := range refsOf(&m.state) {
		keep[ref.key] = true
	}
	for k := range m.bodies {
		if gs, err := m.state.Group(k.g); err == nil && !keep[k] && k.v <= gs.Version {
			delete(m.bodies, k)
		}
	}
}

// keepAlive is how old the newest record may get while the runner runs
// before Refresh writes one: the age check stops a restart once it is
// older than half the retention, so a signer may stay stopped for nearly
// that long.
func keepAlive(retention time.Duration) time.Duration { return min(retention/8, 24*time.Hour) }

// Refresh keeps the log readable for a restart (section 5): a body copy
// older than half the retention gets a new copy, and the log gets a new
// record (same mark and state, the new copies) when a copy was written or
// the newest record is older than keepAlive. Without a setup, and after a
// handover, it does nothing.
func (m *MarkLog) Refresh(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.opt.Setup == nil || !m.claimed || m.handedOver {
		return nil
	}
	if m.lost != nil {
		return m.lost
	}
	now, err := m.now()
	if err != nil {
		return err
	}
	ret := m.opt.Setup.Retention()
	wrote := false
	for _, ref := range refsOf(&m.state) {
		e := m.bodies[ref.key]
		if e == nil || now.Sub(time.Unix(int64(e.copy.At), 0)) < ret/2 {
			continue
		}
		if e.raw == nil {
			m.opt.Log.Error("mark log: update body older than half the retention and unreadable; it cannot be copied",
				"group", ref.key.g.String(), "version", ref.key.v, "copy", e.copy.N)
			continue
		}
		c, err := m.writeCopyLocked(ctx, ref.key, e.raw, e.copy.N+1)
		if err != nil {
			return err
		}
		e.copy, wrote = c, true
	}
	if !wrote && now.Sub(m.written) < keepAlive(ret) {
		return nil
	}
	return m.appendLocked(ctx, m.mark, nil)
}

// RefreshLoop calls Refresh every interval until ctx ends.
func (m *MarkLog) RefreshLoop(ctx context.Context, every time.Duration) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		rctx, cancel := context.WithTimeout(ctx, time.Minute)
		if err := m.Refresh(rctx); err != nil {
			m.opt.Log.Warn("mark log: refresh failed; it will try again", "err", err)
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// Mark is the newest mark this process wrote or read, and its version.
func (m *MarkLog) Mark() (backend.Watermark, uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mark, m.version
}

// Lost reports a takeover by another instance.
func (m *MarkLog) Lost() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lost
}

// Status describes the log for HEALTH and logs.
func (m *MarkLog) Status() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := fmt.Sprintf("marklog %s signer=%s owner=%s version=%d writes=%d target=%d source=%d block=%d",
		m.log, m.signer, hex.EncodeToString(m.owner[:4]), m.version, m.writes, m.mark.TargetEpoch, m.mark.SourceEpoch, m.mark.BlockSlot)
	if m.opt.Setup != nil {
		s += fmt.Sprintf(" setup=%s log_id=%s locked=%d open=%d", hex.EncodeToString(m.setup[:4]), hex.EncodeToString(m.logID[:4]),
			m.state.Locked.Version, m.state.Open.Version)
	}
	if m.skipped > 0 {
		s += fmt.Sprintf(" skipped=%d", m.skipped)
	}
	switch {
	case m.handedOver:
		s += " HANDED-OVER"
	case m.lost != nil:
		s += " LOST"
	}
	return s
}

func (m *MarkLog) String() string { return m.Status() }

// PublicKey is this process's signing key, public half, for logs (nil
// before Claim).
func (m *MarkLog) PublicKey() ed25519.PublicKey {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.key == nil {
		return nil
	}
	return m.key.Public().(ed25519.PublicKey)
}
