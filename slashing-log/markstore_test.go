package markstore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/dev"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// testKey is the key release of image n (dev.NewDevKeys).
func testKey(n byte) platform.Keys { return dev.NewDevKeys(string(rune('a' + n))) }

// testSetup is a setup of signer s with a retention of 30 days.
func testSetup(s string) *Setup {
	return &Setup{Hash: [32]byte{0x5e, 1}, Signer: s, RetentionDays: 30,
		First: ConfigState{Locked: GroupState{Hash: [32]byte{0x10}}, Open: GroupState{Hash: [32]byte{0x20}}}}
}

// clockAt is a trusted clock that reads *t.
func clockAt(t *time.Time) func() (time.Time, error) {
	return func() (time.Time, error) { return *t, nil }
}

// signed makes a record under keys and returns its encoding.
func signed(t *testing.T, keys platform.Keys, r Record) []byte {
	t.Helper()
	seed, blob, err := keys.NewKey(context.Background(), KeyAAD(r.Setup, r.Signer))
	if err != nil {
		t.Fatal(err)
	}
	r.KeyBlob = blob
	return r.Sign(ed25519.NewKeyFromSeed(seed))
}

// decode is what a reader does: parse, open the key blob, verify.
func decode(enc []byte, keys platform.Keys, setup [32]byte, signer string, v uint64) (*Record, error) {
	r, err := Parse(enc)
	if err != nil {
		return nil, err
	}
	seed, err := keys.OpenKey(context.Background(), r.KeyBlob, KeyAAD(setup, signer))
	if err != nil {
		return nil, err
	}
	return r, r.Verify(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey), setup, signer, v)
}

func mark(t uint64) backend.Watermark {
	return backend.Watermark{HasAttestation: true, SourceEpoch: t - 1, TargetEpoch: t, HasBlock: true, BlockSlot: t * 32}
}

// openUpdate is a signed CONFIG_UPDATE of the open group at version v.
func openUpdate(t *testing.T, v uint64, tag byte) []byte {
	t.Helper()
	u := setupwire.Update{Body: setupwire.UpdateBody{ClusterID: [32]byte{1}, Group: setupwire.GroupOpen, Version: v,
		Open:  &setupwire.Open{ForkSchedule: []setupwire.Fork{{Epoch: uint64(tag), Version: backend.Version{tag}}}},
		Salts: setupwire.Salts{{tag, 1}, {tag, 2}}},
		Approvals: []setupwire.Approval{{Position: 0}}}
	b, err := u.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// memLog keeps several objects per name, as S3 versions do, so tests can
// put a second valid record under one name.
type memLog struct{ objs map[string][][]byte }

func (m *memLog) Create(_ context.Context, name string, data []byte) error {
	if len(m.objs[name]) > 0 {
		return ErrExists
	}
	m.objs[name] = [][]byte{data}
	return nil
}
func (m *memLog) List(_ context.Context, prefix string) ([]Entry, error) {
	var out []Entry
	for n, vs := range m.objs {
		if strings.HasPrefix(n, prefix) {
			for i := range vs {
				out = append(out, Entry{Name: n, Ref: string(rune('0' + i))})
			}
		}
	}
	return out, nil
}
func (m *memLog) Get(_ context.Context, e Entry) ([]byte, error) {
	vs := m.objs[e.Name]
	i := int(e.Ref[0] - '0')
	if i >= len(vs) {
		return nil, ErrNotFound
	}
	return vs[i], nil
}
func (m *memLog) String() string { return "mem" }

func TestFileLogWriteOnce(t *testing.T) {
	dir := t.TempDir()
	l, err := Open("file:"+dir, Env{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := l.Create(ctx, "marks/s/1", []byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := l.Create(ctx, "marks/s/1", []byte("b")); !errors.Is(err, ErrExists) {
		t.Fatalf("second create: %v", err)
	}
	b, _ := l.Get(ctx, Entry{Name: "marks/s/1"})
	if string(b) != "a" {
		t.Fatalf("overwritten: %q", b)
	}
	fi, _ := os.Stat(filepath.Join(dir, "marks/s/1"))
	if fi.Mode().Perm()&0o222 != 0 {
		t.Fatalf("record file is writable: %v", fi.Mode())
	}
	if _, err := Open("s3:bucket=b,region=r", Env{}); err == nil || !strings.Contains(err.Error(), "not built") {
		t.Fatalf("s3 in a build without it: %v", err)
	}
	if _, err := Open("file:", Env{}); err == nil {
		t.Fatal("file: without a directory")
	}
}

func TestRecordEncoding(t *testing.T) {
	k := testKey(1)
	s := testSetup("signer-1")
	pend := &Pending{Version: 4, Hash: [32]byte{4}, EffectiveAt: 1_900_000_000}
	r0 := Record{Setup: s.Hash, Signer: "signer-1", Version: 7, PrevVersion: 6, LogID: [32]byte{7}, Mark: mark(40), Time: 1,
		State:  ConfigState{Locked: GroupState{Version: 2, Hash: [32]byte{2}}, Open: GroupState{Version: 3, Hash: [32]byte{3}, Pending: pend}},
		Copies: [4]BodyCopy{{N: 1, At: 10}, {}, {N: 2, At: 20}, {N: 1, At: 30}}}
	enc := signed(t, k, r0)
	got, err := decode(enc, k, s.Hash, "signer-1", 7)
	if err != nil || got.Mark != mark(40) || got.PrevVersion != 6 || got.LogID != r0.LogID || !got.State.Equal(r0.State) || got.Copies != r0.Copies {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	t.Logf("record with a dev key blob and two bodies: %d bytes", len(enc))
	// A record whose blob opens but whose signature is by another key.
	r2, _ := Parse(enc)
	other := r2.Sign(ed25519.NewKeyFromSeed(make([]byte, 32)))
	for name, c := range map[string]func() error{
		"another key release":             func() error { _, e := decode(enc, testKey(2), s.Hash, "signer-1", 7); return e },
		"another setup":                   func() error { _, e := decode(enc, k, [32]byte{9}, "signer-1", 7); return e },
		"another signer":                  func() error { _, e := decode(enc, k, s.Hash, "signer-2", 7); return e },
		"another name":                    func() error { _, e := decode(enc, k, s.Hash, "signer-1", 8); return e },
		"signed by a key not in its blob": func() error { _, e := decode(other, k, s.Hash, "signer-1", 7); return e },
		"one bit flipped": func() error {
			b := append([]byte(nil), enc...)
			b[len(b)-70] ^= 1
			_, e := decode(b, k, s.Hash, "signer-1", 7)
			return e
		},
		"truncated": func() error {
			_, e := decode(enc[:len(enc)-1], k, s.Hash, "signer-1", 7)
			return e
		},
	} {
		if c() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if CheckSigner("Signer/1") == nil || CheckSigner("") == nil || CheckSigner("signer-1") != nil {
		t.Fatal("signer ID check")
	}
	if Name([32]byte{}, "s", 12) != "marks/s/00000000000000000012" {
		t.Fatal(Name([32]byte{}, "s", 12))
	}
	if n := Name([32]byte{0xab}, "s", 12); n != "marks/ab"+strings.Repeat("00", 31)+"/s/00000000000000000012" {
		t.Fatal(n)
	}
	if n := BodyName([32]byte{0xab}, setupwire.GroupOpen, 3, 2); n != "config/ab"+strings.Repeat("00", 31)+"/open/00000000000000000003/2" {
		t.Fatal(n)
	}
}

// Parse refuses every encoding the format does not allow, so no record
// reads two ways.
func TestRecordStrict(t *testing.T) {
	k := testKey(1)
	s := testSetup("s")
	base := Record{Setup: s.Hash, Signer: "s", Version: 2, PrevVersion: 1, LogID: [32]byte{1}, Mark: mark(5), State: s.First}
	if _, err := Parse(signed(t, k, base)); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(r *Record){
		"log_id zero in a later record": func(r *Record) { r.LogID = [32]byte{} },
		"log_id in a first record":      func(r *Record) { r.PrevVersion = 0 },
		"target on a plain record":      func(r *Record) { r.Target = &[32]byte{1} },
		"active body without a copy":    func(r *Record) { r.State.Open.Version = 1 },
		"copy for version 0":            func(r *Record) { r.Copies[0] = BodyCopy{N: 1} },
		"pending at the active version": func(r *Record) { r.State.Open.Pending = &Pending{Version: 0}; r.Copies[3] = BodyCopy{N: 1} },
		"pending without a copy":        func(r *Record) { r.State.Open.Pending = &Pending{Version: 1} },
		"order of an unknown kind":      func(r *Record) { r.State.Order = &Order{Kind: 3} },
		"order of kind 2":               func(r *Record) { r.State.Order = &Order{Kind: 2, Hash: [32]byte{8}, ActAt: 9} },
		"order of kind 0":               func(r *Record) { r.State.Order = &Order{Kind: 0} },
		"links forward":                 func(r *Record) { r.PrevVersion = 2 },
	} {
		r := base
		r.State = base.State.Clone()
		edit(&r)
		if _, err := Parse(signed(t, k, r)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	// A copy for no pending update has no place in the encoding; the
	// writer's check refuses it.
	noPending := base
	noPending.Copies[1] = BodyCopy{N: 1}
	if noPending.check() == nil {
		t.Error("a body copy for no pending update passed the check")
	}
	enc := signed(t, k, base)
	body := enc[:len(enc)-64]
	for name, b := range map[string][]byte{
		"presence byte 2": append(append([]byte(nil), body[:len(body)-1]...), 2),
		"trailing byte":   append(append([]byte(nil), body...), 0),
	} {
		if _, err := Parse(append(b, enc[len(enc)-64:]...)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	tomb := base
	tomb.Mark, tomb.Target = Tombstone, &[32]byte{7}
	if r, err := Parse(signed(t, k, tomb)); err != nil || r.Target == nil || *r.Target != [32]byte{7} {
		t.Fatalf("tombstone with a target: %+v %v", r, err)
	}
	order := base
	order.State.Order = &Order{Kind: OrderHandover, Hash: [32]byte{8}, ActAt: 9}
	if r, err := Parse(signed(t, k, order)); err != nil || *r.State.Order != *order.State.Order {
		t.Fatalf("pending order: %+v %v", r, err)
	}
}

// SetupOf takes the signer, the retention and version 0 of both groups
// from a setup.
func TestSetupOf(t *testing.T) {
	raw, err := os.ReadFile("../governance/setupwire/testdata/setup-gcp.bin")
	if err != nil {
		t.Fatal(err)
	}
	ws, err := setupwire.DecodeSetup(raw)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := ws.Hash()
	s, err := SetupOf(ws, h)
	if err != nil {
		t.Fatal(err)
	}
	lh, _ := ws.GroupHash(setupwire.GroupLocked)
	oh, _ := ws.GroupHash(setupwire.GroupOpen)
	if s.Signer != ws.SignerName || s.RetentionDays != ws.SlashingLogMinLockDays || s.Hash != h ||
		!s.First.Equal(ConfigState{Locked: GroupState{Hash: lh}, Open: GroupState{Hash: oh}}) {
		t.Fatalf("%+v", s)
	}
	if _, err := New(&memLog{objs: map[string][][]byte{}}, "other", testKey(1), Options{Setup: s, Clock: func() (time.Time, error) { return time.Now(), nil }, Log: quiet}); err == nil {
		t.Fatal("a log for another signer than the setup's")
	}
}

func TestMarkLogOnFiles(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	opt := Options{Setup: testSetup("signer-1"), Clock: clockAt(&now), Log: quiet}
	l, _ := NewFileLog(t.TempDir())
	m, _ := New(l, "signer-1", testKey(1), opt)
	if _, found, err := m.Claim(ctx, false); err != nil || found {
		t.Fatalf("claim: %v %v", found, err)
	}
	for e := uint64(5); e < 9; e++ {
		if err := m.Append(ctx, mark(e)); err != nil {
			t.Fatal(err)
		}
	}
	_, _, h, err := m.PutBody(ctx, openUpdate(t, 1, 1))
	if err != nil {
		t.Fatal(err)
	}
	st := m.State()
	st.Open.Pending = &Pending{Version: 1, Hash: h, EffectiveAt: 1_800_000_100}
	if err := m.SetState(ctx, st); err != nil {
		t.Fatal(err)
	}
	// Kind 2, the key generation order of earlier builds, is not a kind.
	kind2 := st.Clone()
	kind2.Order = &Order{Kind: 2, Hash: [32]byte{8}, ActAt: 1_800_000_100}
	if err := m.SetState(ctx, kind2); err == nil {
		t.Fatal("SetState took an order of kind 2")
	}
	m2, _ := New(l, "signer-1", testKey(1), opt)
	got, found, err := m2.Claim(ctx, true)
	if err != nil || !found || got != mark(8) || !m2.State().Equal(st) || m2.LogID() != m.LogID() {
		t.Fatalf("restart: %+v %v %v", got, found, err)
	}
	if !strings.Contains(m2.Status(), "version=7") || !strings.Contains(m2.Status(), "open=0") {
		t.Fatalf("status %s", m2.Status())
	}
	if b, _, err := m2.Body(setupwire.GroupOpen, 1); err != nil || !bytes.Equal(b, openUpdate(t, 1, 1)) {
		t.Fatalf("body: %v", err)
	}
	// Another key release (another image): no valid record, objects under
	// record names, so it refuses to start, with or without shares.
	for _, shares := range []bool{true, false} {
		m3, _ := New(l, "signer-1", testKey(9), opt)
		if _, _, err := m3.Claim(ctx, shares); err == nil {
			t.Fatalf("claim under another key release (shares %v)", shares)
		}
	}
	// The file log has no lock: the lock check refuses it.
	if err := CheckLock(ctx, l, 1); !errors.Is(err, ErrNoLock) {
		t.Fatalf("lock check of a file log: %v", err)
	}
	if err := CheckLock(ctx, &memLog{}, 1); !errors.Is(err, ErrNoLock) {
		t.Fatalf("lock check of a log without Lock: %v", err)
	}
}

func TestForkRefused(t *testing.T) {
	ctx := context.Background()
	k := testKey(1)
	put := func(l *memLog, v, prev uint64, prevEnc []byte, owner byte, t2 uint64, logID [32]byte) []byte {
		r := Record{Signer: "s", Version: v, PrevVersion: prev, LogID: logID, Mark: mark(t2)}
		r.Owner[0] = owner
		if prevEnc != nil {
			r.PrevHash = Hash(prevEnc)
		}
		enc := signed(t, k, r)
		l.objs[Name([32]byte{}, "s", v)] = append(l.objs[Name([32]byte{}, "s", v)], enc)
		return enc
	}
	// Version 3 names version 1 as its predecessor, but a valid 2 exists.
	l := &memLog{objs: map[string][][]byte{}}
	r1 := put(l, 1, 0, nil, 1, 5, [32]byte{})
	id := Hash(r1)
	put(l, 2, 1, r1, 1, 6, id)
	put(l, 3, 1, r1, 2, 7, id)
	m, _ := New(l, "s", k, Options{Log: quiet})
	if _, _, err := m.Claim(ctx, true); err == nil || !strings.Contains(err.Error(), "fork") {
		t.Fatalf("skipped valid record: %v", err)
	}
	// Two different valid records under one name.
	l = &memLog{objs: map[string][][]byte{}}
	r1 = put(l, 1, 0, nil, 1, 5, [32]byte{})
	put(l, 2, 1, r1, 1, 6, Hash(r1))
	put(l, 2, 1, r1, 2, 9, Hash(r1))
	m, _ = New(l, "s", k, Options{Log: quiet})
	if _, _, err := m.Claim(ctx, true); err == nil || !strings.Contains(err.Error(), "two writers") {
		t.Fatalf("two records at one version: %v", err)
	}
	// A record whose link does not match the record it names.
	l = &memLog{objs: map[string][][]byte{}}
	r1 = put(l, 1, 0, nil, 1, 5, [32]byte{})
	put(l, 2, 1, []byte("not the record"), 1, 6, Hash(r1))
	m, _ = New(l, "s", k, Options{Log: quiet})
	if _, _, err := m.Claim(ctx, true); err == nil || !strings.Contains(err.Error(), "link") {
		t.Fatalf("broken link: %v", err)
	}
	// A record that links to its predecessor but names another log.
	l = &memLog{objs: map[string][][]byte{}}
	r1 = put(l, 1, 0, nil, 1, 5, [32]byte{})
	put(l, 2, 1, r1, 1, 6, [32]byte{0xee})
	m, _ = New(l, "s", k, Options{Log: quiet})
	if _, _, err := m.Claim(ctx, true); err == nil || !strings.Contains(err.Error(), "log_id") {
		t.Fatalf("another log_id: %v", err)
	}
	// An expired predecessor (retention over, deleted) is fine, and the
	// log_id comes from the record.
	l = &memLog{objs: map[string][][]byte{}}
	r1 = put(l, 1, 0, nil, 1, 5, [32]byte{})
	put(l, 2, 1, r1, 1, 6, Hash(r1))
	delete(l.objs, Name([32]byte{}, "s", 1))
	m, _ = New(l, "s", k, Options{Log: quiet})
	if got, _, err := m.Claim(ctx, true); err != nil || got != mark(6) || m.LogID() != Hash(r1) {
		t.Fatalf("expired predecessor: %+v %v", got, err)
	}
}

// Objects under future names that are not records cost the writer a skip
// each; it writes past them and readers ignore them.
func TestSquattedNamesSkipped(t *testing.T) {
	ctx := context.Background()
	name := func(v uint64) string { return Name([32]byte{}, "s", v) }
	l := &memLog{objs: map[string][][]byte{}}
	m, _ := New(l, "s", testKey(1), Options{Log: quiet})
	if _, _, err := m.Claim(ctx, false); err != nil {
		t.Fatal(err)
	}
	l.objs[name(2)] = [][]byte{[]byte("junk")}
	l.objs[name(3)] = [][]byte{[]byte("junk")}
	if err := m.Append(ctx, mark(10)); err != nil {
		t.Fatal(err)
	}
	if _, v := m.Mark(); v != 4 {
		t.Fatalf("wrote version %d, want 4", v)
	}
	m2, _ := New(l, "s", testKey(1), Options{Log: quiet})
	if got, _, err := m2.Claim(ctx, true); err != nil || got != mark(10) {
		t.Fatalf("read back: %+v %v", got, err)
	}
	for v := uint64(6); v < 6+maxSkips+2; v++ {
		l.objs[name(v)] = [][]byte{[]byte("junk")}
	}
	if err := m2.Append(ctx, mark(11)); err == nil {
		t.Fatal("wrote past more squatted names than allowed")
	}
}

// A body the newest record names but no copy of which reads back does not
// stop the claim; Body reports it, and the same update sent again restores
// it as a new copy.
func TestMissingBodyRestored(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	s := testSetup("s")
	l := &memLog{objs: map[string][][]byte{}}
	opt := Options{Setup: s, Clock: clockAt(&now), Log: quiet}
	m, _ := New(l, "s", testKey(1), opt)
	if _, _, err := m.Claim(ctx, false); err != nil {
		t.Fatal(err)
	}
	u := openUpdate(t, 2, 5)
	_, _, h, err := m.PutBody(ctx, u)
	if err != nil {
		t.Fatal(err)
	}
	st := m.State()
	st.Open = GroupState{Version: 2, Hash: h}
	if err := m.SetState(ctx, st); err != nil {
		t.Fatal(err)
	}
	delete(l.objs, BodyName(s.Hash, setupwire.GroupOpen, 2, 1))
	m2, _ := New(l, "s", testKey(1), opt)
	if _, _, err := m2.Claim(ctx, true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m2.Body(setupwire.GroupOpen, 2); !errors.Is(err, ErrBodyMissing) {
		t.Fatalf("missing body: %v", err)
	}
	if _, _, _, err := m2.PutBody(ctx, u); err != nil {
		t.Fatal(err)
	}
	if _, ok := l.objs[BodyName(s.Hash, setupwire.GroupOpen, 2, 2)]; !ok {
		t.Fatal("the update sent again was not written as copy 2")
	}
	if b, _, err := m2.Body(setupwire.GroupOpen, 2); err != nil || !bytes.Equal(b, u) {
		t.Fatalf("restored body: %v", err)
	}
	// Another update under a version the state names is refused.
	if _, _, _, err := m2.PutBody(ctx, openUpdate(t, 2, 6)); err == nil {
		t.Fatal("a second update under an active version")
	}
}

// Two updates stored before either state is written: writing the first
// state keeps the second body, so its state can follow (supersede).
func TestBodiesKeptUntilNamed(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	l := &memLog{objs: map[string][][]byte{}}
	m, _ := New(l, "s", testKey(1), Options{Setup: testSetup("s"), Clock: clockAt(&now), Log: quiet})
	if _, _, err := m.Claim(ctx, false); err != nil {
		t.Fatal(err)
	}
	_, _, h1, err := m.PutBody(ctx, openUpdate(t, 1, 1))
	if err != nil {
		t.Fatal(err)
	}
	_, _, h2, err := m.PutBody(ctx, openUpdate(t, 2, 2))
	if err != nil {
		t.Fatal(err)
	}
	st := m.State()
	st.Open.Pending = &Pending{Version: 1, Hash: h1, EffectiveAt: 1}
	if err := m.SetState(ctx, st); err != nil {
		t.Fatal(err)
	}
	st.Open.Pending = &Pending{Version: 2, Hash: h2, EffectiveAt: 2}
	if err := m.SetState(ctx, st); err != nil {
		t.Fatalf("the second update after the first was written: %v", err)
	}
	st.Open = GroupState{Version: 2, Hash: h2}
	if err := m.SetState(ctx, st); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Body(setupwire.GroupOpen, 1); !errors.Is(err, ErrBodyMissing) {
		t.Fatalf("a body below the active version is kept: %v", err)
	}
}
