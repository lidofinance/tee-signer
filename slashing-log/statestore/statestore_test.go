package statestore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/dev"
	"github.com/lidofinance/tee-signer/platform/filestore"
	"github.com/lidofinance/tee-signer/slashing-log"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func keysOf(image string) platform.Keys { return dev.NewDevKeys(image) }

func newLocal(t *testing.T) *filestore.Store {
	t.Helper()
	s, err := filestore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// setupA is the setup of the tests' signer.
var setupA = [32]byte{0x5e, 0xa}

func open(t *testing.T, local platform.Store, l markstore.Log, keys platform.Keys, opt Options) (*Store, error) {
	t.Helper()
	if opt.SetupHash == ([32]byte{}) {
		opt.SetupHash = setupA
	}
	if opt.Log == nil {
		opt.Log = quiet
	}
	return Open(context.Background(), local, l, "signer-1", keys, opt)
}

func mustGet(t *testing.T, s platform.Store, k string) []byte {
	t.Helper()
	v, err := s.Get(k)
	if err != nil {
		t.Fatalf("%s: %v", k, err)
	}
	return v
}

// A runner writes its sealing key and a share; its local state is lost; a
// new process of the same image restores both before anything reads them.
// Keys outside the copy (the mark hint, an older build's repeat roots) stay
// local.
func TestRestoreAfterLostState(t *testing.T) {
	l, _ := markstore.NewFileLog(t.TempDir())
	local := newLocal(t)
	s, err := open(t, local, l, keysOf("image-a"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{"sealing/dek.azure-rsa": "wrapped dek", "shares/aa": "sealed share", "rr/aa": "roots", "mark-hint/signer-1": "hint"} {
		if err := s.Put(k, []byte(v)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Put("shares/aa", []byte("sealed share")); err != nil {
		t.Fatal(err)
	}
	ents, _ := l.List(context.Background(), Prefix(setupA, "signer-1"))
	if len(ents) != 2 {
		t.Fatalf("%d snapshots, want 2 (one per change of a durable key, none for the same value)", len(ents))
	}

	fresh := newLocal(t)
	s2, err := open(t, fresh, l, keysOf("image-a"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if string(mustGet(t, fresh, "shares/aa")) != "sealed share" || string(mustGet(t, fresh, "sealing/dek.azure-rsa")) != "wrapped dek" {
		t.Fatal("restore did not write the durable keys")
	}
	if _, err := fresh.Get("rr/aa"); !errors.Is(err, platform.ErrNotFound) {
		t.Fatal("repeat roots came back from the copy")
	}
	if err := s2.Put("shares/bb", []byte("second share")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s2.Status(), "version=3") {
		t.Fatalf("status %q, want version 3", s2.Status())
	}
}

// Another key release (another image, another Key Vault key version) opens
// none of the snapshots: the start stops, unless AllowCreate.
func TestOtherKeyReleaseRefused(t *testing.T) {
	l, _ := markstore.NewFileLog(t.TempDir())
	s, _ := open(t, newLocal(t), l, keysOf("image-a"), Options{})
	if err := s.Put("shares/aa", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := open(t, newLocal(t), l, keysOf("image-b"), Options{}); err == nil || !strings.Contains(err.Error(), "none opens") {
		t.Fatalf("another key release: %v", err)
	}
	s2, err := open(t, newLocal(t), l, keysOf("image-b"), Options{AllowCreate: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.Put("shares/cc", []byte("y")); err != nil {
		t.Fatal(err)
	}
	// image-b writes above the version image-a used; image-a still reads
	// its own snapshot (the newest that opens for it).
	fresh := newLocal(t)
	if _, err := open(t, fresh, l, keysOf("image-a"), Options{}); err != nil {
		t.Fatal(err)
	}
	if string(mustGet(t, fresh, "shares/aa")) != "x" {
		t.Fatal("image-a lost its snapshot")
	}
}

// Changed or foreign objects: a flipped byte, a snapshot copied under
// another version name or another signer's prefix do not open; a forged
// object at a future name costs a skip.
func TestTamperedSnapshots(t *testing.T) {
	dir := t.TempDir()
	l, _ := markstore.NewFileLog(dir)
	s, _ := open(t, newLocal(t), l, keysOf("image-a"), Options{})
	s.Put("shares/aa", []byte("v1"))
	s.Put("shares/aa", []byte("v2"))
	p2 := filepath.Join(dir, filepath.FromSlash(Name(setupA, "signer-1", 2)))
	b, _ := os.ReadFile(p2)

	// The newest snapshot changed by the store's admin.
	flipped := append([]byte(nil), b...)
	flipped[len(flipped)-1] ^= 1
	os.Chmod(p2, 0o600)
	os.WriteFile(p2, flipped, 0o600)
	fresh := newLocal(t)
	if _, err := open(t, fresh, l, keysOf("image-a"), Options{}); err != nil {
		t.Fatal(err)
	}
	// A changed object does not open: the copy falls back to version 1,
	// the newest that does (a rollback, see docs/durable-state.md).
	if string(mustGet(t, fresh, "shares/aa")) != "v1" {
		t.Fatalf("restored %q", mustGet(t, fresh, "shares/aa"))
	}
	os.WriteFile(p2, b, 0o600)

	// Version 2's bytes under name 3: the version inside differs.
	if err := l.Create(context.Background(), Name(setupA, "signer-1", 3), b); err != nil {
		t.Fatal(err)
	}
	// And under another signer's name.
	if err := l.Create(context.Background(), Name(setupA, "signer-2", 2), b); err != nil {
		t.Fatal(err)
	}
	fresh = newLocal(t)
	s3, err := open(t, fresh, l, keysOf("image-a"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if string(mustGet(t, fresh, "shares/aa")) != "v2" {
		t.Fatal("copy under a new name was taken")
	}
	if _, err := Open(context.Background(), newLocal(t), l, "signer-2", keysOf("image-a"), Options{SetupHash: setupA, Log: quiet}); err == nil {
		t.Fatal("signer-2 opened signer-1's snapshot")
	}
	// The next write skips name 3.
	if err := s3.Put("shares/aa", []byte("v3")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s3.Status(), "version=4") {
		t.Fatalf("status %q", s3.Status())
	}
}

// A local durable key that the newest snapshot lacks: the copy lost
// snapshots or the local state is another's. The start stops.
func TestLocalKeyMissingFromCopy(t *testing.T) {
	l, _ := markstore.NewFileLog(t.TempDir())
	local := newLocal(t)
	s, _ := open(t, local, l, keysOf("image-a"), Options{})
	s.Put("shares/aa", []byte("x"))
	local.Put("shares/zz", []byte("planted"))
	if _, err := open(t, local, l, keysOf("image-a"), Options{}); err == nil || !strings.Contains(err.Error(), "shares/zz") {
		t.Fatalf("got %v", err)
	}
}

// A runner that ran before the copy existed: its local state becomes the
// first snapshot.
func TestFirstSnapshotOfLocalState(t *testing.T) {
	l, _ := markstore.NewFileLog(t.TempDir())
	local := newLocal(t)
	local.Put("sealing/dek.gcpkms", []byte("wrapped"))
	local.Put("handover/key", []byte("sealed operator key"))
	if _, err := open(t, local, l, keysOf("image-a"), Options{}); err != nil {
		t.Fatal(err)
	}
	fresh := newLocal(t)
	if _, err := open(t, fresh, l, keysOf("image-a"), Options{}); err != nil {
		t.Fatal(err)
	}
	if string(mustGet(t, fresh, "handover/key")) != "sealed operator key" {
		t.Fatal("operator key not in the first snapshot")
	}
}

// Two processes of one signer (a clone): the second write at a version
// the other took makes the loser change nothing more, and its local store
// keeps the old value.
func TestCloneLoses(t *testing.T) {
	l, _ := markstore.NewFileLog(t.TempDir())
	la, lb := newLocal(t), newLocal(t)
	a, _ := open(t, la, l, keysOf("image-a"), Options{})
	a.Put("shares/aa", []byte("x"))
	b, err := open(t, lb, l, keysOf("image-a"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Put("shares/bb", []byte("b's")); err != nil {
		t.Fatal(err)
	}
	if err := a.Put("shares/cc", []byte("a's")); !errors.Is(err, ErrLost) {
		t.Fatalf("clone write: %v", err)
	}
	if _, err := la.Get("shares/cc"); !errors.Is(err, platform.ErrNotFound) {
		t.Fatal("a failed snapshot still wrote the local store")
	}
}

// The key release down at start is an error, not "nothing to restore".
type downKeys struct{ platform.Keys }

func (downKeys) OpenKey(context.Context, []byte, []byte) ([]byte, error) {
	return nil, errors.New("key service unreachable")
}

func TestKeyReleaseDownStops(t *testing.T) {
	l, _ := markstore.NewFileLog(t.TempDir())
	s, _ := open(t, newLocal(t), l, keysOf("image-a"), Options{})
	s.Put("shares/aa", []byte("x"))
	if _, err := open(t, newLocal(t), l, downKeys{keysOf("image-a")}, Options{}); err == nil || !strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("got %v", err)
	}
}

// Too large a value is refused at the write, not found unreadable at the
// next start.
func TestEntryLimit(t *testing.T) {
	l, _ := markstore.NewFileLog(t.TempDir())
	local := newLocal(t)
	s, _ := open(t, local, l, keysOf("image-a"), Options{})
	if err := s.Put("shares/big", bytes.Repeat([]byte{1}, MaxEntry+1)); err == nil {
		t.Fatal("accepted a value over the limit")
	}
	if _, err := local.Get("shares/big"); !errors.Is(err, platform.ErrNotFound) {
		t.Fatal("the local store took the refused value")
	}
}

// Refresh writes a new commit once the newest is old enough.
func TestRefresh(t *testing.T) {
	l, _ := markstore.NewFileLog(t.TempDir())
	now := time.Unix(1_800_000_000, 0)
	s, _ := open(t, newLocal(t), l, keysOf("image-a"), Options{Now: func() time.Time { return now }})
	s.Put("shares/aa", []byte("x"))
	if err := s.Refresh(context.Background(), time.Hour); err != nil || !strings.Contains(s.Status(), "version=1") {
		t.Fatalf("early refresh: %v %s", err, s.Status())
	}
	now = now.Add(2 * time.Hour)
	if err := s.Refresh(context.Background(), time.Hour); err != nil || !strings.Contains(s.Status(), "version=2") {
		t.Fatalf("refresh: %v %s", err, s.Status())
	}
}

// The copy lives under its setup's name and its AAD binds the setup: a new
// setup with the same signer name starts with an empty copy, and a
// snapshot of another setup copied under its names does not open. The flag
// path without a setup keeps the names state/<signer>/.
func TestSetupBindsTheCopy(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	l, _ := markstore.NewFileLog(dir)
	s, _ := open(t, newLocal(t), l, keysOf("image-a"), Options{})
	if err := s.Put("shares/aa", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(Name(setupA, "signer-1", 1), "state/5e0a") {
		t.Fatalf("name %s", Name(setupA, "signer-1", 1))
	}
	setupB := [32]byte{0x5e, 0xb}
	fresh := newLocal(t)
	if _, err := open(t, fresh, l, keysOf("image-a"), Options{SetupHash: setupB}); err != nil {
		t.Fatalf("a new setup with the same signer name: %v", err)
	}
	if _, err := fresh.Get("shares/aa"); !errors.Is(err, platform.ErrNotFound) {
		t.Fatal("a new setup restored another setup's share")
	}
	b, _ := os.ReadFile(filepath.Join(dir, filepath.FromSlash(Name(setupA, "signer-1", 1))))
	if err := l.Create(ctx, Name(setupB, "signer-1", 1), b); err != nil {
		t.Fatal(err)
	}
	if _, err := open(t, newLocal(t), l, keysOf("image-a"), Options{SetupHash: setupB}); err == nil || !strings.Contains(err.Error(), "none opens") {
		t.Fatalf("another setup's snapshot under this setup's name: %v", err)
	}
	flag, err := Open(ctx, newLocal(t), l, "signer-1", keysOf("image-a"), Options{Log: quiet})
	if err != nil {
		t.Fatal(err)
	}
	if err := flag.Put("shares/aa", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "state", "signer-1", "00000000000000000001")); err != nil {
		t.Fatalf("flag path name: %v", err)
	}
}
