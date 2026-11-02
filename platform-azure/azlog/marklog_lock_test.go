//go:build platform_azure

package azlog

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/platform/dev"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/slashing-log"
	"github.com/lidofinance/tee-signer/slashing-log/wormfake"
)

// versionFront sits before the Azure fake. It models version-level
// immutability at the data plane: Get of a name in junk returns a new
// current version the admin wrote over the locked one, while List still
// shows the name. armBlocked fails every management-plane read, as a host
// that blocks management.azure.com does.
type versionFront struct {
	*httptest.Server
	back       *wormfake.Server
	mu         sync.Mutex
	junk       map[string]bool
	armBlocked bool
}

func newVersionFront(t *testing.T) *versionFront {
	back := wormfake.New(wormfake.Azure, "marks")
	t.Cleanup(back.Close)
	u, err := url.Parse(back.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(u)
	f := &versionFront{back: back, junk: map[string]bool{}}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		blocked := f.armBlocked
		junk := r.Method == http.MethodGet && f.junk[strings.TrimPrefix(r.URL.Path, "/marks/")]
		f.mu.Unlock()
		switch {
		case blocked && strings.HasPrefix(r.URL.Path, "/subscriptions/"):
			http.Error(w, "dropped", http.StatusBadGateway)
		case junk:
			_, _ = w.Write([]byte("a new version over the locked one"))
		default:
			proxy.ServeHTTP(w, r)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *versionFront) set(fn func()) { f.mu.Lock(); fn(); f.mu.Unlock() }

// start runs the runner's start order on the setup path: CheckLock, New,
// Claim. between runs after the first lock check and before the claim.
// No hint store: where the sealed hint does not survive a restart.
func (f *versionFront) start(t *testing.T, between func()) (*markstore.MarkLog, backend.Watermark, error) {
	t.Helper()
	ctx := context.Background()
	tok := func(context.Context) (string, error) { return "tok", nil }
	l, err := Open("account=acct,container=marks,endpoint="+f.URL+",subscription=sub-1,resource_group=rg-1,arm_endpoint="+f.URL,
		markstore.Env{HTTP: f.Client(), Token: tok, ARMToken: tok})
	if err != nil {
		t.Fatal(err)
	}
	if err := markstore.CheckLock(ctx, l, 30); err != nil {
		return nil, backend.Watermark{}, err
	}
	setup := &markstore.Setup{Hash: [32]byte{0x5e, 1}, Signer: "signer-1", RetentionDays: 30,
		First: markstore.ConfigState{Locked: markstore.GroupState{Hash: [32]byte{0x10}}, Open: markstore.GroupState{Hash: [32]byte{0x20}}}}
	m, err := markstore.New(l, "signer-1", dev.NewDevKeys("image-1"), markstore.Options{AllowCreate: true, Setup: setup,
		Clock: func() (time.Time, error) { return time.Now(), nil }, LockDays: 30, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	between()
	w, _, err := m.Claim(ctx, true)
	return m, w, err
}

func epochMark(e uint64) backend.Watermark {
	return backend.Watermark{HasAttestation: true, SourceEpoch: e - 1, TargetEpoch: e, HasBlock: true, BlockSlot: e * 32}
}

// A migration to version-level immutability that completes after the
// start's lock check and before the claim reads the log lets the admin
// hide the newest records. The claim checks the lock again after the read
// and refuses, instead of starting from the older mark.
func TestAzureClaimRefusesVersionLevelAfterTheStartCheck(t *testing.T) {
	ctx := context.Background()
	f := newVersionFront(t)
	m1, _, err := f.start(t, func() {})
	if err != nil {
		t.Fatal(err)
	}
	if err := m1.Raise(ctx, epochMark(10)); err != nil {
		t.Fatal(err)
	}
	at10 := map[string]bool{}
	for _, n := range f.back.Names() {
		at10[n] = true
	}
	if err := m1.Raise(ctx, epochMark(20)); err != nil {
		t.Fatal(err)
	}
	var newer []string
	for _, n := range f.back.Names() {
		if !at10[n] {
			newer = append(newer, n)
		}
	}

	_, w, err := f.start(t, func() {
		f.back.SetLock(wormfake.Lock{Compliance: true, Days: 30, VersionLevel: true})
		f.set(func() {
			for _, n := range newer {
				f.junk[n] = true
			}
		})
	})
	if err == nil {
		t.Fatalf("claim took target %d after target 20 was written", w.TargetEpoch)
	}
	if !errors.Is(err, markstore.ErrNoLock) || !strings.Contains(err.Error(), "version-level") {
		t.Fatalf("claim: %v, want a version-level refusal", err)
	}
}

// A host that blocks the management plane makes the refresh's lock check
// fail without ErrNoLock. The log then writes nothing, so the runner signs
// nothing above its committed mark, until a check passes again.
func TestAzureBlockedLockCheckStopsWrites(t *testing.T) {
	ctx := context.Background()
	f := newVersionFront(t)
	m, _, err := f.start(t, func() {})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Raise(ctx, epochMark(10)); err != nil {
		t.Fatal(err)
	}
	f.set(func() { f.armBlocked = true })
	if err := m.Refresh(ctx); err == nil || errors.Is(err, markstore.ErrNoLock) {
		t.Fatalf("refresh with the management plane blocked: %v", err)
	}
	if err := m.Raise(ctx, epochMark(15)); !errors.Is(err, markstore.ErrLockUnchecked) {
		t.Fatalf("a write after the lock check could not reach the management plane: %v", err)
	}
	if got, _ := m.Mark(); got != epochMark(10) {
		t.Fatalf("mark %+v, want the one committed before the blocked check", got)
	}
	f.set(func() { f.armBlocked = false })
	if err := m.Refresh(ctx); err != nil {
		t.Fatalf("refresh with the management plane back: %v", err)
	}
	if err := m.Raise(ctx, epochMark(15)); err != nil {
		t.Fatalf("a write after the check passed again: %v", err)
	}
	f.back.SetLock(wormfake.Lock{Compliance: true, Days: 30, VersionLevel: true})
	if err := m.Refresh(ctx); !errors.Is(err, markstore.ErrNoLock) {
		t.Fatalf("refresh after the migration: %v", err)
	}
	if err := m.Raise(ctx, epochMark(16)); !errors.Is(err, markstore.ErrNoLock) {
		t.Fatalf("a write after the migration: %v", err)
	}
}
