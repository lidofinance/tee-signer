//go:build !debugimport

package server

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/slashing-log"
)

// A mark log whose store is no longer locked at a refresh stops writing,
// and HEALTH says so: ready false and mark_log_lost names the lock.
func TestHealthSaysTheMarkLogStoppedOnALostLock(t *testing.T) {
	a := newVariantEnv(t, "dev", nil)
	a.lockDays = 1
	a.restart()
	h, err := a.srv.health()
	if err != nil {
		t.Fatal(err)
	}
	if !h.Ready || h.MarkLogLost != "" {
		t.Fatalf("HEALTH before the refresh: ready %v, mark_log_lost %q", h.Ready, h.MarkLogLost)
	}
	a.lockGone = true
	if err := a.marks.Refresh(ctx); !errors.Is(err, markstore.ErrNoLock) {
		t.Fatalf("refresh on an unlocked store: %v, want ErrNoLock", err)
	}
	if h, err = a.srv.health(); err != nil {
		t.Fatal(err)
	}
	if h.Ready || !strings.HasPrefix(h.MarkLogLost, "mark log stopped: store lock lost") {
		t.Errorf("HEALTH after the refresh: ready %v, mark_log_lost %q", h.Ready, h.MarkLogLost)
	}
}

// A refresh that cannot read the store's lock stops the log's writes
// until a check passes, and HEALTH says so: ready false and mark_log_lost
// names the unchecked lock. Once a check passes, HEALTH is ready again.
func TestHealthSaysTheMarkLogLockIsUnchecked(t *testing.T) {
	a := newVariantEnv(t, "dev", nil)
	a.lockDays = 1
	a.restart()
	a.lockErr = errors.New("management plane blocked")
	if err := a.marks.Refresh(ctx); !errors.Is(err, markstore.ErrLockUnchecked) {
		t.Fatalf("refresh with the lock read failing: %v, want ErrLockUnchecked", err)
	}
	h, err := a.srv.health()
	if err != nil {
		t.Fatal(err)
	}
	if h.Ready || !strings.HasPrefix(h.MarkLogLost, "mark log paused: store lock unchecked") {
		t.Errorf("HEALTH with the lock unchecked: ready %v, mark_log_lost %q", h.Ready, h.MarkLogLost)
	}
	a.lockErr = nil
	if err := a.marks.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if h, err = a.srv.health(); err != nil {
		t.Fatal(err)
	}
	if !h.Ready || h.MarkLogLost != "" {
		t.Errorf("HEALTH after a check passed: ready %v, mark_log_lost %q", h.Ready, h.MarkLogLost)
	}
}

// HEALTH reports when the mark log's last record was written, and once no
// record landed for half the retention (rv-ic0.1), ready false and
// mark_log_lost naming the gap.
func TestHealthSaysTheMarkLogIsStale(t *testing.T) {
	a := newTgtEnv(t, "dev", nil)
	h, err := a.srv.health()
	if err != nil {
		t.Fatal(err)
	}
	if !h.Ready || h.MarkLogLost != "" || h.MarkLogWrittenUnix == 0 || h.MarkLogWrittenUnix > h.ClockUnix {
		t.Fatalf("HEALTH before the gap: ready %v, mark_log_lost %q, written %d, clock %d", h.Ready, h.MarkLogLost, h.MarkLogWrittenUnix, h.ClockUnix)
	}
	written := h.MarkLogWrittenUnix
	half := time.Duration(a.setup.SlashingLogMinLockDays) * 24 * time.Hour / 2
	a.clock.mu.Lock()
	a.clock.t = a.clock.t.Add(half + time.Hour)
	a.clock.mu.Unlock()
	if err := a.marks.Refresh(ctx); !errors.Is(err, markstore.ErrStale) {
		t.Fatalf("refresh past half the retention: %v, want ErrStale", err)
	}
	if h, err = a.srv.health(); err != nil {
		t.Fatal(err)
	}
	if h.Ready || !strings.HasPrefix(h.MarkLogLost, "mark log stopped: no record for half the retention") || h.MarkLogWrittenUnix != written {
		t.Errorf("HEALTH after the gap: ready %v, mark_log_lost %q, written %d (was %d)", h.Ready, h.MarkLogLost, h.MarkLogWrittenUnix, written)
	}
}

// HEALTH carries key_lock_why (S2, T-124) and mark_log_lost (S1,
// RBRLOG-03) side by side: a runner with a setup whose key rule is not
// locked, after a clone took its mark log over.
func TestHealthCarriesKeyLockWhyAndMarkLogLost(t *testing.T) {
	a := newVariantEnv(t, "dev", nil)
	why := "release_policy.immutable is false: the key's owner can change the release policy"
	a.srv.KeyLock, a.srv.KeyLockWhy = backend.KeyLockNotLocked, why
	sk, pk := newKey(t)
	if err := a.importSealed(pk, sk, 5, nil); err != nil {
		t.Fatal(err)
	}

	b := *a
	b.start()
	if err := a.signer.CoverEpoch(a.signer.EpochAt(a.now()) + 10); err == nil {
		t.Fatal("A's cover write went through after the clone's claim")
	}
	h, err := a.srv.health()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got["key_lock"] != "not_locked" || got["key_lock_why"] != why {
		t.Errorf("HEALTH key_lock %v, key_lock_why %v", got["key_lock"], got["key_lock_why"])
	}
	if s, _ := got["mark_log_lost"].(string); s == "" || got["ready"] != false {
		t.Errorf("HEALTH mark_log_lost %q, ready %v", s, got["ready"])
	}
}
