//go:build (peer_azure || peer_aws || peer_gcp || peer_dev) && !debugimport

package server

import (
	"encoding/json"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// HEALTH carries key_lock_why (S2, T-124) and mark_log_lost (S1,
// RBRLOG-03) side by side: a runner with a setup whose key rule is not
// locked, after a clone took its mark log over.
func TestHealthCarriesKeyLockWhyAndMarkLogLost(t *testing.T) {
	a := newTgtEnv(t, "dev", nil)
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
