package core

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// Every bare root but RANDAO reaches the runner without its object, so the
// runner signs them only with allow_unverified_nonslashable on (issue #5
// R11: selection proof, sync committee message and sync selection proof
// roots too).
func TestUnverifiedSwitch(t *testing.T) {
	roots := func(cfg Config) []*backend.RootMessage {
		return []*backend.RootMessage{
			{Type: backend.RootAggregateAndProof, Epoch: 20, ObjectRoot: backend.Root{9}, Domain: cfg.Domain(backend.DomainAggregateAndProof, 20)},
			{Type: backend.RootSyncCommitteeContributionAndProof, Epoch: 20, ObjectRoot: backend.Root{6}, Domain: cfg.Domain(backend.DomainContributionAndProof, 20)},
			{Type: backend.RootAggregationSlot, Epoch: 20, ObjectRoot: backend.HashTreeRootUint64(20 * 32), Domain: cfg.Domain(backend.DomainSelectionProof, 20)},
			{Type: backend.RootSyncCommitteeMessage, Epoch: 20, ObjectRoot: backend.Root{8}, Domain: cfg.Domain(backend.DomainSyncCommittee, 20)},
			{Type: backend.RootSyncCommitteeSelectionProof, Epoch: 20, ObjectRoot: backend.Root{7}, Domain: cfg.Domain(backend.DomainSyncCommitteeSelectionProof, 20)},
		}
	}
	checked := func(cfg Config) []*backend.RootMessage {
		return []*backend.RootMessage{
			{Type: backend.RootRandaoReveal, Epoch: 20, ObjectRoot: backend.HashTreeRootUint64(20), Domain: cfg.Domain(backend.DomainRandao, 20)},
		}
	}

	// Off (the default): every unverified root refused, RANDAO signs,
	// nothing counted.
	off, pk, cfg := newTestSigner(t, NewMemHooks())
	if cfg.AllowUnverifiedNonslashable {
		t.Fatal("DevConfig turns the switch on")
	}
	for _, m := range roots(cfg) {
		_, err := off.Sign(signReq(off, pk, m))
		wantStatus(t, err, backend.StatusPolicyDomain)
	}
	for _, m := range checked(cfg) {
		if _, err := off.Sign(signReq(off, pk, m)); err != nil {
			t.Fatalf("type %d with the switch off: %v", m.Type, err)
		}
	}
	if n := off.Stats().UnverifiedSignatures; n != 0 {
		t.Fatalf("unverified count %d with the switch off", n)
	}

	// On: they sign and verify, and each one is counted. The domain check
	// and the clock horizon still apply.
	cfg.AllowUnverifiedNonslashable = true
	on, pk, cfg := newTestSignerWith(t, NewMemHooks(), cfg)
	for _, m := range roots(cfg) {
		sig, err := on.Sign(signReq(on, pk, m))
		if err != nil {
			t.Fatalf("type %d with the switch on: %v", m.Type, err)
		}
		root, _ := cfg.SigningRoot(m)
		if !Verify(pk, root, sig) {
			t.Fatalf("type %d: signature does not verify", m.Type)
		}
	}
	if n := on.Stats().UnverifiedSignatures; n != 5 {
		t.Fatalf("unverified count %d, want 5", n)
	}
	sign := func(m backend.Message) error {
		_, err := on.Sign(signReq(on, pk, m))
		return err
	}
	wantStatus(t, sign(&backend.RootMessage{Type: backend.RootAggregateAndProof, Epoch: 20, Domain: cfg.Domain(backend.DomainAggregateAndProof, 5)}), backend.StatusDomainMismatch)
	wantStatus(t, sign(&backend.RootMessage{Type: backend.RootSyncCommitteeContributionAndProof, Epoch: 30, Domain: cfg.Domain(backend.DomainContributionAndProof, 30)}), backend.StatusPolicyFuture)
	// No root type outside the nine exists, switch or not: exits,
	// registrations, blocks and attestations only come typed. The Gloas
	// types 7 to 9 are in TestGloasUnverifiedRoots.
	for _, typ := range []backend.RootType{0, 10, 99, 255} {
		wantStatus(t, sign(&backend.RootMessage{Type: typ, Epoch: 20}), backend.StatusUnsupported)
	}
	if n := on.Stats().UnverifiedSignatures; n != 5 {
		t.Fatalf("refusals counted: %d", n)
	}
}

// A config file without the field loads with the switch off; with it, on.
func TestUnverifiedSwitchConfigFile(t *testing.T) {
	raw, err := json.Marshal(DevConfig(genesis, 12, 32))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	delete(m, "allow_unverified_nonslashable")
	old, _ := json.Marshal(m)
	if bytes.Contains(old, []byte("allow_unverified")) {
		t.Fatal("field still in the old-style file")
	}
	dir := t.TempDir()
	load := func(b []byte) Config {
		p := filepath.Join(dir, "chain.json")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		c, _, err := LoadConfig(p)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	if load(old).AllowUnverifiedNonslashable {
		t.Fatal("a config without the field turned the switch on")
	}
	m["allow_unverified_nonslashable"] = true
	on, _ := json.Marshal(m)
	if !load(on).AllowUnverifiedNonslashable {
		t.Fatal("the field did not turn the switch on")
	}
}
