package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/setup"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/slashing-log"
	"github.com/lidofinance/tee-signer/tee-signer/server"
)

// keyRuleEnv is the sample nitro setup, which lists one nitro image (PCR0
// 0x11 repeated), with a read-only mark log in its first state after
// change, and a nitro platform whose own image is the listed one. The
// config in force is read as main.go does before the share checks.
func keyRuleEnv(t *testing.T, change func(*markstore.ConfigState)) (*server.Updates, *platform.Platform) {
	t.Helper()
	st, err := setup.Load(testdata(t, "setup-nitro.bin"), "nitro")
	if err != nil {
		t.Fatal(err)
	}
	ms, err := markstore.SetupOf(st.Wire, st.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	state := ms.First
	if change != nil {
		change(&state)
	}
	updates, err := newConfigUpdates(st, &fakeLog{state: state}, fixedClock{time.Unix(1_790_000_000, 0)}, "nitro", quietLog)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := chainConfig(st.Wire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := updates.StartConfig(cfg); err != nil {
		t.Fatal(err)
	}
	self := st.Wire.Locked.AllowedImageMeasurements[0]
	if self.Kind != setupwire.ImageNitro || !bytes.Equal(platform.RuleImageID(self), bytes.Repeat([]byte{0x11}, 48)) {
		t.Fatalf("the sample setup lists %v", self)
	}
	plat := &platform.Platform{Name: "nitro", SelfImage: func(context.Context) (setupwire.Image, error) { return self, nil }}
	return updates, plat
}

func lockedRule(ids ...[]byte) platform.KeyRule {
	return platform.KeyRule{Hash: [32]byte{1}, Lock: backend.KeyLockLocked, Images: ids}
}

// wantNotReady is the refusal every signing request gets from the gate.
func wantNotReady(t *testing.T, err error) {
	t.Helper()
	var r *backend.RefusedError
	if !errors.As(err, &r) || r.Code != backend.StatusNotReady || !strings.Contains(err.Error(), "image check:") {
		t.Fatalf("SIGN check: %v, want NOT_READY from the image check", err)
	}
}

// The image rule of the key rule lock at start: on a prod chain a locked
// key rule that releases the sealing key to an image
// allowed_image_measurements in force does not name leaves the shares
// sealed, as the image check does, and HEALTH says key_rule_unlisted. A
// rule whose images are all listed loads, and so does a platform that
// reports no image set. Off prod the rule only warns.
func TestKeyRuleImagesAtStart(t *testing.T) {
	updates, plat := keyRuleEnv(t, nil)
	listed, other := bytes.Repeat([]byte{0x11}, 48), bytes.Repeat([]byte{0x22}, 48)
	for _, c := range []struct {
		name  string
		prod  bool
		rule  platform.KeyRule
		load  bool
		state string
		why   string
	}{
		{"prod, listed", true, lockedRule(listed), true, backend.ImageAllowed, ""},
		{"prod, unlisted", true, lockedRule(other), false, backend.ImageKeyRuleUnlisted, "releases the sealing key to 1 image(s)"},
		{"prod, listed and unlisted", true, lockedRule(listed, other), false, backend.ImageKeyRuleUnlisted, "does not name (PCR0 " + strings.Repeat("22", 48) + ")"},
		{"prod, no image set", true, platform.KeyRule{Hash: [32]byte{1}, Lock: backend.KeyLockLocked}, true, backend.ImageAllowed, ""},
		{"testnet, unlisted", false, lockedRule(other), true, backend.ImageAllowed, ""},
		{"testnet, listed", false, lockedRule(listed), true, backend.ImageAllowed, ""},
	} {
		g, load, err := startImageCheck(context.Background(), plat, c.prod, c.rule, updates, quietLog)
		if err != nil {
			t.Errorf("%s: the start returns an error: %v", c.name, err)
			continue
		}
		st, refused := g.Status(updates)
		if load != c.load || st.State != c.state || refused == c.load || !strings.Contains(st.Why, c.why) {
			t.Errorf("%s: load %v, HEALTH image %+v; want load %v, state %s, why with %q", c.name, load, st, c.load, c.state, c.why)
		}
	}
	// Without the list in force (no mark log) a prod chain withholds the
	// shares, a test network loads them.
	g, load, err := startImageCheck(context.Background(), plat, true, lockedRule(listed), nil, quietLog)
	if err != nil {
		t.Fatalf("prod without updates: the start returns an error: %v", err)
	}
	if st, _ := g.Status(nil); load || st.State != backend.ImageUnknown {
		t.Fatalf("prod without updates: load %v, HEALTH image %+v", load, st)
	}
	g, load, err = startImageCheck(context.Background(), plat, false, lockedRule(other), nil, quietLog)
	if err != nil {
		t.Fatalf("testnet without updates: %v", err)
	}
	if st, _ := g.Status(nil); !load || st.State != backend.ImageNotApplicable {
		t.Fatalf("testnet without updates: load %v, HEALTH image %+v", load, st)
	}
}

// A prod chain whose key rule names an image the list in force does not:
// the runner does not exit. It loads no share, HEALTH says why (the PCR0
// values the list lacks, not the listed ones), and the check every
// signing request runs refuses with NOT_READY. CONFIG_UPDATE is served in
// that state (server.TestKeyRuleImagesWithheldServesStatusAndConfig), so
// a locked update that lists the image can reach this runner.
func TestKeyRuleImagesWithholdShares(t *testing.T) {
	updates, plat := keyRuleEnv(t, nil)
	listed, other := bytes.Repeat([]byte{0x11}, 48), bytes.Repeat([]byte{0x22}, 48)
	g, load, err := startImageCheck(context.Background(), plat, true, lockedRule(listed, other), updates, quietLog)
	if err != nil {
		t.Fatalf("the start returns an error: %v", err)
	}
	if load {
		t.Fatal("the shares load under a key rule that releases the sealing key to an unlisted image")
	}
	st, refused := g.Status(updates)
	if !refused || st.State != backend.ImageKeyRuleUnlisted || st.LockedVersion != 0 || !strings.Contains(st.Why, hex.EncodeToString(other)) || strings.Contains(st.Why, hex.EncodeToString(listed)) {
		t.Fatalf("HEALTH image %+v, refused %v", st, refused)
	}
	wantNotReady(t, g.Check(updates))
}

// A locked body the log names but the store cannot give ("send the update
// again" in config.go): on a prod chain the start used to stop, since the
// key rule's images could not be compared. Now it withholds the shares as
// the image check does when the list in force is unknown, and the runner
// stays up to take the body again.
func TestKeyRuleImagesMissingBodyWithholds(t *testing.T) {
	updates, plat := keyRuleEnv(t, func(s *markstore.ConfigState) {
		s.Locked = markstore.GroupState{Version: 1, Hash: [32]byte{9}} // body never stored, or gone
	})
	listed := bytes.Repeat([]byte{0x11}, 48)
	for _, prod := range []bool{true, false} {
		g, load, err := startImageCheck(context.Background(), plat, prod, lockedRule(listed), updates, quietLog)
		if err != nil {
			t.Fatalf("prod %v: the start returns an error: %v", prod, err)
		}
		st, refused := g.Status(updates)
		if load || !refused || st.State != backend.ImageUnknown || !strings.Contains(st.Why, "the allowed list in force is unknown") {
			t.Fatalf("prod %v: load %v, HEALTH image %+v", prod, load, st)
		}
		wantNotReady(t, g.Check(updates))
	}
}
