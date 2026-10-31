//go:build !debugimport

package server

import (
	"strconv"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// The rule of the device source alarm, vote by vote.
func TestSourceWatchRule(t *testing.T) {
	var pk backend.Pubkey
	w := &sourceWatch{}
	steps := []struct {
		source, target uint64
		alarm          bool
	}{
		{10, 20, false}, // nothing for target 19 yet
		{10, 21, false}, // no finality: the source stays
		{11, 21, false}, // one epoch above the votes of target 20
		{12, 22, false}, // finality: one epoch per epoch
		{21, 23, true},  // nine epochs above the votes of target 22
		{20, 23, false}, // a lower jump than the alarm in force
		{25, 24, true},  // a higher source replaces the alarm
		{25, 24, false}, // the same vote again
		{20, 30, false}, // no votes for target 29
	}
	for i, s := range steps {
		got := w.note(pk, s.source, s.target)
		if (got != "") != s.alarm {
			t.Fatalf("step %d (source %d, target %d): alarm %q, want %v", i, s.source, s.target, got, s.alarm)
		}
	}
	if st := w.status(); !strings.Contains(st, "source 25 (target 24)") {
		t.Fatalf("alarm in force: %q", st)
	}
	// Old targets are dropped.
	if _, ok := w.highest[20]; ok || len(w.highest) > keepTargets+1 {
		t.Fatalf("kept targets: %v", w.highest)
	}
}

// One signing client's vote with a source above the chain's justified
// epoch pins the device source: after a restart every other key refuses
// its honest votes. The runner raises the alarm when the vote is signed,
// before any restart, and HEALTH shows it; ready stays true.
func TestDeviceSourceAlarmBeforeTheRestart(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	ask, apk := newKey(t)
	bsk, bpk := newKey(t)
	if err := e.importSealed(apk, ask, 5, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.importSealed(bpk, bsk, 6, nil); err != nil {
		t.Fatal(err)
	}
	e.clock.add(6 * testEpoch) // past the restart floor (margin 3)
	now := e.signer.EpochAt(e.now())
	// The chain does not finalize: every vote carries source j, the
	// lowest the source gate of a fresh log allows here.
	j := now - 3

	health := func() *backend.Health {
		t.Helper()
		h, err := e.srv.health()
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	for _, v := range []struct {
		pk     backend.Pubkey
		source uint64
		target uint64
	}{{apk, j, now - 1}, {bpk, j, now - 1}, {bpk, j, now}} {
		if err := e.signMsg(v.pk, vote(v.source, v.target)); err != nil {
			t.Fatalf("honest vote (%d, %d): %v", v.source, v.target, err)
		}
	}
	if h := health(); h.DeviceSourceAlarm != "" {
		t.Fatalf("alarm after honest votes: %q", h.DeviceSourceAlarm)
	}

	// Key A's client sends the shape of a vote under finality. The core
	// signs it and the device source becomes now-1.
	if err := e.signMsg(apk, vote(now-1, now)); err != nil {
		t.Fatal(err)
	}
	h := health()
	if !strings.Contains(h.DeviceSourceAlarm, "source "+itoa(now-1)) || !h.Ready {
		t.Fatalf("HEALTH after the pinning vote: ready %v, device_source_alarm %q", h.Ready, h.DeviceSourceAlarm)
	}
	if !strings.Contains(e.marks.Status(), "source="+itoa(now-1)) {
		t.Fatalf("the log's source did not move: %s", e.marks.Status())
	}
}

func itoa(v uint64) string { return strconv.FormatUint(v, 10) }
