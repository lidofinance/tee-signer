package setupwire

import (
	"bytes"
	"math"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

const maxU = math.MaxUint64

func TestSatAdd(t *testing.T) {
	for _, c := range []struct{ a, b, want uint64 }{
		{1, 2, 3}, {maxU, 0, maxU}, {maxU, 1, maxU}, {maxU - 1, 1, maxU}, {maxU, maxU, maxU}, {1 << 63, 1 << 63, maxU},
	} {
		if got := SatAdd(c.a, c.b); got != c.want {
			t.Errorf("%d + %d = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCheckVersion(t *testing.T) {
	for _, c := range []struct {
		v, active, pending uint64
		ok                 bool
	}{
		{1, 0, 0, true},
		{0, 0, 0, false},
		{5, 5, 0, false},
		{6, 5, 0, true},
		{6, 5, 6, false}, // must pass the pending one too
		{7, 5, 6, true},
		{5, 7, 0, false},
		{1 << 32, 0, 0, true},
		{1<<32 + 1, 0, 0, false},
		{10 + 1<<32, 3, 10, true},
		{11 + 1<<32, 3, 10, false},
		{maxU, maxU - 1<<32, 0, true},
		{maxU, maxU, 0, false},
	} {
		if err := CheckVersion(c.v, c.active, c.pending); (err == nil) != c.ok {
			t.Errorf("version %d over active %d, pending %d: got %v, want ok=%v", c.v, c.active, c.pending, err, c.ok)
		}
	}
}

func TestWait(t *testing.T) {
	active := sampleLocked() // time lock 0
	newImage := Image{Kind: ImageTA, Measurement: bytes.Repeat([]byte{7}, 32)}
	gains := sampleLocked()
	gains.AllowedImageMeasurements = append(gains.AllowedImageMeasurements, newImage)
	drops := sampleLocked()
	drops.AllowedImageMeasurements = drops.AllowedImageMeasurements[:1]
	same := sampleLocked()
	open := sampleOpen()
	nonProd := sampleChain().GenesisForkVersion
	cases := []struct {
		name     string
		chain    backend.Version
		timeLock *uint64
		body     UpdateBody
		want     uint64
	}{
		{"open", nonProd, u64p(5 * 86400), UpdateBody{Group: GroupOpen, Open: &open}, 0},
		{"locked, time lock 0", nonProd, u64p(0), UpdateBody{Group: GroupLocked, Locked: &same}, 0},
		{"locked, default", nonProd, nil, UpdateBody{Group: GroupLocked, Locked: &same}, DefaultTimeLock},
		{"new image, time lock 0", nonProd, u64p(0), UpdateBody{Group: GroupLocked, Locked: &gains}, ImagesMinTimeLock},
		{"new image, default", nonProd, nil, UpdateBody{Group: GroupLocked, Locked: &gains}, ImagesMinTimeLock},
		{"new image, longer time lock", nonProd, u64p(10 * 86400), UpdateBody{Group: GroupLocked, Locked: &gains}, 10 * 86400},
		{"image removed", nonProd, u64p(3600), UpdateBody{Group: GroupLocked, Locked: &drops}, 3600},
		// A prod chain never waits less than the floor, whatever the
		// stored value says.
		{"prod, open", MainnetForkVersion, u64p(0), UpdateBody{Group: GroupOpen, Open: &open}, 0},
		{"prod, time lock 0", MainnetForkVersion, u64p(0), UpdateBody{Group: GroupLocked, Locked: &same}, DefaultTimeLock},
		{"prod, time lock 1", MainnetForkVersion, u64p(1), UpdateBody{Group: GroupLocked, Locked: &same}, DefaultTimeLock},
		{"prod, default", MainnetForkVersion, nil, UpdateBody{Group: GroupLocked, Locked: &same}, DefaultTimeLock},
		{"prod, longer", MainnetForkVersion, u64p(DefaultTimeLock + 1), UpdateBody{Group: GroupLocked, Locked: &same}, DefaultTimeLock + 1},
		{"prod, new image, time lock 0", MainnetForkVersion, u64p(0), UpdateBody{Group: GroupLocked, Locked: &gains}, max(DefaultTimeLock, ImagesMinTimeLock)},
		{"unknown chain, time lock 0", backend.Version{0xde, 0xad, 0xbe, 0xef}, u64p(0), UpdateBody{Group: GroupLocked, Locked: &same}, DefaultTimeLock},
	}
	for _, c := range cases {
		a := active
		a.ChangeDelaySeconds = c.timeLock
		if got := Wait(c.chain, &a, &c.body); got != c.want {
			t.Errorf("%s: wait %d, want %d", c.name, got, c.want)
		}
	}
	if !GainsImage(nil, gains.AllowedImageMeasurements) || GainsImage(gains.AllowedImageMeasurements, active.AllowedImageMeasurements) || GainsImage(active.AllowedImageMeasurements, active.AllowedImageMeasurements) {
		t.Fatal("GainsImage")
	}
}

// CheckChangeDelay, the check of a new value, refuses a change delay below
// the floor on a prod chain, the build's default; a non-prod chain takes
// 0. The value rules of a setup (CheckValues) and the match of an update
// to its setup (Matches) carry no floor: they run on stored values too,
// which ChangeDelayOn raises instead.
func TestProdChangeDelayFloor(t *testing.T) {
	if MinChangeDelay(MainnetForkVersion) != DefaultTimeLock || MinChangeDelay(sampleChain().GenesisForkVersion) != 0 {
		t.Fatal("MinChangeDelay")
	}
	for _, c := range []struct {
		name  string
		chain backend.Version
		delay *uint64
		ok    bool
	}{
		{"prod, 0", MainnetForkVersion, u64p(0), false},
		{"prod, under the floor", MainnetForkVersion, u64p(DefaultTimeLock - 1), false},
		{"prod, the floor", MainnetForkVersion, u64p(DefaultTimeLock), true},
		{"prod, absent", MainnetForkVersion, nil, true},
		{"unknown chain, 0", backend.Version{0xde, 0xad, 0xbe, 0xef}, u64p(0), false},
		{"non-prod, 0", sampleChain().GenesisForkVersion, u64p(0), true},
	} {
		s := samples(t)["setup-azure"]
		s.Chain.GenesisForkVersion = c.chain
		s.Locked.ChangeDelaySeconds = c.delay
		err := s.Locked.CheckChangeDelay(c.chain)
		if (err == nil) != c.ok {
			t.Errorf("%s: CheckChangeDelay %v, want ok %v", c.name, err, c.ok)
		}
		if err != nil && !strings.Contains(err.Error(), "locked: change_delay_seconds") {
			t.Errorf("%s: %v does not name change_delay_seconds", c.name, err)
		}
		if w := s.Locked.ChangeDelayOn(c.chain); w < MinChangeDelay(c.chain) || (c.ok && w != s.Locked.ChangeDelay()) {
			t.Errorf("%s: ChangeDelayOn %d, floor %d, stored %d", c.name, w, MinChangeDelay(c.chain), s.Locked.ChangeDelay())
		}
		if err := s.CheckValues(); err != nil {
			t.Errorf("setup %s: CheckValues %v, want the value rules without the floor", c.name, err)
		}
		// The same values in an update to a setup of the chain.
		s.Locked.ChangeDelaySeconds = nil
		b := lockedBody(s)
		b.ClusterID, b.ChainHash = s.ClusterID, s.Chain.Hash()
		b.Locked.ChangeDelaySeconds = c.delay
		if err := b.Matches(s); err != nil {
			t.Errorf("update %s: Matches %v, want the match without the floor", c.name, err)
		}
	}
}

// A setup of a prod chain with change_delay_seconds = 0, as a tool before
// the floor wrote it, still decodes and encodes: a runner pinned to it
// starts, and its waits are the floor. A stored locked update with 0 for
// such a setup decodes and matches the setup the same way.
func TestStoredChangeDelayBelowFloorDecodes(t *testing.T) {
	for _, chain := range []backend.Version{MainnetForkVersion, {0xde, 0xad, 0xbe, 0xef}} {
		s := samples(t)["setup-nitro"]
		s.Chain.GenesisForkVersion = chain
		s.Locked.ChangeDelaySeconds = u64p(0)
		raw := rawSetup(s)
		got, err := DecodeSetup(raw)
		if err != nil {
			t.Fatalf("%x: a stored setup with change_delay_seconds 0 does not decode: %v", chain, err)
		}
		if got.Locked.ChangeDelay() != 0 || got.Locked.ChangeDelayOn(chain) != DefaultTimeLock {
			t.Fatalf("%x: stored %d, in force %d, want 0 and the floor %d", chain, got.Locked.ChangeDelay(), got.Locked.ChangeDelayOn(chain), DefaultTimeLock)
		}
		if again, err := got.Encode(); err != nil || !bytes.Equal(again, raw) {
			t.Fatalf("%x: Encode of the stored setup: %v", chain, err)
		}
		b := lockedBody(s)
		b.Locked.ChangeDelaySeconds = u64p(0)
		enc, err := signedUpdate(t, s, b, []byte{0, 1}, nil).Encode()
		if err != nil {
			t.Fatal(err)
		}
		dec, err := DecodeUpdate(enc)
		if err != nil {
			t.Fatalf("%x: a stored update with change_delay_seconds 0 does not decode: %v", chain, err)
		}
		if err := dec.Body.Matches(got); err != nil {
			t.Fatalf("%x: the stored update does not match its setup: %v", chain, err)
		}
		next := lockedBody(s)
		if w := Wait(chain, dec.Body.Locked, &next); w != DefaultTimeLock {
			t.Fatalf("%x: the wait under the stored 0 is %d, want the floor %d", chain, w, DefaultTimeLock)
		}
	}
}

func TestActivation(t *testing.T) {
	const now, w = 1_800_000_000, 3600
	limit := uint64(now + w + ActivationHorizon)
	if LatestActivateAt(now, w) != limit {
		t.Fatal("latest")
	}
	for _, c := range []struct {
		at, now, w uint64
		ok         bool
	}{
		{limit, now, w, true},
		{limit + 1, now, w, false},
		{0, now, w, true}, // in the past: it still waits w from arrival
		{maxU, now, w, false},
		{maxU, maxU - 10, w, true},  // the sum saturates, it does not wrap
		{maxU, 10, maxU, true},      // a huge wait saturates too
		{1 << 40, maxU, maxU, true}, // and no sum wraps to a small limit
		{maxU - 1, 1 << 63, 1 << 63, true},
	} {
		if err := CheckActivateAt(c.at, c.now, c.w); (err == nil) != c.ok {
			t.Errorf("activate_at %d, now %d, wait %d: got %v, want ok=%v", c.at, c.now, c.w, err, c.ok)
		}
	}
	for _, c := range []struct{ at, arrival, w, want uint64 }{
		{now + 2*w, now, w, now + 2*w}, // in time: switch at activate_at
		{now, now, w, now + w},         // late: wait the full w
		{0, now, 0, now},
		{5, maxU - 1, 10, maxU},
	} {
		if got := EffectiveActivation(c.at, c.arrival, c.w); got != c.want {
			t.Errorf("effective(%d, %d, %d) = %d, want %d", c.at, c.arrival, c.w, got, c.want)
		}
	}
}
