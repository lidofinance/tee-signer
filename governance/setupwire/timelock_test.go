package setupwire

import (
	"bytes"
	"math"
	"testing"
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
	cases := []struct {
		name     string
		timeLock *uint64
		body     UpdateBody
		want     uint64
	}{
		{"open", u64p(5 * 86400), UpdateBody{Group: GroupOpen, Open: &open}, 0},
		{"locked, time lock 0", u64p(0), UpdateBody{Group: GroupLocked, Locked: &same}, 0},
		{"locked, default", nil, UpdateBody{Group: GroupLocked, Locked: &same}, DefaultTimeLock},
		{"new image, time lock 0", u64p(0), UpdateBody{Group: GroupLocked, Locked: &gains}, ImagesMinTimeLock},
		{"new image, default", nil, UpdateBody{Group: GroupLocked, Locked: &gains}, ImagesMinTimeLock},
		{"new image, longer time lock", u64p(10 * 86400), UpdateBody{Group: GroupLocked, Locked: &gains}, 10 * 86400},
		{"image removed", u64p(3600), UpdateBody{Group: GroupLocked, Locked: &drops}, 3600},
	}
	for _, c := range cases {
		a := active
		a.ChangeDelaySeconds = c.timeLock
		if got := Wait(&a, &c.body); got != c.want {
			t.Errorf("%s: wait %d, want %d", c.name, got, c.want)
		}
	}
	if !GainsImage(nil, gains.AllowedImageMeasurements) || GainsImage(gains.AllowedImageMeasurements, active.AllowedImageMeasurements) || GainsImage(active.AllowedImageMeasurements, active.AllowedImageMeasurements) {
		t.Fatal("GainsImage")
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
