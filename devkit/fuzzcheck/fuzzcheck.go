// Package fuzzcheck holds the oracles the fuzz targets share: a decoder of
// untrusted bytes must not panic, and must not allocate more than its
// input justifies. Only tests import it.
package fuzzcheck

import (
	"runtime"
	"testing"
)

// Slack is the allocation any decode may make whatever its input: the
// fixed-size values, errors and small maps.
const Slack = 64 << 10

// PerByte is the allocation a decode may make per input byte: a part is
// cloned out of the input, and a few values point into it.
const PerByte = 16

// Bounded runs decode and fails t when it allocated more than
// PerByte*n + Slack bytes for an input of n bytes: a decoder that trusts
// a declared length allocates before the bytes are there.
func Bounded(t *testing.T, n int, decode func()) {
	t.Helper()
	BoundedBy(t, uint64(PerByte*n+Slack), decode)
}

// BoundedBy runs decode and fails t when it allocated more than limit
// bytes. TotalAlloc counts every goroutine of the process, so another
// test's goroutine can add to one run: decode runs up to tries times, and
// t fails only if every run went over. A decoder that trusts a declared
// length goes over every time.
func BoundedBy(t *testing.T, limit uint64, decode func()) {
	t.Helper()
	const tries = 3
	var got uint64
	for range tries {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		decode()
		runtime.ReadMemStats(&after)
		if got = after.TotalAlloc - before.TotalAlloc; got <= limit {
			return
		}
	}
	t.Fatalf("decode allocated %d bytes, at most %d (%d runs)", got, limit, tries)
}
