package certreload

import (
	"testing"
	"time"
)

// Each poll counts under its result, and Since moves with each swap.
func TestStats(t *testing.T) {
	f := newFixture(t, goodPair(t, 1))
	if s := f.w.Stats(); s != (Stats{Since: t0}) {
		t.Fatalf("stats at start %+v", s)
	}
	if got, want := f.w.Current().NotBefore(), t0.Add(-time.Hour); !got.Equal(want) {
		t.Fatalf("not before %v, want %v", got, want)
	}
	f.w.Poll()
	f.write(content(t, kindGarbage, 2))
	f.w.Poll()
	f.w.Poll()
	f.write(goodPair(t, 3))
	f.now = t0.Add(time.Minute)
	if !f.w.Poll() {
		t.Fatal("no swap")
	}
	f.w.Poll()
	want := Stats{Reloaded: 1, Refused: 2, Unchanged: 2, Since: t0.Add(time.Minute)}
	if s := f.w.Stats(); s != want {
		t.Fatalf("stats %+v, want %+v", s, want)
	}
}
