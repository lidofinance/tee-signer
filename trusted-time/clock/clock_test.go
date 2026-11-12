package clock

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeSource struct {
	name string
	t    time.Time
	err  error
}

func (f *fakeSource) Fetch(context.Context) (time.Time, error) { return f.t, f.err }
func (f *fakeSource) Name() string                             { return f.name }

var base = time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)

func TestQuorumMedianAndMinimum(t *testing.T) {
	ctx := context.Background()
	honest := func(s int) *fakeSource { return &fakeSource{name: "h", t: base.Add(time.Duration(s) * time.Second)} }
	liarBack := &fakeSource{name: "back", t: base.Add(-24 * time.Hour)}
	liarFwd := &fakeSource{name: "fwd", t: base.Add(24 * time.Hour)}
	down := &fakeSource{name: "down", err: errors.New("timeout")}

	q := &Quorum{Sources: []Source{honest(0), honest(1), honest(2), liarBack, liarFwd}, Min: 3}
	got, err := q.Fetch(ctx)
	if err != nil || got.Before(base) || got.After(base.Add(2*time.Second)) {
		t.Fatalf("2 liars of 5: got %v %v", got, err)
	}
	q = &Quorum{Sources: []Source{honest(0), liarBack, liarBack, down, down}, Min: 3}
	if got, err = q.Fetch(ctx); err != nil || !got.Equal(liarBack.t) {
		// 3 answers, 2 of them lies: the median is a lie. This is the
		// documented limit: liars must stay below Min.
		t.Fatalf("expected the liars to win with 2 of 3 answers, got %v %v", got, err)
	}
	q = &Quorum{Sources: []Source{honest(0), down, down}, Min: 2}
	if _, err = q.Fetch(ctx); err == nil || !strings.Contains(err.Error(), "1 of 3") {
		t.Fatalf("want quorum failure, got %v", err)
	}
}

func TestHTTPSDate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Date", "Mon, 12 Oct 2026 12:00:00 GMT")
	}))
	defer srv.Close()
	h := &HTTPSDate{URL: srv.URL, Client: srv.Client()}
	got, err := h.Fetch(context.Background())
	if err != nil || !got.Equal(base) {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := (&HTTPSDate{URL: "http://example.invalid"}).Fetch(context.Background()); err == nil {
		t.Fatal("plain http accepted")
	}
}

// The quorum counts each source: answers, failures, the last error, and how
// far its reading was from the quorum's answer. A failed round still counts.
func TestQuorumSourceStats(t *testing.T) {
	ctx := context.Background()
	a := &fakeSource{name: "a", t: base}
	b := &fakeSource{name: "b", t: base.Add(2 * time.Second)}
	c := &fakeSource{name: "c", err: errors.New("timeout")}
	q := &Quorum{Sources: []Source{a, b, c}, Min: 2}
	if st := q.SourceStats(); len(st) != 3 || st[0].Name != "a" || st[0].Queries != 0 || st[0].LastAnswerAge != -1 {
		t.Fatalf("before any round: %+v", st)
	}
	if got, err := q.Fetch(ctx); err != nil || !got.Equal(base) {
		t.Fatalf("%v %v", got, err)
	}
	st := q.SourceStats()
	if st[0].Answers != 1 || st[0].LastDiff != 0 || st[0].LastAnswerAge < 0 || st[0].LastError != "" {
		t.Fatalf("a: %+v", st[0])
	}
	if st[1].Answers != 1 || st[1].LastDiff != 2*time.Second {
		t.Fatalf("b: %+v", st[1])
	}
	if st[2].Queries != 1 || st[2].Failures != 1 || st[2].Answers != 0 || st[2].LastAnswerAge != -1 || st[2].LastError == "" {
		t.Fatalf("c: %+v", st[2])
	}
	// A round without a quorum: b's answer counts, its last diff stays.
	a.err, b.t = errors.New("down"), base.Add(5*time.Second)
	if _, err := q.Fetch(ctx); err == nil {
		t.Fatal("quorum with one answer")
	}
	st = q.SourceStats()
	if st[0].Failures != 1 || st[1].Answers != 2 || st[1].LastDiff != 2*time.Second || st[2].Failures != 2 {
		t.Fatalf("after a failed round: %+v", st)
	}
	an := &Anchored{Src: q, Interval: time.Second}
	if got := an.SourceStats(); len(got) != 3 || got[1].Answers != 2 {
		t.Fatalf("anchored: %+v", got)
	}
	if got := (&Anchored{Src: a, Interval: time.Second}).SourceStats(); got != nil {
		t.Fatalf("a source without stats: %+v", got)
	}
}
