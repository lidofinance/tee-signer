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
