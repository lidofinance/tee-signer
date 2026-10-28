package gcp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/slashing-log"
)

// kmsErrors wraps fakeGoogle: a decrypt of a ciphertext in fail gets the
// HTTP status and error body set for it, as Cloud KMS answers for a key
// version that is disabled or destroyed, or when it is out of service.
type kmsErrors struct {
	mu   sync.Mutex
	fail map[string]kmsAnswer
}

type kmsAnswer struct {
	status int
	body   string
}

func gcpError(code int, status, msg string) string {
	return fmt.Sprintf(`{"error":{"code":%d,"message":%q,"status":%q}}`, code, msg, status)
}

func (k *kmsErrors) wrap(t *testing.T, g *httptest.Server) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ":decrypt") {
			body, _ := io.ReadAll(r.Body)
			k.mu.Lock()
			var a *kmsAnswer
			for ct, ans := range k.fail {
				if strings.Contains(string(body), ct) {
					a = &ans
				}
			}
			k.mu.Unlock()
			if a != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(a.status)
				io.WriteString(w, a.body)
				return
			}
			r.Body = io.NopCloser(strings.NewReader(string(body)))
		}
		req, _ := http.NewRequestWithContext(r.Context(), r.Method, g.URL+r.URL.RequestURI(), r.Body)
		req.Header = r.Header.Clone()
		resp, err := g.Client().Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// RBRGCP-01: OpenKey's error classes. Only a decrypt that KMS refuses as
// INVALID_ARGUMENT (a ciphertext it did not make, or another aad) is
// ErrNotAuthentic; the mark log skips such a record. Every other answer is
// a hard error that stops Claim: a disabled or destroyed key version
// (FAILED_PRECONDITION), a 400 without a status, a denial, an outage. The
// error shapes follow the Google API error model; which status Cloud KMS
// gives a disabled version is not verified against a live KMS.
func TestRBRGCP01OpenKeyErrorClasses(t *testing.T) {
	g := fakeGoogle(t)
	defer g.Close()
	ke := &kmsErrors{fail: map[string]kmsAnswer{}}
	front := ke.wrap(t, g)
	ctx := context.Background()
	aad := []byte("signer-mark-key-v1|signer-3")
	keys := Keys{K: testKMS(t, front)}
	_, blob, err := keys.NewKey(ctx, aad)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name      string
		answer    *kmsAnswer
		authentic bool // false: ErrNotAuthentic
		hard      bool // an error that is not ErrNotAuthentic
		otherAAD  bool
	}{
		{name: "opens", authentic: true},
		{name: "another aad: INVALID_ARGUMENT", otherAAD: true},
		{name: "key version disabled: FAILED_PRECONDITION", answer: &kmsAnswer{400, gcpError(400, "FAILED_PRECONDITION", "projects/p/.../cryptoKeyVersions/2 is not enabled, current state is: DISABLED.")}, hard: true},
		{name: "key version destroyed: FAILED_PRECONDITION", answer: &kmsAnswer{400, gcpError(400, "FAILED_PRECONDITION", "projects/p/.../cryptoKeyVersions/2 is not enabled, current state is: DESTROYED.")}, hard: true},
		{name: "400 without a status", answer: &kmsAnswer{400, "Bad Request"}, hard: true},
		{name: "400 OUT_OF_RANGE", answer: &kmsAnswer{400, gcpError(400, "OUT_OF_RANGE", "x")}, hard: true},
		{name: "permission denied", answer: &kmsAnswer{403, gcpError(403, "PERMISSION_DENIED", "denied")}, hard: true},
		{name: "not found", answer: &kmsAnswer{404, gcpError(404, "NOT_FOUND", "no key")}, hard: true},
		{name: "quota", answer: &kmsAnswer{429, gcpError(429, "RESOURCE_EXHAUSTED", "quota")}, hard: true},
		{name: "unavailable", answer: &kmsAnswer{503, gcpError(503, "UNAVAILABLE", "try again")}, hard: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ke.mu.Lock()
			ke.fail = map[string]kmsAnswer{}
			if c.answer != nil {
				ke.fail[b64(blob)] = *c.answer
			}
			ke.mu.Unlock()
			use := aad
			if c.otherAAD {
				use = []byte("signer-mark-key-v1|signer-4")
			}
			_, err := keys.OpenKey(ctx, blob, use)
			switch {
			case c.authentic && err != nil:
				t.Fatalf("open: %v", err)
			case c.hard && (err == nil || errors.Is(err, platform.ErrNotAuthentic)):
				t.Fatalf("got %v, want a hard error (not ErrNotAuthentic)", err)
			case !c.authentic && !c.hard && !errors.Is(err, platform.ErrNotAuthentic):
				t.Fatalf("got %v, want ErrNotAuthentic", err)
			}
		})
	}
}

// RBRGCP-01, the mark log: runner A writes records under its key blob, a
// later runner B claims and writes the newest records under a blob of its
// own, and the KMS admin disables the key version under B's blob. A
// restart must stop at Claim, not fall back to A's older record (a lower
// mark).
func TestRBRGCP01DisabledKeyVersionStopsClaim(t *testing.T) {
	g := fakeGoogle(t)
	defer g.Close()
	ke := &kmsErrors{fail: map[string]kmsAnswer{}}
	front := ke.wrap(t, g)
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	setup := &markstore.Setup{Hash: [32]byte{0x5e, 2}, Signer: "signer-1", RetentionDays: 30,
		First: markstore.ConfigState{Locked: markstore.GroupState{Hash: [32]byte{0x10}}, Open: markstore.GroupState{Hash: [32]byte{0x20}}}}
	opt := markstore.Options{Setup: setup, Clock: func() (time.Time, error) { return now, nil },
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	fl, err := markstore.NewFileLog(filepath.Join(t.TempDir(), "marks"))
	if err != nil {
		t.Fatal(err)
	}
	keys := Keys{K: testKMS(t, front), Setup: setup.Hash}
	wm := func(e uint64) backend.Watermark {
		return backend.Watermark{HasAttestation: true, SourceEpoch: e - 1, TargetEpoch: e, HasBlock: true, BlockSlot: e * 32}
	}
	a, _ := markstore.New(fl, "signer-1", keys, opt)
	if _, _, err := a.Claim(ctx, false); err != nil {
		t.Fatal(err)
	}
	if err := a.Append(ctx, wm(10)); err != nil {
		t.Fatal(err)
	}
	b, _ := markstore.New(fl, "signer-1", keys, opt)
	if _, _, err := b.Claim(ctx, true); err != nil {
		t.Fatal(err)
	}
	if err := b.Append(ctx, wm(20)); err != nil {
		t.Fatal(err)
	}
	r, err := markstore.Parse(mustNewest(t, fl, setup))
	if err != nil {
		t.Fatal(err)
	}
	ke.mu.Lock()
	ke.fail[b64(r.KeyBlob)] = kmsAnswer{400, gcpError(400, "FAILED_PRECONDITION", "cryptoKeyVersions/2 is not enabled, current state is: DISABLED.")}
	ke.mu.Unlock()

	c, _ := markstore.New(fl, "signer-1", keys, opt)
	mark, _, err := c.Claim(ctx, true)
	if err == nil {
		t.Errorf("Claim fell back to an older record (target %d) past the newest one, whose key version is disabled", mark.TargetEpoch)
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func mustNewest(t *testing.T, l markstore.Log, s *markstore.Setup) []byte {
	t.Helper()
	es, err := l.List(context.Background(), markstore.Prefix(s.Hash, s.Signer))
	if err != nil || len(es) == 0 {
		t.Fatal("no records", err)
	}
	newest := es[0]
	for _, e := range es {
		if e.Name > newest.Name {
			newest = e
		}
	}
	b, err := l.Get(context.Background(), newest)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
