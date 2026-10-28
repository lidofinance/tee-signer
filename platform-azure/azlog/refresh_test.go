//go:build platform_azure

package azlog

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/slashing-log"
	"github.com/lidofinance/tee-signer/slashing-log/wormfake"
)

// expiringStore puts a front on a fake container that refuses expired
// tokens as Blob Storage does: 401
// InvalidAuthenticationInfo with an AuthenticationErrorDetail and a
// WWW-Authenticate header. ARM answers its own 401 form.
type expiringStore struct {
	mu      sync.Mutex
	expired map[string]bool
	refused []string // tokens answered with 401
}

func (s *expiringStore) expire(tok string) {
	s.mu.Lock()
	s.expired[tok] = true
	s.mu.Unlock()
}

func (s *expiringStore) refusals() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.refused...)
}

func newExpiringStore(t *testing.T) (*expiringStore, *wormfake.Server, *httptest.Server) {
	t.Helper()
	back := wormfake.New(wormfake.Azure, "marks")
	t.Cleanup(back.Close)
	u, _ := url.Parse(back.URL)
	proxy := httputil.NewSingleHostReverseProxy(u)
	s := &expiringStore{expired: map[string]bool{}}
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		s.mu.Lock()
		bad := s.expired[tok]
		if bad {
			s.refused = append(s.refused, tok)
		}
		s.mu.Unlock()
		if !bad {
			proxy.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/subscriptions/") {
			w.Header().Set("WWW-Authenticate", `Bearer authorization_uri="https://login.microsoftonline.com/tenant", error="invalid_token", error_description="The access token has expired."`)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":{"code":"ExpiredAuthenticationToken","message":"The access token expiry UTC time is earlier than current UTC time."}}`))
			return
		}
		w.Header().Set("WWW-Authenticate", "Bearer authorization_uri=https://login.microsoftonline.com/tenant/oauth2/authorize resource_id=https://storage.azure.com")
		w.Header().Set("x-ms-error-code", "InvalidAuthenticationInfo")
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?><Error><Code>InvalidAuthenticationInfo</Code><Message>Server failed to authenticate the request. Please refer to the information in the www-authenticate header.
RequestId:0e5a6f1e-201e-0042-2b8f-0123456789ab
Time:2026-10-25T04:33:12.0000000Z</Message><AuthenticationErrorDetail>Lifetime validation failed. The token is expired.</AuthenticationErrorDetail></Error>`))
	}))
	t.Cleanup(front.Close)
	return s, back, front
}

// fakeIMDS hands out tok-1, tok-2, ... each valid for an hour by its
// expires_on.
type fakeIMDS struct {
	mu     sync.Mutex
	prefix string
	n      int
}

func (f *fakeIMDS) fetch(context.Context) (string, time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	return f.prefix + string(rune('0'+f.n)), time.Now().Add(time.Hour), nil
}

func (f *fakeIMDS) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.n
}

func openRefreshing(t *testing.T, front *httptest.Server, imds, arm *fakeIMDS) *Log {
	t.Helper()
	c := markstore.NewTokenCache(imds.fetch, markstore.TokenRefreshAfter, markstore.TokenMaxAge)
	a := markstore.NewTokenCache(arm.fetch, markstore.TokenRefreshAfter, markstore.TokenMaxAge)
	l, err := Open("account=acct,container=marks,endpoint="+front.URL+",subscription=sub-1,resource_group=rg-1,arm_endpoint="+front.URL,
		markstore.Env{HTTP: front.Client(), Token: c.Token, TokenRefused: c.Invalidate, ARMToken: a.Token, ARMTokenRefused: a.Invalidate})
	if err != nil {
		t.Fatal(err)
	}
	return l.(*Log)
}

// The store refuses the cached token once (it expired before the cache
// thought it would): the write fetches a fresh token and goes through.
func TestAzureRefreshesTheTokenOn401(t *testing.T) {
	store, _, front := newExpiringStore(t)
	imds, arm := &fakeIMDS{prefix: "tok-"}, &fakeIMDS{prefix: "arm-"}
	l := openRefreshing(t, front, imds, arm)
	ctx := context.Background()
	if err := l.Create(ctx, "m/1", []byte("one")); err != nil {
		t.Fatal(err)
	}
	store.expire("tok-1")
	if err := l.Create(ctx, "m/2", []byte("two")); err != nil {
		t.Fatalf("write after the token expired: %v", err)
	}
	if got := store.refusals(); len(got) != 1 || got[0] != "tok-1" {
		t.Fatalf("refused %v, want tok-1 once", got)
	}
	if imds.count() != 2 {
		t.Fatalf("IMDS fetches = %d, want 2", imds.count())
	}
	// Reads go out with the fresh token, no new fetch.
	if b, err := l.Get(ctx, markstore.Entry{Name: "m/1"}); err != nil || string(b) != "one" {
		t.Fatalf("read: %q %v", b, err)
	}
	if es, err := l.List(ctx, "m/"); err != nil || len(es) != 2 {
		t.Fatalf("list: %v %v", es, err)
	}
	if imds.count() != 2 || len(store.refusals()) != 1 {
		t.Fatalf("after the reads: %d fetches, refusals %v", imds.count(), store.refusals())
	}
}

// The store refuses the fresh token too: one retry only, and the error
// carries the code, the AuthenticationErrorDetail and WWW-Authenticate.
func TestAzure401ErrorSaysWhy(t *testing.T) {
	store, _, front := newExpiringStore(t)
	imds, arm := &fakeIMDS{prefix: "tok-"}, &fakeIMDS{prefix: "arm-"}
	l := openRefreshing(t, front, imds, arm)
	for i := 1; i <= 9; i++ {
		store.expire("tok-" + string(rune('0'+i)))
	}
	err := l.Create(context.Background(), "m/1", []byte("one"))
	if err == nil {
		t.Fatal("write with every token refused: no error")
	}
	for _, want := range []string{"401", "InvalidAuthenticationInfo", "detail: Lifetime validation failed. The token is expired.", "WWW-Authenticate: Bearer authorization_uri=", "resource_id=https://storage.azure.com"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "\n") {
		t.Errorf("error spans lines: %q", err)
	}
	if got := store.refusals(); len(got) != 2 || imds.count() != 2 {
		t.Fatalf("refused %v after %d fetches, want two tries", got, imds.count())
	}
}

// The lock check's management token: the same refresh on a 401.
func TestAzureLockRefreshesTheManagementTokenOn401(t *testing.T) {
	store, back, front := newExpiringStore(t)
	back.SetLock(wormfake.Lock{Compliance: true, Days: 30})
	imds, arm := &fakeIMDS{prefix: "tok-"}, &fakeIMDS{prefix: "arm-"}
	l := openRefreshing(t, front, imds, arm)
	ctx := context.Background()
	if _, err := l.Lock(ctx); err != nil {
		t.Fatal(err)
	}
	store.expire("arm-1")
	lk, err := l.Lock(ctx)
	if err != nil || !lk.Compliance {
		t.Fatalf("lock after the token expired: %+v %v", lk, err)
	}
	if got := store.refusals(); len(got) != 1 || got[0] != "arm-1" || arm.count() != 2 || imds.count() != 0 {
		t.Fatalf("refused %v; fetches: arm %d, storage %d", got, arm.count(), imds.count())
	}
	store.expire("arm-2")
	store.expire("arm-3")
	_, err = l.Lock(ctx)
	if err == nil || !strings.Contains(err.Error(), "ExpiredAuthenticationToken") || !strings.Contains(err.Error(), `WWW-Authenticate: Bearer authorization_uri="https://login.microsoftonline.com/tenant", error="invalid_token"`) {
		t.Fatalf("lock with every token refused: %v", err)
	}
}
