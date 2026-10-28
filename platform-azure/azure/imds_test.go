package azure

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

type imdsSeen struct {
	path, query, metadata string
}

func fakeIMDS(t *testing.T, answers ...func(w http.ResponseWriter)) (*httptest.Server, func() []imdsSeen) {
	t.Helper()
	var mu sync.Mutex
	var seen []imdsSeen
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, imdsSeen{r.URL.Path, r.URL.RawQuery, r.Header.Get("Metadata")})
		i := len(seen) - 1
		mu.Unlock()
		if i >= len(answers) {
			i = len(answers) - 1
		}
		answers[i](w)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []imdsSeen {
		mu.Lock()
		defer mu.Unlock()
		return append([]imdsSeen(nil), seen...)
	}
}

func okToken(w http.ResponseWriter) {
	w.Write([]byte(`{"access_token":"the-token","refresh_token":"","expires_in":"28799","expires_on":"1539927532","not_before":"1539898432","resource":"https://vault.azure.net/","token_type":"Bearer"}`))
}

func status(code int, body string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) { http.Error(w, body, code) }
}

func TestIMDSTokenRequest(t *testing.T) {
	srv, seen := fakeIMDS(t, okToken)
	tok, err := (&IMDSTokens{URL: srv.URL + "/metadata/identity/oauth2/token", HTTP: srv.Client()}).Token(context.Background(), "https://vault.azure.net")
	if err != nil || tok != "the-token" {
		t.Fatal(tok, err)
	}
	got := seen()
	if len(got) != 1 || got[0].path != "/metadata/identity/oauth2/token" || got[0].metadata != "true" ||
		got[0].query != "api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net" {
		t.Fatalf("request %+v", got)
	}

	// A group with several identities names the one to use.
	srv2, seen2 := fakeIMDS(t, okToken)
	if _, err := (&IMDSTokens{URL: srv2.URL, ClientID: "0000-1111", HTTP: srv2.Client()}).Token(context.Background(), "https://vault.azure.net"); err != nil {
		t.Fatal(err)
	}
	q, _ := url.ParseQuery(seen2()[0].query)
	if q.Get("client_id") != "0000-1111" || q.Get("resource") != "https://vault.azure.net" || q.Get("api-version") != "2018-02-01" || len(q) != 3 {
		t.Fatalf("query %v", q)
	}
}

func TestIMDSRetries(t *testing.T) {
	// 404 (identity not ready), 410 and 429 are tried again.
	srv, seen := fakeIMDS(t, status(404, "not ready"), status(429, "slow down"), status(410, "gone"), okToken)
	tok, err := (&IMDSTokens{URL: srv.URL, HTTP: srv.Client()}).Token(context.Background(), "r")
	if err != nil || tok != "the-token" || len(seen()) != 4 {
		t.Fatal(tok, err, len(seen()))
	}
	// A bad request is not.
	srv, seen = fakeIMDS(t, status(400, `{"error":"invalid_request"}`), okToken)
	_, err = (&IMDSTokens{URL: srv.URL, HTTP: srv.Client()}).Token(context.Background(), "r")
	if err == nil || !strings.Contains(err.Error(), "invalid_request") || len(seen()) != 1 {
		t.Fatal(err, len(seen()))
	}
	// Failures that go on end after four tries.
	srv, seen = fakeIMDS(t, status(404, "no"))
	if _, err = (&IMDSTokens{URL: srv.URL, HTTP: srv.Client()}).Token(context.Background(), "r"); err == nil || len(seen()) != 4 {
		t.Fatal(err, len(seen()))
	}
}

func TestIMDSBadAnswers(t *testing.T) {
	for name, a := range map[string]func(http.ResponseWriter){
		"no token": func(w http.ResponseWriter) { w.Write([]byte(`{"expires_in":"1"}`)) },
		"not json": func(w http.ResponseWriter) { w.Write([]byte(`<html>`)) },
	} {
		srv, _ := fakeIMDS(t, a)
		if _, err := (&IMDSTokens{URL: srv.URL, HTTP: srv.Client()}).Token(context.Background(), "r"); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
