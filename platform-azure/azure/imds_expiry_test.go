package azure

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/slashing-log"
)

func tokenAnswer(tok, fields string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		fmt.Fprintf(w, `{"access_token":%q,%s"resource":"https://storage.azure.com/","token_type":"Bearer"}`, tok, fields)
	}
}

// Fetch gives the expiry: expires_on, else expires_in from now, as a
// string (what IMDS sends) or a number; neither gives the zero time.
func TestIMDSTokenExpiry(t *testing.T) {
	now := time.Now()
	for name, c := range map[string]struct {
		fields string
		want   time.Time // zero: none
		within time.Duration
	}{
		"expires_on string": {`"expires_in":"28799","expires_on":"1539927532",`, time.Unix(1539927532, 0), 0},
		"expires_on number": {`"expires_on":1539927532,`, time.Unix(1539927532, 0), 0},
		"expires_in only":   {`"expires_in":"600",`, now.Add(600 * time.Second), 5 * time.Second},
		"bad expires_on":    {`"expires_on":"soon","expires_in":"600",`, now.Add(600 * time.Second), 5 * time.Second},
		"none":              {``, time.Time{}, 0},
		"bad both":          {`"expires_on":"x","expires_in":"-",`, time.Time{}, 0},
	} {
		srv, _ := fakeIMDS(t, tokenAnswer("tok", c.fields))
		got, err := (&IMDSTokens{URL: srv.URL, HTTP: srv.Client()}).Fetch(context.Background(), StorageResource)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got.Value != "tok" {
			t.Errorf("%s: token %q", name, got.Value)
		}
		if c.want.IsZero() != got.Expires.IsZero() || got.Expires.Sub(c.want).Abs() > c.within {
			t.Errorf("%s: expires %v, want %v", name, got.Expires, c.want)
		}
	}
}

// IMDS hands out a cached token with 3 minutes left (it renews its own
// cache late). The mark log's cache asks again a second later and takes
// the fresh token; then it keeps the fresh one.
func TestIMDSShortLivedTokenThroughTheCache(t *testing.T) {
	soon := time.Now().Add(3 * time.Minute).Unix()
	later := time.Now().Add(time.Hour).Unix()
	srv, seen := fakeIMDS(t,
		tokenAnswer("old", fmt.Sprintf(`"expires_on":"%d",`, soon)),
		tokenAnswer("new", fmt.Sprintf(`"expires_on":"%d",`, later)))
	imds := &IMDSTokens{URL: srv.URL, HTTP: srv.Client()}
	c := markstore.NewTokenCache(func(ctx context.Context) (string, time.Time, error) {
		t, err := imds.Fetch(ctx, StorageResource)
		return t.Value, t.Expires, err
	}, markstore.TokenRefreshAfter, markstore.TokenMaxAge)
	for i := 0; i < 3; i++ {
		tok, err := c.Token(context.Background())
		if err != nil || tok != "new" {
			t.Fatalf("request %d: %q %v", i, tok, err)
		}
	}
	if n := len(seen()); n != 2 {
		t.Fatalf("IMDS requests = %d, want 2", n)
	}
}
