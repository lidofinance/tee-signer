//go:build platform_gcp

package gcslog

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/lidofinance/tee-signer/slashing-log"
	"github.com/lidofinance/tee-signer/slashing-log/logtest"
	"github.com/lidofinance/tee-signer/slashing-log/wormfake"
)

func TestGCSLog(t *testing.T) {
	logtest.Run(t, wormfake.GCS, func(t *testing.T, srv *wormfake.Server) markstore.Log {
		srv.Auth = func(r *http.Request) error {
			if r.Header.Get("Authorization") != "Bearer federated-token" {
				return errors.New("bad token")
			}
			return nil
		}
		l, err := Open("bucket="+srv.Bucket+",endpoint="+srv.URL, markstore.Env{
			HTTP: srv.Client(), Token: func(context.Context) (string, error) { return "federated-token", nil }})
		if err != nil {
			t.Fatal(err)
		}
		return l
	})
}

func TestGCSOpenNeedsToken(t *testing.T) {
	if _, err := Open("bucket=b", markstore.Env{}); err == nil {
		t.Fatal("opened without a token source")
	}
	if _, err := Open("region=x", markstore.Env{Token: func(context.Context) (string, error) { return "", nil }}); err == nil {
		t.Fatal("opened without a bucket")
	}
}
