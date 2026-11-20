//go:build platform_gcp

package gcslog

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
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

// ProjectNumber reads the bucket's projectNumber from its metadata, and
// refuses metadata without one.
func TestGCSProjectNumber(t *testing.T) {
	read := func(number string) (uint64, error) {
		srv := wormfake.New(wormfake.GCS, "signer-marks")
		defer srv.Close()
		srv.ProjectNumber = number
		l, err := Open("bucket="+srv.Bucket+",endpoint="+srv.URL, markstore.Env{
			HTTP: srv.Client(), Token: func(context.Context) (string, error) { return "federated-token", nil }})
		if err != nil {
			t.Fatal(err)
		}
		return l.(*Log).ProjectNumber(context.Background())
	}
	if _, err := read(""); err == nil {
		t.Fatal("metadata without projectNumber gave a project")
	}
	if n, err := read("123456789"); err != nil || n != 123456789 {
		t.Fatalf("project number: %d, %v", n, err)
	}
}

func TestGCSOpenNeedsToken(t *testing.T) {
	if _, err := Open("bucket=b", markstore.Env{}); err == nil {
		t.Fatal("opened without a token source")
	}
	if _, err := Open("region=x", markstore.Env{Token: func(context.Context) (string, error) { return "", nil }}); err == nil {
		t.Fatal("opened without a bucket")
	}
}

// A nil Env.HTTP falls back to
// http.DefaultClient, which trusts the system roots and follows proxy
// variables; the platform's client trusts Google's roots only. Open, or
// the first request, must refuse a nil client instead. The fake is plain
// HTTP on loopback, which http.DefaultClient reaches.
func TestGCSNilClientIsRefused(t *testing.T) {
	srv := wormfake.New(wormfake.GCS, "signer-marks")
	defer srv.Close()
	var hits atomic.Int32
	srv.Auth = func(*http.Request) error { hits.Add(1); return nil }
	l, err := Open("bucket="+srv.Bucket+",endpoint="+srv.URL, markstore.Env{
		Token: func(context.Context) (string, error) { return "federated-token", nil }})
	if err == nil {
		_, err = l.List(context.Background(), "")
	}
	if err == nil || hits.Load() != 0 {
		t.Fatalf("a nil client sent %d request(s) through http.DefaultClient (err %v), want an error and no request", hits.Load(), err)
	}
}
