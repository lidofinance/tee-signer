//go:build platform_azure

package azlog

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/slashing-log"
	"github.com/lidofinance/tee-signer/slashing-log/logtest"
	"github.com/lidofinance/tee-signer/slashing-log/wormfake"
)

func TestAzureBlobLog(t *testing.T) {
	logtest.Run(t, wormfake.Azure, func(t *testing.T, srv *wormfake.Server) markstore.Log {
		srv.Auth = func(r *http.Request) error {
			if strings.HasPrefix(r.URL.Path, "/subscriptions/") {
				if r.Header.Get("Authorization") != "Bearer arm-token" {
					return errors.New("bad management token")
				}
				return nil
			}
			if r.Header.Get("Authorization") != "Bearer mi-token" || r.Header.Get("x-ms-version") != APIVersion {
				return errors.New("bad token or version")
			}
			return nil
		}
		l, err := Open("account=acct,container="+srv.Bucket+",endpoint="+srv.URL+",subscription=sub-1,resource_group=rg-1,arm_endpoint="+srv.URL,
			markstore.Env{HTTP: srv.Client(), Token: func(context.Context) (string, error) { return "mi-token", nil },
				ARMToken: func(context.Context) (string, error) { return "arm-token", nil }})
		if err != nil {
			t.Fatal(err)
		}
		return l
	})
}

func TestAzureOpenNeedsToken(t *testing.T) {
	if _, err := Open("account=a,container=c", markstore.Env{}); err == nil {
		t.Fatal("opened without a token source")
	}
}

// The data plane does not show the container's policy, so the lock check
// fails closed without the management-plane names and token.
func TestAzureLockNeedsTheManagementPlane(t *testing.T) {
	srv := wormfake.New(wormfake.Azure, "marks")
	defer srv.Close()
	tok := func(context.Context) (string, error) { return "mi-token", nil }
	l, err := Open("account=acct,container=marks,endpoint="+srv.URL, markstore.Env{HTTP: srv.Client(), Token: tok})
	if err != nil {
		t.Fatal(err)
	}
	if err := markstore.CheckLock(context.Background(), l, 1); err == nil || !strings.Contains(err.Error(), "subscription") {
		t.Fatalf("lock check without the management plane: %v", err)
	}
}
