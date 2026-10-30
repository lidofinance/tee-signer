//go:build platform_azure

package azlog

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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

func openARM(t *testing.T, url string, client *http.Client) *Log {
	t.Helper()
	tok := func(context.Context) (string, error) { return "tok", nil }
	l, err := Open("account=acct,container=marks,endpoint="+url+",subscription=sub-1,resource_group=rg-1,arm_endpoint="+url,
		markstore.Env{HTTP: client, Token: tok, ARMToken: tok})
	if err != nil {
		t.Fatal(err)
	}
	return l.(*Log)
}

// A container with version-level immutability keeps overwritten blobs as
// previous versions, which List and Get do not read: the lock check
// refuses it even with a locked policy, and so it does during a migration
// to it.
func TestAzureLockRefusesVersionLevelImmutability(t *testing.T) {
	srv := wormfake.New(wormfake.Azure, "marks")
	defer srv.Close()
	l := openARM(t, srv.URL, srv.Client())
	ctx := context.Background()
	if err := markstore.CheckLock(ctx, l, 30); err != nil {
		t.Fatalf("container-level, locked, 30 days: %v", err)
	}
	for _, c := range []struct {
		lock wormfake.Lock
		want string
	}{
		{wormfake.Lock{Compliance: true, Days: 30, VersionLevel: true}, "enabled true"},
		{wormfake.Lock{Compliance: true, Days: 30, Migrating: true}, `migration "InProgress"`},
	} {
		srv.SetLock(c.lock)
		err := markstore.CheckLock(ctx, l, 30)
		if !errors.Is(err, markstore.ErrNoLock) || !strings.Contains(err.Error(), "version-level") || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v, want ErrNoLock for version-level immutability", c.lock, err)
		}
	}
}

// The container read on its own: a container answer without
// immutableStorageWithVersioning is container-level; no container is no
// lock; any other failure fails the check.
func TestAzureLockContainerRead(t *testing.T) {
	const policy = `{"properties":{"immutabilityPeriodSinceCreationInDays":30,"state":"Locked"}}`
	for _, c := range []struct {
		name      string
		status    int
		container string
		ok        bool
		noLock    bool
	}{
		{"no versioning property", http.StatusOK, `{"properties":{"hasImmutabilityPolicy":true}}`, true, false},
		{"version-level off", http.StatusOK, `{"properties":{"immutableStorageWithVersioning":{"enabled":false}}}`, true, false},
		{"version-level on", http.StatusOK, `{"properties":{"immutableStorageWithVersioning":{"enabled":true,"migrationState":"Completed"}}}`, false, true},
		{"no container", http.StatusNotFound, `{"error":{"code":"ContainerNotFound"}}`, false, true},
		{"no read access", http.StatusForbidden, `{"error":{"code":"AuthorizationFailed"}}`, false, false},
		{"not JSON", http.StatusOK, `<html>`, false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			var policyReads int
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("api-version") != ARMAPIVersion {
					http.Error(w, "api-version", http.StatusBadRequest)
					return
				}
				switch r.URL.Path {
				case "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/acct/blobServices/default/containers/marks":
					w.WriteHeader(c.status)
					w.Write([]byte(c.container))
				case "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/acct/blobServices/default/containers/marks/immutabilityPolicies/default":
					policyReads++
					w.Write([]byte(policy))
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			err := markstore.CheckLock(context.Background(), openARM(t, srv.URL, srv.Client()), 30)
			switch {
			case c.ok && err != nil:
				t.Fatalf("lock check: %v", err)
			case !c.ok && err == nil:
				t.Fatal("lock check passed")
			case !c.ok && errors.Is(err, markstore.ErrNoLock) != c.noLock:
				t.Fatalf("lock check: %v, want ErrNoLock %v", err, c.noLock)
			}
			if !c.ok && policyReads != 0 {
				t.Fatalf("read the policy %d times after the container read refused", policyReads)
			}
		})
	}
}
