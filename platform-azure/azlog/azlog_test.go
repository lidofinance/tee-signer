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

// A container or account with version-level immutability keeps
// overwritten blobs as previous versions, which List and Get do not read,
// and a policy with protected append writes lets bytes be added to a
// blob: the lock check refuses each, even with a locked policy.
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
		{wormfake.Lock{Compliance: true, Days: 30, VersionLevel: true}, "version-level immutability (enabled true"},
		{wormfake.Lock{Compliance: true, Days: 30, Migrating: true}, `migration "InProgress"`},
		{wormfake.Lock{Compliance: true, Days: 30, AccountVersionLevel: true}, "storage account acct has version-level immutability"},
		{wormfake.Lock{Compliance: true, Days: 30, AppendWrites: true}, "allows appends"},
	} {
		srv.SetLock(c.lock)
		for what, err := range map[string]error{"lock": markstore.CheckLock(ctx, l, 30), "versions": markstore.CheckVersions(ctx, l)} {
			if !errors.Is(err, markstore.ErrNoLock) || !strings.Contains(err.Error(), c.want) {
				t.Errorf("%s check, %+v: %v, want ErrNoLock with %q", what, c.lock, err, c.want)
			}
		}
	}
}

// The management-plane reads on their own: the account, then the
// container with its policy. A refusal or a failed read fails both checks;
// a container without a locked policy fails only the lock check.
func TestAzureLockContainerRead(t *testing.T) {
	const pol = `"immutabilityPolicy":{"properties":{"immutabilityPeriodSinceCreationInDays":30,"state":"Locked"}}`
	for _, c := range []struct {
		name               string
		acctStatus         int    // 0: 200
		acct               string // "": an account without version-level immutability
		status             int
		container          string
		lockOK, versionsOK bool
		noLock             bool   // a failure is ErrNoLock
		want               string // in the error of a failure
	}{
		{"no versioning property", 0, "", 200, `{"properties":{"hasImmutabilityPolicy":true,` + pol + `}}`, true, true, false, ""},
		{"version-level off", 0, "", 200, `{"properties":{"immutableStorageWithVersioning":{"enabled":false},` + pol + `}}`, true, true, false, ""},
		{"version-level on", 0, "", 200, `{"properties":{"immutableStorageWithVersioning":{"enabled":true,"migrationState":"Completed"},` + pol + `}}`, false, false, true, "version-level"},
		{"migration in progress", 0, "", 200, `{"properties":{"immutableStorageWithVersioning":{"enabled":false,"migrationState":"InProgress"},` + pol + `}}`, false, false, true, "InProgress"},
		{"append writes all", 0, "", 200, `{"properties":{"immutabilityPolicy":{"properties":{"immutabilityPeriodSinceCreationInDays":30,"state":"Locked","allowProtectedAppendWritesAll":true}}}}`, false, false, true, "allows appends"},
		{"append writes", 0, "", 200, `{"properties":{"immutabilityPolicy":{"properties":{"immutabilityPeriodSinceCreationInDays":30,"state":"Locked","allowProtectedAppendWrites":true}}}}`, false, false, true, "allows appends"},
		{"no policy", 0, "", 200, `{"properties":{"hasImmutabilityPolicy":false}}`, false, true, true, `mode "none"`},
		{"unlocked policy", 0, "", 200, `{"properties":{"immutabilityPolicy":{"properties":{"immutabilityPeriodSinceCreationInDays":30,"state":"Unlocked"}}}}`, false, true, true, `mode "Unlocked"`},
		{"no container", 0, "", 404, `{"error":{"code":"ContainerNotFound"}}`, false, false, true, "no container at http"},
		{"no account", 404, `{"error":{"code":"ResourceNotFound"}}`, 200, `{"properties":{` + pol + `}}`, false, false, true, "no storage account at http"},
		{"account version-level", 0, `{"properties":{"immutableStorageWithVersioning":{"enabled":true}}}`, 200, `{"properties":{` + pol + `}}`, false, false, true, "storage account acct has version-level"},
		{"no account read access", 403, `{"error":{"code":"AuthorizationFailed"}}`, 200, `{"properties":{` + pol + `}}`, false, false, false, "403"},
		{"no container read access", 0, "", 403, `{"error":{"code":"AuthorizationFailed"}}`, false, false, false, "403"},
		{"not JSON", 0, "", 200, `<html>`, false, false, false, "container"},
	} {
		t.Run(c.name, func(t *testing.T) {
			const acctPath = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/acct"
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("api-version") != ARMAPIVersion {
					http.Error(w, "api-version", http.StatusBadRequest)
					return
				}
				switch r.URL.Path {
				case acctPath:
					if c.acctStatus != 0 {
						w.WriteHeader(c.acctStatus)
					}
					if c.acct == "" {
						w.Write([]byte(`{"properties":{}}`))
						return
					}
					w.Write([]byte(c.acct))
				case acctPath + "/blobServices/default/containers/marks":
					w.WriteHeader(c.status)
					w.Write([]byte(c.container))
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			l := openARM(t, srv.URL, srv.Client())
			for _, k := range []struct {
				what string
				ok   bool
				err  error
			}{
				{"lock check", c.lockOK, markstore.CheckLock(context.Background(), l, 30)},
				{"version check", c.versionsOK, markstore.CheckVersions(context.Background(), l)},
			} {
				switch {
				case k.ok && k.err != nil:
					t.Errorf("%s: %v", k.what, k.err)
				case k.ok:
				case k.err == nil:
					t.Errorf("%s passed", k.what)
				case errors.Is(k.err, markstore.ErrNoLock) != c.noLock || !strings.Contains(k.err.Error(), c.want):
					t.Errorf("%s: %v, want ErrNoLock %v and %q", k.what, k.err, c.noLock, c.want)
				}
			}
			if c.status == http.StatusNotFound || c.acctStatus == http.StatusNotFound {
				for _, f := range []func(context.Context) error{
					func(ctx context.Context) error { return markstore.CheckLock(ctx, l, 30) },
					func(ctx context.Context) error { return markstore.CheckVersions(ctx, l) },
				} {
					if err := f(context.Background()); err == nil || !strings.Contains(err.Error(), "/subscriptions/sub-1/resourceGroups/rg-1/") {
						t.Errorf("404 error does not name the path: %v", err)
					}
				}
			}
		})
	}
}
