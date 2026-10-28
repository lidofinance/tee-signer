package azure

// The managed identity token for Key Vault.
//
// Sources: Microsoft's page "Enable Managed Identity in a Container Group"
// (https://learn.microsoft.com/en-us/azure/container-instances/container-instances-managed-identity):
// in a Linux container,
//
//	GET http://169.254.169.254/metadata/identity/oauth2/token
//	    ?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net[&client_id=<id>]
//	Metadata: true
//
// returns {"access_token": ..., "expires_on": ..., "resource": ...}, with
// expires_on in Unix seconds and expires_in in seconds, both as strings. The
// sidecar's pkg/common/token.go builds the same URL (its Identity has only
// a client_id) and its pkg/common/http.go adds the Metadata header. The
// group has one user-assigned identity and no system-assigned one, so the
// request names no client_id; the platform option client_id adds it if a
// group ever carries more than one. The page says nothing about which
// identity answers when there are several and no client_id is given.
//
// The identity needs the role "Key Vault Crypto Service Release User" on
// its key (cloud/azure/deploy.sh key-role).
//
// UNVERIFIED on Azure: whether a confidential group serves the metadata
// endpoint to its containers the same way.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	imdsTokenURL   = "http://169.254.169.254/metadata/identity/oauth2/token"
	imdsAPIVersion = "2018-02-01"
	vaultResource  = "https://vault.azure.net"
)

// TokenSource gives an access token for a resource.
type TokenSource interface {
	Token(ctx context.Context, resource string) (string, error)
}

// IMDSTokens gets tokens from the instance metadata service.
type IMDSTokens struct {
	URL      string // empty means imdsTokenURL
	ClientID string // optional: which user-assigned identity
	HTTP     *http.Client
}

// imdsRetry also retries 404 and 410, which the service answers while an
// identity is not ready yet (Microsoft's retry guidance for managed
// identities on VMs).
func imdsRetry(status int) bool {
	return retryable(status) || status == http.StatusNotFound || status == http.StatusGone
}

func (t *IMDSTokens) Token(ctx context.Context, resource string) (string, error) {
	tok, err := t.Fetch(ctx, resource)
	return tok.Value, err
}

// AccessToken is a token and the time it expires. Expires is zero when the
// answer gives no expiry.
type AccessToken struct {
	Value   string
	Expires time.Time
}

// Fetch gets a token and its expiry: expires_on, else expires_in from now.
// IMDS caches tokens and can hand out one that expires soon, so a cache of
// tokens must go by this time, not by the time it fetched the token.
func (t *IMDSTokens) Fetch(ctx context.Context, resource string) (AccessToken, error) {
	base := t.URL
	if base == "" {
		base = imdsTokenURL
	}
	q := url.Values{"api-version": {imdsAPIVersion}, "resource": {resource}}
	if t.ClientID != "" {
		q.Set("client_id", t.ClientID)
	}
	b, err := httpGetWithRetry(ctx, t.HTTP, base+"?"+q.Encode(), map[string]string{"Metadata": "true"}, imdsRetry)
	if err != nil {
		return AccessToken{}, fmt.Errorf("azure: managed identity token: %w", err)
	}
	now := time.Now()
	var out struct {
		AccessToken string          `json:"access_token"`
		ExpiresOn   json.RawMessage `json:"expires_on"`
		ExpiresIn   json.RawMessage `json:"expires_in"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return AccessToken{}, fmt.Errorf("azure: managed identity token answer: %w", err)
	}
	if out.AccessToken == "" {
		return AccessToken{}, errors.New("azure: managed identity token answer has no access_token")
	}
	tok := AccessToken{Value: out.AccessToken}
	if on, ok := seconds(out.ExpiresOn); ok && on > 0 {
		tok.Expires = time.Unix(on, 0)
	} else if in, ok := seconds(out.ExpiresIn); ok && in >= 0 {
		tok.Expires = now.Add(time.Duration(in) * time.Second)
	}
	return tok, nil
}

// seconds reads a whole number of seconds given as a JSON string or number.
func seconds(raw json.RawMessage) (int64, bool) {
	s := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	if s == "" || len(s) > 18 {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil
}
