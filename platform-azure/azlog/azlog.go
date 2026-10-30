//go:build platform_azure

// Package azlog is the mark log in an Azure Blob Storage container under a
// locked time-based retention policy (container-level WORM, not
// version-level: locked blobs "can't be modified or deleted by any user,
// not even by users with account administrative privileges"), through the
// Blob REST API with a small client of its own: Put Blob with
// If-None-Match: *, Get Blob and List Blobs. Nothing else of the API is
// used.
//
// Requests carry a Microsoft Entra token for https://storage.azure.com/
// from the container group's managed identity (IMDS), which only the
// confidential container gets.
package azlog

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/slashing-log"
)

func init() { markstore.Register("azblob", Open) }

// APIVersion is the x-ms-version the client sends. OAuth needs 2017-11-09
// or later.
const APIVersion = "2021-08-06"

// Log is one container.
type Log struct {
	Account   string
	Container string
	Endpoint  string // base URL of the account; empty: https://ACCOUNT.blob.core.windows.net
	HTTP      *http.Client
	Token     func(ctx context.Context) (string, error)
	// TokenRefused, if set, drops a token the store answered 401 to; the
	// request then goes once more with a fresh token.
	TokenRefused func(token string)
	// The lock check reads the container's immutability policy from the
	// management plane: the storage account's subscription and resource
	// group, and a token for https://management.azure.com/.
	Subscription  string
	ResourceGroup string
	ARMEndpoint   string // empty: https://management.azure.com
	ARMToken      func(ctx context.Context) (string, error)
	// ARMTokenRefused is TokenRefused for ARMToken.
	ARMTokenRefused func(token string)
}

// Open parses "account=A,container=C[,endpoint=URL][,subscription=S,resource_group=G[,arm_endpoint=URL]]".
func Open(rest string, env markstore.Env) (markstore.Log, error) {
	p, err := markstore.Params(rest, []string{"account", "container"}, []string{"endpoint", "subscription", "resource_group", "arm_endpoint"})
	if err != nil {
		return nil, err
	}
	if env.Token == nil {
		return nil, errors.New("azlog: no token source: the store needs the managed identity's token")
	}
	return &Log{Account: p["account"], Container: p["container"], Endpoint: p["endpoint"], HTTP: env.HTTP, Token: env.Token, TokenRefused: env.TokenRefused,
		Subscription: p["subscription"], ResourceGroup: p["resource_group"], ARMEndpoint: p["arm_endpoint"],
		ARMToken: env.ARMToken, ARMTokenRefused: env.ARMTokenRefused}, nil
}

// ARMAPIVersion is the api-version of the management-plane read.
const ARMAPIVersion = "2023-05-01"

// Lock reads the container (Blob Containers, Get) and its time-based
// retention policy (Get Immutability Policy) from the management plane:
// the data plane only says whether a container has a policy
// (x-ms-has-immutability-policy), not its state or period. The managed
// identity needs read access to both
// (Microsoft.Storage/storageAccounts/blobServices/containers/read and
// .../containers/immutabilityPolicies/read; Reader on the container grants
// both). A container with version-level immutability does not count as
// locked (CheckVersions).
func (l *Log) Lock(ctx context.Context) (markstore.Lock, error) {
	container, found, err := l.container(ctx)
	if err != nil {
		return markstore.Lock{}, err
	}
	if !found {
		// No such container under this subscription and resource group
		// (a wrong one in the setup also gives 404): no lock, and
		// CheckLock stops the start.
		return markstore.Lock{Kind: "azure immutability policy", Mode: "none"}, nil
	}
	var p struct {
		Properties struct {
			Days  int64  `json:"immutabilityPeriodSinceCreationInDays"`
			State string `json:"state"` // Locked or Unlocked
		} `json:"properties"`
	}
	if found, err = l.armGet(ctx, container+"/immutabilityPolicies/default", "immutability policy", &p); err != nil {
		return markstore.Lock{}, err
	}
	if !found {
		// No policy on the container: no lock.
		return markstore.Lock{Kind: "azure immutability policy", Mode: "none"}, nil
	}
	if p.Properties.Days < 0 || p.Properties.Days > 1<<20 {
		return markstore.Lock{}, fmt.Errorf("azlog: immutability period of %d days", p.Properties.Days)
	}
	return markstore.Lock{Kind: "azure immutability policy", Mode: p.Properties.State, Compliance: p.Properties.State == "Locked",
		Retention: time.Duration(p.Properties.Days) * 24 * time.Hour}, nil
}

// CheckVersions reads the container from the management plane and fails
// when it has version-level immutability (immutableStorageWithVersioning
// enabled, or a migration to it started). There an overwrite makes a new
// current version and keeps the locked one as a previous version, and List
// and Get read current versions only, so a storage admin could hide the
// newest objects and roll the log or the state copy back. A container the
// management plane does not find (404) fails too: the account name is
// global, so the data plane can reach a container that a wrong
// subscription or resource group in the setup hides from this check.
func (l *Log) CheckVersions(ctx context.Context) error {
	u, found, err := l.container(ctx)
	if err == nil && !found {
		err = fmt.Errorf("%w: azlog: the management plane has no container at %s; check the subscription, resource group, account and container",
			markstore.ErrNoLock, u)
	}
	return err
}

// container reads the container from the management plane, refuses
// version-level immutability, and returns the container's ARM URL.
func (l *Log) container(ctx context.Context) (u string, found bool, err error) {
	if l.Subscription == "" || l.ResourceGroup == "" || l.ARMToken == nil {
		return "", false, errors.New("azlog: the lock and version checks need subscription=, resource_group= and a management-plane token")
	}
	base := "https://management.azure.com"
	if l.ARMEndpoint != "" {
		base = strings.TrimSuffix(l.ARMEndpoint, "/")
	}
	u = fmt.Sprintf("%s/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s/blobServices/default/containers/%s",
		base, url.PathEscape(l.Subscription), url.PathEscape(l.ResourceGroup), url.PathEscape(l.Account), url.PathEscape(l.Container))
	var c struct {
		Properties struct {
			VersionLevel *struct {
				Enabled        bool   `json:"enabled"`
				MigrationState string `json:"migrationState"`
			} `json:"immutableStorageWithVersioning"`
		} `json:"properties"`
	}
	if found, err = l.armGet(ctx, u, "container", &c); err != nil || !found {
		return u, found, err
	}
	if v := c.Properties.VersionLevel; v != nil && (v.Enabled || v.MigrationState != "") {
		return u, true, fmt.Errorf("%w: azlog: container %s has version-level immutability (enabled %v, migration %q); the client reads current blob versions only and needs a container with a locked container-level policy",
			markstore.ErrNoLock, l.Container, v.Enabled, v.MigrationState)
	}
	return u, true, nil
}

// armGet reads one management-plane resource at u into v. A 404 is
// found == false with no error.
func (l *Log) armGet(ctx context.Context, u, what string, v any) (found bool, err error) {
	u += "?api-version=" + ARMAPIVersion
	resp, err := l.send(ctx, l.ARMToken, l.ARMTokenRefused, "management token", func() (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	})
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return false, fmt.Errorf("azlog: %s: %s: %s%s", what, resp.Status, strings.TrimSpace(string(b)), authHeader(resp))
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(v); err != nil {
		return false, fmt.Errorf("azlog: %s: %w", what, err)
	}
	return true, nil
}

func (l *Log) String() string { return "azblob://" + l.Account + "/" + l.Container }

func (l *Log) base() string {
	if l.Endpoint != "" {
		return strings.TrimSuffix(l.Endpoint, "/") + "/" + l.Container
	}
	return "https://" + l.Account + ".blob.core.windows.net/" + l.Container
}

func (l *Log) do(ctx context.Context, method, u string, body []byte, hdr map[string]string) (*http.Response, error) {
	return l.send(ctx, l.Token, l.TokenRefused, "token", func() (*http.Request, error) {
		var r io.Reader
		if body != nil {
			r = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, u, r)
		if err != nil {
			return nil, err
		}
		req.Header.Set("x-ms-version", APIVersion)
		req.Header.Set("x-ms-date", time.Now().UTC().Format(http.TimeFormat))
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		return req, nil
	})
}

// send sends the request that build makes with a bearer token from token.
// On a 401 it hands that token to refused (the cache drops it), takes a
// fresh one and sends the request once more; the second answer stands.
func (l *Log) send(ctx context.Context, token func(context.Context) (string, error), refused func(string), what string,
	build func() (*http.Request, error)) (*http.Response, error) {
	client := l.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	for try := 0; ; try++ {
		tok, err := token(ctx)
		if err != nil {
			return nil, fmt.Errorf("azlog: %s: %w", what, err)
		}
		req, err := build()
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != http.StatusUnauthorized || refused == nil || try > 0 {
			return resp, err
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		refused(tok)
	}
}

// errorOf reads a Blob service error: the status, the error code and
// message, and for a 401 the AuthenticationErrorDetail and the
// WWW-Authenticate header, which say why the token was refused (expired,
// wrong audience).
func errorOf(resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	var e struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
		Detail  string `xml:"AuthenticationErrorDetail"`
	}
	_ = xml.Unmarshal(b, &e)
	if e.Code == "" {
		e.Code = resp.Header.Get("x-ms-error-code")
	}
	msg := fmt.Sprintf("azlog: %s %s %s", resp.Status, e.Code, oneLine(e.Message))
	if e.Detail != "" {
		msg += "; detail: " + oneLine(e.Detail)
	}
	return errors.New(msg + authHeader(resp))
}

// authHeader is the answer's WWW-Authenticate header for an error message,
// or nothing.
func authHeader(resp *http.Response) string {
	if h := resp.Header.Get("WWW-Authenticate"); h != "" {
		return "; WWW-Authenticate: " + oneLine(h)
	}
	return ""
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

func escapeName(name string) string {
	parts := strings.Split(name, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

// Create puts a block blob with If-None-Match: *. An existing blob (409
// BlobAlreadyExists, or 412) is ErrExists; so is a blob the immutability
// policy keeps (409 BlobImmutableDueToPolicy), which only happens when it
// exists.
func (l *Log) Create(ctx context.Context, name string, data []byte) error {
	resp, err := l.do(ctx, http.MethodPut, l.base()+"/"+escapeName(name), data, map[string]string{
		"x-ms-blob-type": "BlockBlob", "If-None-Match": "*", "Content-Type": "application/octet-stream",
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusCreated:
		return nil
	case resp.StatusCode == http.StatusPreconditionFailed,
		resp.StatusCode == http.StatusConflict && (resp.Header.Get("x-ms-error-code") == "BlobAlreadyExists" ||
			resp.Header.Get("x-ms-error-code") == "BlobImmutableDueToPolicy"):
		return markstore.ErrExists
	}
	return errorOf(resp)
}

// List enumerates the blobs under prefix (List Blobs, all pages).
func (l *Log) List(ctx context.Context, prefix string) ([]markstore.Entry, error) {
	var out []markstore.Entry
	marker := ""
	for page := 0; page < 100000; page++ {
		q := url.Values{"restype": {"container"}, "comp": {"list"}, "prefix": {prefix}}
		if marker != "" {
			q.Set("marker", marker)
		}
		resp, err := l.do(ctx, http.MethodGet, l.base()+"?"+q.Encode(), nil, nil)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			err := errorOf(resp)
			resp.Body.Close()
			return nil, err
		}
		var r struct {
			Blobs struct {
				Blob []struct {
					Name string `xml:"Name"`
				} `xml:"Blob"`
			} `xml:"Blobs"`
			NextMarker string `xml:"NextMarker"`
		}
		err = xml.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&r)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("azlog: list: %w", err)
		}
		for _, b := range r.Blobs.Blob {
			out = append(out, markstore.Entry{Name: b.Name})
		}
		if r.NextMarker == "" {
			return out, nil
		}
		marker = r.NextMarker
	}
	return nil, errors.New("azlog: listing too long")
}

// Get reads one blob.
func (l *Log) Get(ctx context.Context, e markstore.Entry) ([]byte, error) {
	resp, err := l.do(ctx, http.MethodGet, l.base()+"/"+escapeName(e.Name), nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	case http.StatusNotFound:
		return nil, markstore.ErrNotFound
	}
	return nil, errorOf(resp)
}
