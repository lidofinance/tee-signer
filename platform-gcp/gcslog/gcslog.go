//go:build platform_gcp

// Package gcslog is the mark log on a Cloud Storage bucket with a locked
// retention policy (Bucket Lock) and object versioning, through the JSON
// API with a small client of its own: a media upload with
// ifGenerationMatch=0, a media download by generation, and a listing with
// versions=true. Nothing else of the API is used.
//
// Requests carry an OAuth access token from the Confidential Space flow
// (attestation token, STS exchange, optional service account), so only the
// attested workload can write; the WIF provider's condition pins the image.
package gcslog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/slashing-log"
)

func init() { markstore.Register("gcs", Open) }

// Log is one bucket.
type Log struct {
	Bucket   string
	Endpoint string // base URL; empty: https://storage.googleapis.com
	HTTP     *http.Client
	Token    func(ctx context.Context) (string, error)
}

// Open parses "bucket=B[,endpoint=URL]".
func Open(rest string, env markstore.Env) (markstore.Log, error) {
	p, err := markstore.Params(rest, []string{"bucket"}, []string{"endpoint"})
	if err != nil {
		return nil, err
	}
	if env.Token == nil {
		return nil, errors.New("gcslog: no token source: the store needs the workload's federated token")
	}
	return &Log{Bucket: p["bucket"], Endpoint: p["endpoint"], HTTP: env.HTTP, Token: env.Token}, nil
}

func (l *Log) String() string { return "gs://" + l.Bucket }

func (l *Log) base() string {
	if l.Endpoint != "" {
		return strings.TrimSuffix(l.Endpoint, "/")
	}
	return "https://storage.googleapis.com"
}

func (l *Log) do(ctx context.Context, method, u string, body []byte) (*http.Response, error) {
	tok, err := l.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcslog: token: %w", err)
	}
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	client := l.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	return client.Do(req)
}

func errorOf(resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	var e struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(b, &e)
	return fmt.Errorf("gcslog: %s: %s", resp.Status, e.Error.Message)
}

// Create uploads data under name with ifGenerationMatch=0: only if no live
// object of that name exists. After an upload that landed it checks that
// the name holds no other generation (checkGenerations).
func (l *Log) Create(ctx context.Context, name string, data []byte) error {
	q := url.Values{"uploadType": {"media"}, "name": {name}, "ifGenerationMatch": {"0"}}
	resp, err := l.do(ctx, http.MethodPost, l.base()+"/upload/storage/v1/b/"+url.PathEscape(l.Bucket)+"/o?"+q.Encode(), data)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return l.checkGenerations(ctx, name)
	case http.StatusPreconditionFailed:
		return markstore.ErrExists
	}
	return errorOf(resp)
}

// checkGenerations lists the generations of name after a create landed:
// anything besides the new one is an object someone made noncurrent, which
// let the create through (object versioning on; RBRLOG-01). That is
// markstore.ErrHidden, which the mark log reads as another instance's write.
func (l *Log) checkGenerations(ctx context.Context, name string) error {
	es, err := l.List(ctx, name)
	if err != nil {
		return fmt.Errorf("gcslog: created %s, but its generations cannot be listed: %w", name, err)
	}
	n := 0
	for _, e := range es {
		if e.Name == name {
			n++
		}
	}
	if n != 1 {
		return fmt.Errorf("%w: %s has %d generations after the create", markstore.ErrHidden, name, n)
	}
	return nil
}

// List returns every generation under prefix (versions=true), so an object
// made noncurrent does not drop out of the listing.
func (l *Log) List(ctx context.Context, prefix string) ([]markstore.Entry, error) {
	var out []markstore.Entry
	token := ""
	for page := 0; page < 100000; page++ {
		q := url.Values{"prefix": {prefix}, "versions": {"true"}, "fields": {"items(name,generation),nextPageToken"}}
		if token != "" {
			q.Set("pageToken", token)
		}
		resp, err := l.do(ctx, http.MethodGet, l.base()+"/storage/v1/b/"+url.PathEscape(l.Bucket)+"/o?"+q.Encode(), nil)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			err := errorOf(resp)
			resp.Body.Close()
			return nil, err
		}
		var r struct {
			Items []struct {
				Name       string `json:"name"`
				Generation string `json:"generation"`
			} `json:"items"`
			NextPageToken string `json:"nextPageToken"`
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&r)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("gcslog: list: %w", err)
		}
		for _, it := range r.Items {
			if _, err := strconv.ParseInt(it.Generation, 10, 64); err != nil {
				return nil, fmt.Errorf("gcslog: list: generation %q", it.Generation)
			}
			out = append(out, markstore.Entry{Name: it.Name, Ref: it.Generation})
		}
		if r.NextPageToken == "" {
			return out, nil
		}
		token = r.NextPageToken
	}
	return nil, errors.New("gcslog: listing too long")
}

// Lock reads the bucket's retention policy (buckets.get,
// fields=retentionPolicy). The principal needs storage.buckets.get. A
// bucket without a policy answers without the field.
func (l *Log) Lock(ctx context.Context) (markstore.Lock, error) {
	q := url.Values{"fields": {"retentionPolicy"}}
	resp, err := l.do(ctx, http.MethodGet, l.base()+"/storage/v1/b/"+url.PathEscape(l.Bucket)+"?"+q.Encode(), nil)
	if err != nil {
		return markstore.Lock{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return markstore.Lock{}, errorOf(resp)
	}
	var b struct {
		RetentionPolicy *struct {
			RetentionPeriod string `json:"retentionPeriod"` // seconds, int64 as a string
			IsLocked        bool   `json:"isLocked"`
		} `json:"retentionPolicy"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&b); err != nil {
		return markstore.Lock{}, fmt.Errorf("gcslog: bucket: %w", err)
	}
	p := b.RetentionPolicy
	if p == nil {
		return markstore.Lock{Kind: "gcs retention policy", Mode: "none"}, nil
	}
	secs, err := strconv.ParseInt(p.RetentionPeriod, 10, 64)
	if err != nil || secs < 0 || secs > 1<<40 {
		return markstore.Lock{}, fmt.Errorf("gcslog: retention period %q", p.RetentionPeriod)
	}
	mode := "unlocked"
	if p.IsLocked {
		mode = "locked"
	}
	return markstore.Lock{Kind: "gcs retention policy", Mode: mode, Compliance: p.IsLocked,
		Retention: time.Duration(secs) * time.Second}, nil
}

// Get downloads one generation of an object.
func (l *Log) Get(ctx context.Context, e markstore.Entry) ([]byte, error) {
	q := url.Values{"alt": {"media"}}
	if e.Ref != "" {
		q.Set("generation", e.Ref)
	}
	resp, err := l.do(ctx, http.MethodGet, l.base()+"/storage/v1/b/"+url.PathEscape(l.Bucket)+"/o/"+url.PathEscape(e.Name)+"?"+q.Encode(), nil)
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
