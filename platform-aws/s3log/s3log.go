//go:build platform_aws

// Package s3log is the mark log on an S3 bucket with versioning and Object
// Lock (default retention in compliance mode), with a small SigV4 client of
// its own: PutObject with If-None-Match: *, GetObject by version ID and
// ListObjectVersions. Nothing else of the S3 API is used.
//
// Requests are signed with credentials only the enclave holds
// (platform.Platform.RecordCredentials, the same path as the clone guard's
// DynamoDB record). The bucket's Object Lock default retention locks every
// record when it is written, so the client sends no retention headers; S3
// requires Content-MD5 on a put to such a bucket, which it does send.
// Every header the client sets is signed, as the AWS SDKs do (the S3 SigV4
// rules require host, x-amz-*, and Content-Type and Content-MD5 when
// present). A request that fails before an answer (connection reset) is
// sent once more: a create whose first attempt landed then answers 412,
// which the mark log reads back as its own record.
package s3log

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/slashing-log"
)

func init() { markstore.Register("s3", Open) }

// Log is one bucket.
type Log struct {
	Bucket   string
	Region   string
	Endpoint string // path-style base URL (tests, or a VPC endpoint); empty: https://BUCKET.s3.REGION.amazonaws.com
	HTTP     *http.Client
	Creds    func(ctx context.Context) (platform.Credentials, error)
	Now      func() time.Time
}

// Open parses "bucket=B,region=R[,endpoint=URL]".
func Open(rest string, env markstore.Env) (markstore.Log, error) {
	p, err := markstore.Params(rest, []string{"bucket", "region"}, []string{"endpoint"})
	if err != nil {
		return nil, err
	}
	if env.AWSCreds == nil {
		return nil, errors.New("s3log: no credentials: the store needs credentials only the enclave holds")
	}
	return &Log{Bucket: p["bucket"], Region: p["region"], Endpoint: p["endpoint"], HTTP: env.HTTP, Creds: env.AWSCreds}, nil
}

func (l *Log) String() string { return "s3://" + l.Bucket }

// target is the URL of key (empty: the bucket) and the host to sign.
func (l *Log) target(key string, q url.Values) (*url.URL, error) {
	var base string
	if l.Endpoint != "" {
		base = strings.TrimSuffix(l.Endpoint, "/") + "/" + l.Bucket
	} else {
		base = fmt.Sprintf("https://%s.s3.%s.amazonaws.com", l.Bucket, l.Region)
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	if key != "" {
		u.Path += "/" + key
	} else if u.Path == "" {
		u.Path = "/"
	}
	u.RawQuery = canonicalQuery(q)
	return u, nil
}

// uriEncode is SigV4's UriEncode: unreserved characters as they are,
// everything else %XX; slashes kept in paths.
func uriEncode(s string, path bool) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && path:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func canonicalQuery(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vs := append([]string(nil), q[k]...)
		sort.Strings(vs)
		for _, v := range vs {
			parts = append(parts, uriEncode(k, false)+"="+uriEncode(v, false))
		}
	}
	return strings.Join(parts, "&")
}

func hmacSHA(key []byte, s string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(s))
	return m.Sum(nil)
}

// Sign computes a SigV4 signature (service s3) over the request parts:
// the method, the decoded path, the canonical query, the signed headers
// (lower-case names, with values) and the payload hash.
func Sign(method, path, query string, headers map[string]string, payloadHash string,
	creds platform.Credentials, region string, t time.Time) (signedHeaders, signature string) {
	names := make([]string, 0, len(headers))
	for h := range headers {
		names = append(names, h)
	}
	sort.Strings(names)
	var ch strings.Builder
	for _, h := range names {
		ch.WriteString(h + ":" + strings.TrimSpace(headers[h]) + "\n")
	}
	signedHeaders = strings.Join(names, ";")
	creq := strings.Join([]string{method, uriEncode(path, true), query, ch.String(), signedHeaders, payloadHash}, "\n")
	amzDate, day := t.UTC().Format("20060102T150405Z"), t.UTC().Format("20060102")
	scope := day + "/" + region + "/s3/aws4_request"
	h := sha256.Sum256([]byte(creq))
	sts := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(h[:])
	k := hmacSHA([]byte("AWS4"+creds.SecretAccessKey), day)
	k = hmacSHA(k, region)
	k = hmacSHA(k, "s3")
	k = hmacSHA(k, "aws4_request")
	return signedHeaders, hex.EncodeToString(hmacSHA(k, sts))
}

// send is do, once more after a failure without an answer.
func (l *Log) send(ctx context.Context, method, key string, q url.Values, body []byte, hdr http.Header) (*http.Response, error) {
	resp, err := l.do(ctx, method, key, q, body, hdr)
	if err != nil && ctx.Err() == nil {
		resp, err = l.do(ctx, method, key, q, body, hdr)
	}
	return resp, err
}

// do signs and sends one request.
func (l *Log) do(ctx context.Context, method, key string, q url.Values, body []byte, hdr http.Header) (*http.Response, error) {
	creds, err := l.Creds(ctx)
	if err != nil {
		return nil, fmt.Errorf("s3log: credentials: %w", err)
	}
	u, err := l.target(key, q)
	if err != nil {
		return nil, err
	}
	u.RawPath = uriEncode(u.Path, true)
	now := time.Now
	if l.Now != nil {
		now = l.Now
	}
	t := now().UTC()
	ph := sha256.Sum256(body)
	payload := hex.EncodeToString(ph[:])
	req, err := http.NewRequestWithContext(ctx, method, u.String(), strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	signedVals := map[string]string{"host": u.Host, "x-amz-content-sha256": payload, "x-amz-date": t.Format("20060102T150405Z")}
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
		signedVals[strings.ToLower(k)] = strings.Join(vs, ",")
	}
	if creds.SessionToken != "" {
		signedVals["x-amz-security-token"] = creds.SessionToken
	}
	for h, v := range signedVals {
		if h != "host" {
			req.Header.Set(h, v)
		}
	}
	names, sig := Sign(method, u.Path, u.RawQuery, signedVals, payload, creds, l.Region, t)
	scope := t.Format("20060102") + "/" + l.Region + "/s3/aws4_request"
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		creds.AccessKeyID, scope, names, sig))
	client := l.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	return client.Do(req)
}

func errorOf(resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	var e struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}
	_ = xml.Unmarshal(b, &e)
	what := ""
	if resp.Request != nil {
		what = resp.Request.Method + " " + resp.Request.URL.Path + ": "
	}
	return fmt.Errorf("s3log: %s%s %s: %s", what, resp.Status, e.Code, e.Message)
}

// Create puts data under name only if no object of that name is current.
// If-None-Match looks at the current version only, so a delete marker over
// another instance's record lets the put through. After a put that landed
// Create lists the name's versions and delete markers: anything besides
// the one new version is a hidden record, markstore.ErrHidden (issue #5 R3).
// After a put S3 refused it looks for a delete marker (checkMarker).
func (l *Log) Create(ctx context.Context, name string, data []byte) error {
	sum := md5.Sum(data)
	hdr := http.Header{}
	hdr.Set("If-None-Match", "*")
	hdr.Set("Content-MD5", base64.StdEncoding.EncodeToString(sum[:]))
	hdr.Set("Content-Type", "application/octet-stream")
	resp, err := l.send(ctx, http.MethodPut, name, nil, data, hdr)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return l.checkHidden(ctx, name)
	case http.StatusPreconditionFailed:
		return l.checkMarker(ctx, name)
	}
	return errorOf(resp)
}

// checkMarker runs after a create that S3 refused (412): a delete marker on
// the name means the name looked free to some create, so another object may
// sit under it next to the current one (a lost reply to this runner's own
// create over a marker on a clone's record, RBRLOG-01). That is
// markstore.ErrHidden; a name without a marker is markstore.ErrExists.
func (l *Log) checkMarker(ctx context.Context, name string) error {
	_, markers, err := l.listVersions(ctx, name)
	if err != nil {
		return fmt.Errorf("s3log: %s exists, but its versions cannot be listed: %w", name, err)
	}
	for _, v := range markers {
		if v.Name == name {
			return fmt.Errorf("%w: %s exists and has a delete marker", markstore.ErrHidden, name)
		}
	}
	return markstore.ErrExists
}

// checkHidden lists the versions and delete markers of name after a create.
func (l *Log) checkHidden(ctx context.Context, name string) error {
	versions, markers, err := l.listVersions(ctx, name)
	if err != nil {
		return fmt.Errorf("s3log: created %s, but its versions cannot be listed: %w", name, err)
	}
	n, d := 0, 0
	for _, v := range versions {
		if v.Name == name {
			n++
		}
	}
	for _, v := range markers {
		if v.Name == name {
			d++
		}
	}
	if n != 1 || d != 0 {
		return fmt.Errorf("%w: %s has %d versions and %d delete markers after the create", markstore.ErrHidden, name, n, d)
	}
	return nil
}

type listVersions struct {
	IsTruncated         bool        `xml:"IsTruncated"`
	NextKeyMarker       string      `xml:"NextKeyMarker"`
	NextVersionIDMarker string      `xml:"NextVersionIdMarker"`
	Versions            []listEntry `xml:"Version"`
	DeleteMarkers       []listEntry `xml:"DeleteMarker"`
}

type listEntry struct {
	Key       string `xml:"Key"`
	VersionID string `xml:"VersionId"`
}

// List returns every object version under prefix (ListObjectVersions):
// a delete marker the admin puts on a record does not hide it.
func (l *Log) List(ctx context.Context, prefix string) ([]markstore.Entry, error) {
	out, _, err := l.listVersions(ctx, prefix)
	return out, err
}

// listVersions returns the object versions and the delete markers under
// prefix.
func (l *Log) listVersions(ctx context.Context, prefix string) ([]markstore.Entry, []markstore.Entry, error) {
	var out, markers []markstore.Entry
	keyMarker, verMarker := "", ""
	for page := 0; page < 100000; page++ {
		q := url.Values{"versions": {""}, "prefix": {prefix}}
		if keyMarker != "" {
			q.Set("key-marker", keyMarker)
			if verMarker != "" {
				q.Set("version-id-marker", verMarker)
			}
		}
		resp, err := l.send(ctx, http.MethodGet, "", q, nil, nil)
		if err != nil {
			return nil, nil, err
		}
		if resp.StatusCode != http.StatusOK {
			err := errorOf(resp)
			resp.Body.Close()
			return nil, nil, err
		}
		var r listVersions
		err = xml.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&r)
		resp.Body.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("s3log: list: %w", err)
		}
		for _, v := range r.Versions {
			out = append(out, markstore.Entry{Name: v.Key, Ref: v.VersionID})
		}
		for _, v := range r.DeleteMarkers {
			markers = append(markers, markstore.Entry{Name: v.Key, Ref: v.VersionID})
		}
		if !r.IsTruncated {
			return out, markers, nil
		}
		if r.NextKeyMarker == "" {
			return nil, nil, errors.New("s3log: truncated listing without a marker")
		}
		keyMarker, verMarker = r.NextKeyMarker, r.NextVersionIDMarker
	}
	return nil, nil, errors.New("s3log: listing too long")
}

// Lock reads the bucket's Object Lock configuration (GetObjectLockConfiguration,
// GET /?object-lock): the default retention every new record gets. The
// credentials need s3:GetBucketObjectLockConfiguration. A bucket without
// Object Lock answers 404 ObjectLockConfigurationNotFoundError.
func (l *Log) Lock(ctx context.Context) (markstore.Lock, error) {
	resp, err := l.send(ctx, http.MethodGet, "", url.Values{"object-lock": {""}}, nil, nil)
	if err != nil {
		return markstore.Lock{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		err := errorOf(resp)
		if strings.Contains(err.Error(), "ObjectLockConfigurationNotFoundError") {
			return markstore.Lock{Kind: "s3 object lock", Mode: "none"}, nil
		}
		return markstore.Lock{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return markstore.Lock{}, errorOf(resp)
	}
	var c struct {
		Enabled string `xml:"ObjectLockEnabled"`
		Rule    struct {
			DefaultRetention struct {
				Mode  string `xml:"Mode"`
				Days  int64  `xml:"Days"`
				Years int64  `xml:"Years"`
			} `xml:"DefaultRetention"`
		} `xml:"Rule"`
	}
	if err := xml.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&c); err != nil {
		return markstore.Lock{}, fmt.Errorf("s3log: object lock configuration: %w", err)
	}
	r := c.Rule.DefaultRetention
	days := r.Days
	if r.Years > 0 {
		days = r.Years * 365
	}
	if days < 0 || days > 1<<20 {
		return markstore.Lock{}, fmt.Errorf("s3log: object lock retention of %d days", days)
	}
	return markstore.Lock{Kind: "s3 object lock", Mode: r.Mode,
		Compliance: c.Enabled == "Enabled" && r.Mode == "COMPLIANCE",
		Retention:  time.Duration(days) * 24 * time.Hour}, nil
}

// Get reads one object version.
func (l *Log) Get(ctx context.Context, e markstore.Entry) ([]byte, error) {
	var q url.Values
	if e.Ref != "" {
		q = url.Values{"versionId": {e.Ref}}
	}
	resp, err := l.send(ctx, http.MethodGet, e.Name, q, nil, nil)
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
