//go:build platform_aws

package s3log

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/slashing-log"
	"github.com/lidofinance/tee-signer/slashing-log/logtest"
	"github.com/lidofinance/tee-signer/slashing-log/wormfake"
)

var example = platform.Credentials{AccessKeyID: "AKIAIOSFODNN7EXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}

// The two S3 examples of the AWS SigV4 documentation ("Signature
// Calculations for the Authorization Header", GET Object and GET Bucket
// Lifecycle), with their published signatures.
func TestSigV4Examples(t *testing.T) {
	when := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)
	empty := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	for _, c := range []struct {
		path, query string
		hdr         map[string]string
		want        string
	}{
		{"/test.txt", "", map[string]string{"host": "examplebucket.s3.amazonaws.com", "range": "bytes=0-9",
			"x-amz-content-sha256": empty, "x-amz-date": "20130524T000000Z"},
			"f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"},
		{"/", "lifecycle=", map[string]string{"host": "examplebucket.s3.amazonaws.com",
			"x-amz-content-sha256": empty, "x-amz-date": "20130524T000000Z"},
			"fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"},
	} {
		_, sig := Sign(http.MethodGet, c.path, c.query, c.hdr, empty, example, "us-east-1", when)
		if sig != c.want {
			t.Fatalf("%s?%s: signature %s, want %s", c.path, c.query, sig, c.want)
		}
	}
}

var authRE = regexp.MustCompile(`^AWS4-HMAC-SHA256 Credential=([^/]+)/(\d{8})/([^/]+)/s3/aws4_request, SignedHeaders=([a-z0-9;-]+), Signature=([0-9a-f]{64})$`)

// verify recomputes a request's signature: the fake accepts only requests
// signed with the enclave's credentials. It also holds the request to the
// S3 SigV4 rules on which headers must be signed ("Signature Calculations
// for the Authorization Header"): host and x-amz-content-sha256 always,
// every x-amz-* header sent (S3 answers AccessDenied, "There were headers
// present in the request which were not signed"), and Content-Type and
// Content-MD5 when present.
func verify(creds platform.Credentials, region string) func(r *http.Request) error {
	return func(r *http.Request) error {
		m := authRE.FindStringSubmatch(r.Header.Get("Authorization"))
		if m == nil || m[1] != creds.AccessKeyID || m[3] != region {
			return errors.New("bad Authorization header")
		}
		signed := map[string]bool{}
		for _, h := range strings.Split(m[4], ";") {
			signed[h] = true
		}
		if !signed["host"] || !signed["x-amz-content-sha256"] {
			return errors.New("host or x-amz-content-sha256 not signed")
		}
		for name := range r.Header {
			h := strings.ToLower(name)
			if (strings.HasPrefix(h, "x-amz-") || h == "content-type" || h == "content-md5") && !signed[h] {
				return errors.New("There were headers present in the request which were not signed: " + h)
			}
		}
		when, err := time.Parse("20060102T150405Z", r.Header.Get("x-amz-date"))
		if err != nil {
			return err
		}
		hdr := map[string]string{}
		for _, h := range strings.Split(m[4], ";") {
			if h == "host" {
				hdr[h] = r.Host
			} else {
				hdr[h] = r.Header.Get(h)
			}
		}
		if creds.SessionToken != "" && hdr["x-amz-security-token"] != creds.SessionToken {
			return errors.New("no session token")
		}
		_, sig := Sign(r.Method, r.URL.Path, canonicalQuery(r.URL.Query()), hdr, r.Header.Get("x-amz-content-sha256"), creds, region, when)
		if sig != m[5] {
			return errors.New("signature does not match")
		}
		return nil
	}
}

func TestS3Log(t *testing.T) {
	creds := platform.Credentials{AccessKeyID: "AKIDENCLAVE", SecretAccessKey: "secret-only-the-enclave-holds", SessionToken: "session"}
	logtest.Run(t, wormfake.S3, func(t *testing.T, srv *wormfake.Server) markstore.Log {
		srv.Auth = verify(creds, "eu-central-1")
		l, err := Open("bucket="+srv.Bucket+",region=eu-central-1,endpoint="+srv.URL, markstore.Env{
			HTTP: srv.Client(), AWSCreds: func(context.Context) (platform.Credentials, error) { return creds, nil }})
		if err != nil {
			t.Fatal(err)
		}
		return l
	})
}

// A request signed with other credentials (the parent instance's role, for
// example) is refused by the store.
func TestS3OtherCredentialsRefused(t *testing.T) {
	srv := wormfake.New(wormfake.S3, "signer-marks")
	defer srv.Close()
	srv.Auth = verify(platform.Credentials{AccessKeyID: "AKIDENCLAVE", SecretAccessKey: "enclave"}, "eu-central-1")
	l, _ := Open("bucket=signer-marks,region=eu-central-1,endpoint="+srv.URL, markstore.Env{HTTP: srv.Client(),
		AWSCreds: func(context.Context) (platform.Credentials, error) {
			return platform.Credentials{AccessKeyID: "AKIDENCLAVE", SecretAccessKey: "parent"}, nil
		}})
	if err := l.Create(context.Background(), "x", []byte("y")); err == nil {
		t.Fatal("a wrongly signed write was accepted")
	}
	if _, err := Open("bucket=b,region=r", markstore.Env{}); err == nil {
		t.Fatal("opened without credentials")
	}
}

// The PUT of a record carries Content-MD5 (Object Lock) and signs it, with
// Content-Type and If-None-Match: the fake refuses an unsigned one, as the
// SigV4 rules say S3 does.
func TestS3PutSignsItsHeaders(t *testing.T) {
	creds := platform.Credentials{AccessKeyID: "AKIDENCLAVE", SecretAccessKey: "enclave"}
	srv := wormfake.New(wormfake.S3, "signer-marks")
	defer srv.Close()
	var seen http.Header
	check := verify(creds, "eu-central-1")
	srv.Auth = func(r *http.Request) error {
		if r.Method == http.MethodPut {
			seen = r.Header.Clone()
		}
		return check(r)
	}
	l, _ := Open("bucket=signer-marks,region=eu-central-1,endpoint="+srv.URL, markstore.Env{HTTP: srv.Client(),
		AWSCreds: func(context.Context) (platform.Credentials, error) { return creds, nil }})
	if err := l.Create(context.Background(), "marks/s/00000000000000000001", []byte("record")); err != nil {
		t.Fatal(err)
	}
	m := authRE.FindStringSubmatch(seen.Get("Authorization"))
	if m == nil || m[4] != "content-md5;content-type;host;if-none-match;x-amz-content-sha256;x-amz-date" {
		t.Fatalf("signed headers %v", m)
	}
	if sum := md5.Sum([]byte("record")); seen.Get("Content-MD5") != base64.StdEncoding.EncodeToString(sum[:]) {
		t.Fatalf("Content-MD5 %q", seen.Get("Content-MD5"))
	}
	if err := l.Create(context.Background(), "marks/s/00000000000000000001", []byte("other")); !errors.Is(err, markstore.ErrExists) {
		t.Fatalf("second create: %v", err)
	}
}

// A request that gets no answer (the connection drops, as through a
// vsock-proxy that restarts) is sent once more; a refusal names the request.
func TestS3RetryAndErrorText(t *testing.T) {
	var puts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && puts.Add(1) == 1 {
			c, _, _ := w.(http.Hijacker).Hijack()
			c.Close()
			return
		}
		if r.Method == http.MethodGet && r.URL.Query().Get("prefix") == "marks/s/00000000000000000001" {
			// The listing after the create: the one new version.
			io.WriteString(w, `<ListVersionsResult><Version><Key>marks/s/00000000000000000001</Key><VersionId>v1</VersionId></Version></ListVersionsResult>`)
			return
		}
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, "<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>")
		}
	}))
	defer srv.Close()
	l, _ := Open("bucket=b,region=eu-central-1,endpoint="+srv.URL, markstore.Env{HTTP: srv.Client(),
		AWSCreds: func(context.Context) (platform.Credentials, error) { return example, nil }})
	if err := l.Create(context.Background(), "marks/s/00000000000000000001", []byte("r")); err != nil || puts.Load() != 2 {
		t.Fatalf("create after a dropped connection: %v, %d attempts", err, puts.Load())
	}
	_, err := l.List(context.Background(), "marks/s/")
	if err == nil || err.Error() != "s3log: GET /b: 403 Forbidden AccessDenied: Access Denied" {
		t.Fatalf("list: %v", err)
	}
}
