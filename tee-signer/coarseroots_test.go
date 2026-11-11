//go:build nts

package main

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/platform/cloudroots"
	"github.com/lidofinance/tee-signer/trusted-time/clock"
	"github.com/lidofinance/tee-signer/trusted-time/nts"
	"github.com/lidofinance/tee-signer/trusted-time/ntscatalog"
)

// allowCoarseTestURLs lets coarse URLs outside the catalog through, as a
// debug build does, for the length of the test.
func allowCoarseTestURLs(t *testing.T) {
	old := coarseTestURLs
	coarseTestURLs = true
	t.Cleanup(func() { coarseTestURLs = old })
}

func catalogURL(t *testing.T, id string) coarseURL {
	for _, e := range ntscatalog.Builtin.Coarse {
		if e.ID == id {
			return coarseURL{named: e.URL, url: strings.ReplaceAll(e.URL, "{region}", "eu-central-1"), entry: e, ok: true}
		}
	}
	t.Fatalf("no coarse entry %s", id)
	return coarseURL{}
}

// Each coarse source trusts the roots its catalog entry names and nothing
// else; the platform's client keeps its own. A URL outside the catalog is
// refused on a platform with pinned roots, unless a debug build (or this
// test) allows test servers, which then get the platform's roots plus the
// NTS operators'.
func TestCoarseClientRoots(t *testing.T) {
	if c, err := coarseClient(nil, coarseURL{}); c != nil || err != nil {
		t.Fatalf("nil client: %v, %v", c, err)
	}
	plain := &http.Client{}
	if c, _ := coarseClient(plain, coarseURL{named: "https://a.example/"}); c != plain {
		t.Fatal("a client without pinned roots changed")
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: cloudroots.Pool(cloudroots.AWS)}}
	platform := &http.Client{Transport: tr}
	for id, want := range map[string]*x509.CertPool{
		"aws-kms":          cloudroots.Pool(cloudroots.AWS),
		"gcp-sts":          cloudroots.Pool(cloudroots.Google),
		"azure-management": cloudroots.Pool(cloudroots.Azure),
		"cloudflare-www":   withRoots(t, cloudroots.Pool(cloudroots.Google), "isrg-root-x1.pem", "isrg-root-x2.pem", "sslcom-root-ecc.pem"),
	} {
		c, err := coarseClient(platform, catalogURL(t, id))
		if err != nil {
			t.Fatal(err)
		}
		if !c.Transport.(*http.Transport).TLSClientConfig.RootCAs.Equal(want) {
			t.Errorf("%s: roots are not its catalog entry's", id)
		}
		refusesTestCA(t, c)
	}
	if !tr.TLSClientConfig.RootCAs.Equal(cloudroots.Pool(cloudroots.AWS)) {
		t.Error("the platform's client changed")
	}
	old := coarseTestURLs
	coarseTestURLs = false
	_, err := coarseClient(platform, coarseURL{named: "https://a.example/", url: "https://a.example/"})
	coarseTestURLs = old
	if err == nil || !strings.Contains(err.Error(), "not in the coarse catalog") {
		t.Fatalf("a URL outside the catalog: %v", err)
	}
	allowCoarseTestURLs(t)
	c, err := coarseClient(platform, coarseURL{named: "https://a.example/", url: "https://a.example/"})
	if err != nil {
		t.Fatal(err)
	}
	want := cloudroots.Pool(cloudroots.AWS)
	for _, s := range nts.PublicServers {
		if err := nts.AddRoots(want, s.Roots); err != nil {
			t.Fatal(err)
		}
	}
	if !c.Transport.(*http.Transport).TLSClientConfig.RootCAs.Equal(want) {
		t.Error("a test URL's roots are not the platform's plus the NTS operators'")
	}
}

// newNTSClock gives each HTTPS-date source of the coarse clock the client
// coarseClient makes for its URL.
func TestNTSClockUsesCoarseClient(t *testing.T) {
	t.Setenv("RUNNER_NTS_COARSE_URLS", "https://kms.{region}.amazonaws.com/,https://sts.{region}.amazonaws.com/,https://www.cloudflare.com/")
	t.Setenv("RUNNER_NTS_MAX_BOUND", "")
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: cloudroots.Pool(cloudroots.AWS)}}
	_, coarse, err := newNTSClock(&http.Client{Transport: tr}, nil, "eu-central-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]*x509.CertPool{
		"https://kms.eu-central-1.amazonaws.com/": cloudroots.Pool(cloudroots.AWS),
		"https://sts.eu-central-1.amazonaws.com/": cloudroots.Pool(cloudroots.AWS),
		"https://www.cloudflare.com/":             withRoots(t, cloudroots.Pool(cloudroots.Google), "isrg-root-x1.pem", "isrg-root-x2.pem", "sslcom-root-ecc.pem"),
	}
	for _, s := range coarse.Src.(*clock.Quorum).Sources {
		h := s.(*clock.HTTPSDate)
		if !h.Client.Transport.(*http.Transport).TLSClientConfig.RootCAs.Equal(want[h.URL]) {
			t.Fatalf("%s: roots are not its catalog entry's", h.URL)
		}
		refusesTestCA(t, h.Client)
	}
}

// Every coarse URL the image commands name is in the catalog (a release
// runner on a cloud refuses any other and does not start), and every root
// file a coarse entry names is pinned.
func TestCoarseCatalogCoversTheImages(t *testing.T) {
	flag := regexp.MustCompile(`"-nts-coarse-urls",\s*"([^"]*)"`)
	for _, f := range []string{
		"../platform-aws/deploy/enclave/Dockerfile",
		"../platform-gcp/deploy/Dockerfile",
		"../platform-azure/deploy/aci-template.json",
	} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		m := flag.FindAllSubmatch(b, -1)
		if len(m) != 1 {
			t.Fatalf("%s: %d -nts-coarse-urls flags, want 1", f, len(m))
		}
		urls := strings.Split(string(m[0][1]), ",")
		if len(urls) < 3 {
			t.Errorf("%s: %d coarse URLs, want 3 or more", f, len(urls))
		}
		for _, u := range urls {
			if _, ok := ntscatalog.Builtin.CoarseFor(strings.TrimSpace(u)); !ok {
				t.Errorf("%s: %s is not in the coarse catalog", f, u)
			}
		}
	}
	for _, e := range ntscatalog.Builtin.Coarse {
		if _, err := nts.RootPool(e.Roots); err != nil && len(e.Roots) > 0 {
			t.Errorf("%s: %v", e.ID, err)
		}
	}
}

func withRoots(t *testing.T, p *x509.CertPool, files ...string) *x509.CertPool {
	t.Helper()
	if err := nts.AddRoots(p, files); err != nil {
		t.Fatal(err)
	}
	return p
}

// refusesTestCA checks that c refuses a server whose CA is a test CA.
func refusesTestCA(t *testing.T, c *http.Client) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	_, err := c.Get(srv.URL)
	if err == nil || !strings.Contains(err.Error(), "certificate signed by unknown authority") {
		t.Fatalf("got %v, want an unknown authority error", err)
	}
}
