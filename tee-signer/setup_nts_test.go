//go:build nts

package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/platform/setup"
	"github.com/lidofinance/tee-signer/trusted-time/nts"
)

// The Nitro image names its coarse-time hosts with {region}; the runner
// fills in the region option, which comes from the setup, and nothing else.
func TestNTSCoarseURLsRegion(t *testing.T) {
	t.Setenv("RUNNER_NTS_COARSE_URLS", "https://kms.{region}.amazonaws.com/,https://sts.{region}.amazonaws.com/,https://www.cloudflare.com/")
	urls, err := ntsCoarseURLs("eu-central-1")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://kms.eu-central-1.amazonaws.com/", "https://sts.eu-central-1.amazonaws.com/", "https://www.cloudflare.com/"}
	if !slices.Equal(urls, want) {
		t.Fatalf("urls %v", urls)
	}
	if _, err := ntsCoarseURLs(""); err == nil || !strings.Contains(err.Error(), "{region}") {
		t.Fatalf("no region: %v", err)
	}
	// URLs without the placeholder stay as they are (Azure, GCP, old images).
	t.Setenv("RUNNER_NTS_COARSE_URLS", "https://a.example/,https://b.example/,https://c.example/")
	if urls, err := ntsCoarseURLs("eu-central-1"); err != nil || urls[0] != "https://a.example/" {
		t.Fatalf("plain urls %v %v", urls, err)
	}
}

// The fixed Nitro port map routes the NTS-KE servers the NTS clock dials,
// and the coarse-time hosts of the image's URLs.
func TestNitroPortMapMatchesTheNTSServers(t *testing.T) {
	var hosts []string
	for _, r := range setup.NitroNTSKE {
		if r.HostPort != 4460 {
			t.Fatalf("%s on port %d", r.Host, r.HostPort)
		}
		hosts = append(hosts, r.Host)
	}
	var want []string
	for _, s := range nts.PublicServers {
		want = append(want, s.Host)
	}
	if !slices.Equal(hosts, want) {
		t.Fatalf("port map NTS-KE hosts %v, the NTS clock dials %v", hosts, want)
	}
}
