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
	var got []string
	for _, u := range urls {
		got = append(got, u.url)
		if !u.ok {
			t.Errorf("%s: no catalog entry", u.named)
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("urls %v", got)
	}
	if _, err := ntsCoarseURLs(""); err == nil || !strings.Contains(err.Error(), "{region}") {
		t.Fatalf("no region: %v", err)
	}
	// URLs without the placeholder stay as they are (Azure, GCP, old images).
	t.Setenv("RUNNER_NTS_COARSE_URLS", "https://a.example/,https://b.example/,https://c.example/")
	if urls, err := ntsCoarseURLs("eu-central-1"); err != nil || urls[0].url != "https://a.example/" || urls[0].ok {
		t.Fatalf("plain urls %v %v", urls, err)
	}
}

// The fixed Nitro port map routes every NTS-KE server the NTS clock dials by
// default (it routes the rest of the catalog too, for -nts-terms-confirmed).
func TestNitroPortMapMatchesTheNTSServers(t *testing.T) {
	var hosts []string
	for _, r := range setup.NitroNTSKE {
		if r.HostPort != 4460 {
			t.Fatalf("%s on port %d", r.Host, r.HostPort)
		}
		hosts = append(hosts, r.Host)
	}
	for _, s := range nts.PublicServers {
		if !slices.Contains(hosts, s.Host) {
			t.Errorf("the NTS clock dials %s, the port map does not route it: %v", s.Host, hosts)
		}
	}
}
