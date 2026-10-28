//go:build debugimport

package nitro

// Debug build only (-tags platform_aws,debugimport, the
// runner-aws-debugimport binary): one option that lets a test run the
// runner's nitro code path on a machine without an enclave, KMS or a host
// agent.
//
//	test_nsm_url=<URL>  the NSM document comes from a POST to this URL
//	                    instead of /dev/nsm. The body is JSON with the
//	                    base64 members "nonce" and "user_data"; the answer
//	                    is the COSE_Sign1 document, raw. The platform is
//	                    named nitro and attests like it, but seals with the
//	                    dev platform's public key, stores in -state-dir and
//	                    takes the dev options (clock_offset).
//
// With test_nsm_url, the release options proxy= and ntp_relay= work as in
// the enclave: HTTPS and NTS-KE through the proxy routes, NTP through the
// relay, over any transport (tcp: in the tests). Without them the dev
// platform's network is used.
//
// Release builds have no such option (hooks_release.go). The aws-nitro test
// in attest/runnerclient (nitro_e2e_test.go) uses it, with documents from
// attest/internal/testgen.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/dev"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

type fakeNSM struct {
	url    string
	client *http.Client
}

func (f fakeNSM) Attest(ctx context.Context, nonce, userData []byte) (*backend.Attestation, error) {
	body, err := json.Marshal(map[string][]byte{"nonce": nonce, "user_data": userData})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	doc, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nitro: fake NSM: %s: %s", resp.Status, doc)
	}
	return attestation(doc, userData), nil
}

func debugPlatform(o platform.Options) (*platform.Platform, bool, error) {
	url := o.Param("test_nsm_url", "")
	if url == "" {
		return nil, false, nil
	}
	p, err := dev.New(o)
	if err != nil {
		return nil, true, err
	}
	p.Name = "nitro"
	fake := fakeNSM{url: url, client: &http.Client{Timeout: 10 * time.Second}}
	p.Attester = fake
	// No KMS here (the dev platform seals), so no recipient document: the
	// image is the PCRs of a fresh fake document.
	p.SelfImage = func(ctx context.Context) (setupwire.Image, error) {
		a, err := fake.Attest(ctx, []byte("signer-runner self image"), nil)
		if err != nil {
			return setupwire.Image{}, err
		}
		return documentImage(a.Document)
	}
	if o.Param("proxy", "") != "" || o.Param("ntp_relay", "") != "" {
		routes, relay, err := netOptions(o)
		if err != nil {
			return nil, true, err
		}
		p.HTTPClient = ProxyClient(routes)
		p.Dial = NetDial(routes, relay)
	}
	return p, true, nil
}
