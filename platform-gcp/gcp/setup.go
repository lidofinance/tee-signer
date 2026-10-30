package gcp

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/lidofinance/tee-signer/platform/setup"
)

// MetadataSetupURL is the instance metadata attribute that holds the setup,
// base64 of the binary form. Not a
// tee-env-* value: those go into every attestation token's claims. An
// attribute holds up to 256 KB, a setup at most 64 KB.
const MetadataSetupURL = "http://metadata.google.internal/computeMetadata/v1/instance/attributes/signer-setup"

// MetadataSetup is the GCP setup channel (runner/setup.Channel): the
// signer-setup attribute from the metadata server. The setup is not secret
// and the host can hand over any bytes; other bytes make another signer.
type MetadataSetup struct {
	URL   string        // MetadataSetupURL; tests use a fake
	HTTP  *http.Client  // nil: a client with a 10 s timeout
	Retry time.Duration // pause between tries; 0: 2 s
}

// maxAttribute bounds the answer: a setup's base64 and some white space.
const maxAttribute = 128 << 10

// Read gets the attribute. It tries again while the metadata server cannot
// be reached or answers 5xx, until ctx ends. A 404 (no such attribute) ends
// it at once.
func (m MetadataSetup) Read(ctx context.Context) ([]byte, error) {
	client := m.HTTP
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	retry := m.Retry
	if retry <= 0 {
		retry = 2 * time.Second
	}
	for {
		text, again, err := m.get(ctx, client)
		if err == nil {
			return setup.DecodeBase64("metadata attribute signer-setup", text)
		}
		if !again {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("no setup from the metadata server: %w", err)
		case <-time.After(retry):
		}
	}
}

func (m MetadataSetup) get(ctx context.Context, client *http.Client) (text []byte, again bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.URL, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := client.Do(req)
	if err != nil {
		return nil, true, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, false, fmt.Errorf("the instance has no metadata attribute signer-setup (gcp/deploy.sh sets it from the setup file)")
	case resp.StatusCode >= 500:
		return nil, true, fmt.Errorf("metadata server: %s", resp.Status)
	case resp.StatusCode != http.StatusOK:
		return nil, false, fmt.Errorf("metadata server: %s", resp.Status)
	case resp.Header.Get("Metadata-Flavor") != "Google":
		return nil, false, fmt.Errorf("the answer for signer-setup lacks Metadata-Flavor: Google")
	}
	text, err = io.ReadAll(io.LimitReader(resp.Body, maxAttribute+1))
	if err != nil {
		return nil, true, err
	}
	if len(text) > maxAttribute {
		return nil, false, fmt.Errorf("metadata attribute signer-setup: more than %d bytes", maxAttribute)
	}
	return text, false, nil
}

func (m MetadataSetup) String() string { return "metadata attribute signer-setup" }
