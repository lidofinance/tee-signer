package gcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/filestore"
)

// imageLauncher is fakeLauncher whose tokens carry the image digest, as
// the Confidential Space launcher's do (submods.container.image_digest).
func imageLauncher(t *testing.T, digest *string) string {
	sock := filepath.Join(t.TempDir(), "teeserver.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Audience string   `json:"audience"`
			Nonces   []string `json:"nonces"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			http.Error(w, "bad request", 400)
			return
		}
		w.Write([]byte(fakeJWT(map[string]any{"aud": req.Audience, "iat": 1, "eat_nonce": req.Nonces,
			"swname": "CONFIDENTIAL_SPACE", "submods": map[string]any{"container": map[string]any{"image_digest": *digest}}})))
	})}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return sock
}

// The runner's own image is the image digest of the token it sent to STS
// for the KMS key release. A token without a digest, or two digests, make
// the image unknown for good.
func TestSelfImageIsTheSTSTokenDigest(t *testing.T) {
	ctx := context.Background()
	digest := "sha256:" + strings.Repeat("c1", 32)
	l := NewLauncher(imageLauncher(t, &digest))
	g := fakeGoogle(t)
	defer g.Close()
	newKMS := func() *KMS {
		return &KMS{L: l, HTTP: g.Client(), Provider: "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/q",
			Key: "projects/p/locations/l/keyRings/r/cryptoKeys/k", STSURL: g.URL, IAMURL: g.URL, KMSURL: g.URL, Seen: &platform.ImageSeen{}}
	}
	k := newKMS()
	store, _ := filestore.New(t.TempDir())
	if _, err := k.dataKey(ctx, store, [32]byte{1}); err != nil {
		t.Fatal(err)
	}
	im, err := k.Seen.Get(ctx)
	if err != nil || im.Kind != setupwire.ImageGCP || !bytes.Equal(im.Measurement, bytes.Repeat([]byte{0xc1}, 32)) {
		t.Fatalf("image %s %x, %v", im.Kind, im.Measurement, err)
	}

	// Another digest on a later token.
	digest = "sha256:" + strings.Repeat("d2", 32)
	if _, err := k.dataKey(ctx, store, [32]byte{1}); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Seen.Get(ctx); err == nil || !strings.Contains(err.Error(), "two images") {
		t.Fatalf("two digests: %v", err)
	}

	// No digest of the right form.
	for _, d := range []string{"", "sha512:" + strings.Repeat("d2", 32), "sha256:" + strings.Repeat("d2", 31), "sha256:" + strings.Repeat("zz", 32)} {
		digest = d
		k := newKMS()
		if _, err := k.dataKey(ctx, store, [32]byte{1}); err != nil {
			t.Fatal(err)
		}
		if _, err := k.Seen.Get(ctx); err == nil || !strings.Contains(err.Error(), "image_digest") {
			t.Fatalf("digest %q: %v", d, err)
		}
	}
}
