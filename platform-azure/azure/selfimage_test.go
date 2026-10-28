package azure

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform"
)

// The runner's own image is the hostdata of the MAA token Key Vault
// released the key against (the fake SNP report's HOST_DATA, through the
// fake MAA). A release whose token names another hostdata makes the image
// unknown for good.
func TestSelfImageIsTheReleaseTokenHostData(t *testing.T) {
	ctx := context.Background()
	f := newKVFixture(t)
	seen := &platform.ImageSeen{}
	f.releaser.Seen = seen
	if _, err := seen.Get(ctx); err == nil {
		t.Fatal("an image before any key release")
	}
	if _, err := f.releaser.ReleaseKey(ctx, "signer-kek-1"); err != nil {
		t.Fatal(err)
	}
	im, err := seen.Get(ctx)
	if err != nil || im.Kind != setupwire.ImageAzure || !bytes.Equal(im.Measurement, bytes.Repeat([]byte{0x5a}, 32)) {
		t.Fatalf("image %s %x, %v", im.Kind, im.Measurement, err)
	}

	// The same group again: the same image.
	if _, err := f.releaser.ReleaseKey(ctx, "signer-kek-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := seen.Get(ctx); err != nil {
		t.Fatal(err)
	}
	// A token with another hostdata (the release policy here takes any).
	f.kv.hostData = ""
	copy(f.maa.reports.hostData[:], bytes.Repeat([]byte{0x6b}, 32))
	if _, err := f.releaser.ReleaseKey(ctx, "signer-kek-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := seen.Get(ctx); err == nil || !strings.Contains(err.Error(), "two images") {
		t.Fatalf("two hostdata values: %v", err)
	}
}

func TestTokenImage(t *testing.T) {
	key := testRSA(t)
	for _, c := range []struct {
		name   string
		claims map[string]any
		want   string
	}{
		{"no hostdata", map[string]any{"iss": "x"}, "is not 32 bytes of hex"},
		{"short", map[string]any{"x-ms-sevsnpvm-hostdata": "5a5a"}, "is not 32 bytes of hex"},
		{"not hex", map[string]any{"x-ms-sevsnpvm-hostdata": strings.Repeat("zz", 32)}, "is not 32 bytes of hex"},
	} {
		if _, err := tokenImage(signJWT(t, key, c.claims)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: %v", c.name, err)
		}
	}
	if _, err := tokenImage("not a token"); err == nil {
		t.Fatal("a token that does not parse")
	}
	im, err := tokenImage(signJWT(t, key, map[string]any{"x-ms-sevsnpvm-hostdata": strings.Repeat("AB", 32)}))
	if err != nil || im.Kind != setupwire.ImageAzure || !bytes.Equal(im.Measurement, bytes.Repeat([]byte{0xab}, 32)) {
		t.Fatalf("%s %x, %v", im.Kind, im.Measurement, err)
	}
}
