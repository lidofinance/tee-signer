package cloudroots

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRootsMatchPins loads every root: one PEM certificate, self-signed,
// a CA, and the pinned SHA-256.
func TestRootsMatchPins(t *testing.T) {
	seen := map[string]bool{}
	for p, rs := range roots {
		if len(rs) < 2 {
			t.Errorf("provider %d has %d roots, want 2 or more", p, len(rs))
		}
		for _, r := range rs {
			c, err := load(r)
			if err != nil {
				t.Fatal(err)
			}
			if sum := sha256.Sum256(c.Raw); hex.EncodeToString(sum[:]) != r.sha256 {
				t.Errorf("%s: sha256 %x", r.file, sum)
			}
			if !c.IsCA || c.CheckSignatureFrom(c) != nil {
				t.Errorf("%s: not a self-signed CA", r.file)
			}
			seen[r.file] = true
		}
	}
	files, _ := fs.Glob(rootFiles, "roots/*.pem")
	if len(files) != len(seen) {
		t.Errorf("%d embedded files, %d pinned", len(files), len(seen))
	}
}

func TestPoolRefusesOtherCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	for _, p := range []Provider{AWS, Google, Azure} {
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: Pool(p)}}}
		_, err := c.Get(srv.URL)
		if err == nil || !strings.Contains(err.Error(), "certificate signed by unknown authority") {
			t.Errorf("provider %d: got %v, want an unknown authority error", p, err)
		}
	}
}
