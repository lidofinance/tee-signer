package e2e

// The GCP sealing data key in the store (platform-gcp/gcp dataKey): who
// holds cryptoKeyEncrypterDecrypter on the KMS key can wrap a key it knows
// under the public sealing AAD and plant the blob.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// The GCP debug build on the flag path: a blob planted before the first
// start is set aside and the runner makes its own key; a planted blob
// with a planted share stops the start; a runner restarts on its own blob
// and shares.
func TestE2EGCPPlantedSealingKey(t *testing.T) {
	c := newChain(t)
	const image = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	g := fakeGoogle(t, image)
	const kmsKey = "projects/p/locations/l/keyRings/r/cryptoKeys/sealing"
	gcp := func(name string) (*runner, string) {
		sock := filepath.Join(t.TempDir(), name+".sock")
		r := newRunnerOn(t, runnerBinary(t, "gcp-debug"), name, c, "unix:"+sock, "-platform", "gcp",
			"-mark-store", "none",
			"-platform-opt", "socket="+fakeLauncher(t, image),
			"-platform-opt", "wif_provider=//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/q",
			"-platform-opt", "kms_key="+kmsKey,
			"-platform-opt", "test_google_url="+g.URL)
		return r, "unix:" + sock
	}
	blobPath := func(r *runner) string { return filepath.Join(r.stateDir, "sealing", "dek.gcpkms") }
	// A holder of the encrypter role wraps a key it knows under the
	// sealing AAD of the flag path (setup_hash zero).
	plant := func(r *runner) []byte {
		t.Helper()
		var setup [32]byte
		body, _ := json.Marshal(map[string]string{
			"plaintext":                   base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32)),
			"additionalAuthenticatedData": base64.StdEncoding.EncodeToString(setupwire.CtxGCPSealing.Message(setup[:]))})
		req, _ := http.NewRequest(http.MethodPost, g.URL+"/v1/"+kmsKey+":encrypt", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer federated")
		resp, err := g.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out struct{ Ciphertext string }
		json.NewDecoder(resp.Body).Decode(&out)
		blob, err := base64.StdEncoding.DecodeString(out.Ciphertext)
		if err != nil || len(blob) == 0 {
			t.Fatalf("plant: %s %v", resp.Status, err)
		}
		os.MkdirAll(filepath.Dir(blobPath(r)), 0o700)
		if err := os.WriteFile(blobPath(r), blob, 0o600); err != nil {
			t.Fatal(err)
		}
		return blob
	}

	// A planted blob and a planted share: the start stops.
	junk, _ := gcp("gcp-planted-share")
	plant(junk)
	os.MkdirAll(filepath.Join(junk.stateDir, "shares"), 0o700)
	os.WriteFile(filepath.Join(junk.stateDir, "shares", strings.Repeat("aa", 48)), []byte("anything the planter wrote"), 0o600)
	junk.start()
	if !waitExit(t, junk, 20*time.Second) || !strings.Contains(junk.logText(), "opens 0 of 1 stored shares") {
		t.Fatal("a runner started on a planted blob with a planted share")
	}
	t.Logf("planted blob and share: %s", lastLine(junk.logText(), "runner:"))

	// A planted blob on a store without shares: set aside, a new key.
	r, addr := gcp("gcp-planted")
	planted := plant(r)
	r.start()
	waitReady(t, client(t, addr))
	if b, err := os.ReadFile(blobPath(r)); err != nil || bytes.Equal(b, planted) {
		t.Fatalf("the runner kept the planted blob: %v", err)
	}
	if m, _ := filepath.Glob(blobPath(r) + ".ignored-*"); len(m) != 1 {
		t.Fatalf("set-aside copies: %v", m)
	}
	sk, _ := software.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	if _, err := adminOf(client(t, addr)).ImportShareSealed(ctx, backend.ImportShareRequest{Pubkey: pk, Secret: sk, Index: 7}, pk, acceptAny); err != nil {
		t.Fatal(err)
	}
	r.stop()

	// The restart takes the runner's own blob: its share opens under it.
	r.start()
	h := waitReady(t, client(t, addr))
	if h.LoadFailed != "" || h.Validators != 1 {
		t.Fatalf("restart: %d validators, %q", h.Validators, h.LoadFailed)
	}
	t.Logf("planted blob without shares: set aside; restart on the own blob and share: ready")
}
