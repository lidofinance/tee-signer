package gcp

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lidofinance/tee-signer/platform/filestore"
	"github.com/lidofinance/tee-signer/platform/jwtclaims"
)

// The KMS role on the WIF pool's principal set (cloud/gcp/deploy.sh
// kms-bind): the runner calls KMS and the buckets with the federated token
// from STS itself, with no service account in between. The fake KMS takes
// only that token, the IAM credentials endpoint counts calls (there must be
// none), and a service account's own token (what an unmeasured VM that
// runs as the account gets from its metadata server) is refused.
func TestFederatedTokenWithoutServiceAccount(t *testing.T) {
	var iamCalls atomic.Int32
	k32 := sha256.Sum256([]byte("fake kms"))
	b, _ := aes.NewCipher(k32[:])
	g, _ := cipher.NewGCM(b)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/token":
			r.ParseForm()
			c, err := jwtclaims.Claims(r.Form.Get("subject_token"))
			if err != nil || c["aud"] != stsAudience || r.Form.Get("requested_token_type") != "urn:ietf:params:oauth:token-type:access_token" {
				http.Error(w, "bad sts request", 400)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"access_token": "federated-principal-set"})
		case strings.Contains(r.URL.Path, ":generateAccessToken"):
			iamCalls.Add(1)
			http.Error(w, "the principal set has no roles/iam.workloadIdentityUser on any account", 403)
		case strings.HasSuffix(r.URL.Path, ":encrypt"), strings.HasSuffix(r.URL.Path, ":decrypt"):
			if r.Header.Get("Authorization") != "Bearer federated-principal-set" {
				http.Error(w, `{"error":{"code":403,"status":"PERMISSION_DENIED"}}`, 403)
				return
			}
			var in map[string]string
			json.NewDecoder(r.Body).Decode(&in)
			aad, _ := base64.StdEncoding.DecodeString(in["additionalAuthenticatedData"])
			if strings.HasSuffix(r.URL.Path, ":encrypt") {
				p, _ := base64.StdEncoding.DecodeString(in["plaintext"])
				n := make([]byte, g.NonceSize())
				rand.Read(n)
				json.NewEncoder(w).Encode(map[string]any{"ciphertext": base64.StdEncoding.EncodeToString(g.Seal(n, n, p, aad)), "verifiedPlaintextCrc32c": false, "protectionLevel": "SOFTWARE"})
				return
			}
			c, _ := base64.StdEncoding.DecodeString(in["ciphertext"])
			p, err := g.Open(nil, c[:g.NonceSize()], c[g.NonceSize():], aad)
			if err != nil {
				http.Error(w, "Decryption failed", 400)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"plaintext": base64.StdEncoding.EncodeToString(p), "usedPrimary": true, "protectionLevel": "SOFTWARE"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	k := &KMS{L: NewLauncher(fakeLauncher(t, 1)), HTTP: srv.Client(),
		Provider: "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/q",
		Key:      "projects/p/locations/l/keyRings/r/cryptoKeys/k", STSURL: srv.URL, IAMURL: srv.URL, KMSURL: srv.URL}

	tok, err := k.accessToken(ctx)
	if err != nil || tok != "federated-principal-set" {
		t.Fatalf("storage and KMS token %q, %v: want the federated token itself", tok, err)
	}
	store, _ := filestore.New(t.TempDir())
	d1, err := k.dataKey(ctx, store, [32]byte{3})
	if err != nil {
		t.Fatal(err)
	}
	d2, err := k.dataKey(ctx, store, [32]byte{3})
	if err != nil || !bytes.Equal(d1, d2) {
		t.Fatalf("data key through the federated token: %v", err)
	}
	key, blob, err := (Keys{K: k}).NewKey(ctx, []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if again, err := (Keys{K: k}).OpenKey(ctx, blob, []byte("aad")); err != nil || !bytes.Equal(again, key) {
		t.Fatalf("record key: %v", err)
	}
	if n := iamCalls.Load(); n != 0 {
		t.Fatalf("%d calls to the IAM credentials API without service_account", n)
	}

	// With service_account set the runner impersonates; the setup grants
	// no impersonation, so key release fails instead of using the account.
	sa := *k
	sa.ServiceAccount = "signer-workload@p.iam.gserviceaccount.com"
	if _, err := sa.dataKey(ctx, store, [32]byte{3}); err == nil {
		t.Fatal("impersonation worked although the principal set may not act as the account")
	}
	if iamCalls.Load() == 0 {
		t.Fatal("service_account did not go through impersonation")
	}
}
