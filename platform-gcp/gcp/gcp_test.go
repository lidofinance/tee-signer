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
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/filestore"
	"github.com/lidofinance/tee-signer/platform/jwtclaims"
)

func fakeJWT(claims map[string]any) string {
	p, _ := json.Marshal(claims)
	return "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(p) + ".c2ln"
}

// fakeLauncher serves POST /v1/token on a unix socket like the
// Confidential Space launcher (request fields from Google's docs).
func fakeLauncher(t *testing.T, iat int64) string {
	sock := filepath.Join(t.TempDir(), "teeserver.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Audience  string   `json:"audience"`
			TokenType string   `json:"token_type"`
			Nonces    []string `json:"nonces"`
		}
		if r.URL.Path != "/v1/token" || json.NewDecoder(r.Body).Decode(&req) != nil || req.TokenType != "OIDC" {
			http.Error(w, "bad request", 400)
			return
		}
		w.Write([]byte(fakeJWT(map[string]any{"aud": req.Audience, "iat": iat, "eat_nonce": req.Nonces,
			"swname": "CONFIDENTIAL_SPACE"})))
	})}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return sock
}

// fakeGoogle plays STS, IAM credentials and Cloud KMS. KMS is AES-GCM under
// a key per KMS key name, with the request's additional authenticated
// data; a ciphertext that does not open is a 400, as Cloud KMS answers.
func fakeGoogle(t *testing.T) *httptest.Server {
	aeadFor := func(name string) cipher.AEAD {
		k := sha256.Sum256([]byte("fake kms|" + name))
		b, _ := aes.NewCipher(k[:])
		g, _ := cipher.NewGCM(b)
		return g
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/token":
			r.ParseForm()
			if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" ||
				!strings.HasPrefix(r.Form.Get("audience"), "//iam.googleapis.com/") || r.Form.Get("subject_token") == "" {
				http.Error(w, "bad sts request", 400)
				return
			}
			// Like the WIF provider of cloud/gcp/deploy.sh wif-create: only the STS audience.
			if c, err := jwtclaims.Claims(r.Form.Get("subject_token")); err != nil || c["aud"] != stsAudience {
				http.Error(w, "audience not allowed", 400)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"access_token": "federated"})
		case strings.HasSuffix(r.URL.Path, ":generateAccessToken"):
			if r.Header.Get("Authorization") != "Bearer federated" {
				http.Error(w, "unauthorized", 401)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"accessToken": "sa-token"})
		case strings.HasSuffix(r.URL.Path, ":encrypt"), strings.HasSuffix(r.URL.Path, ":decrypt"):
			if a := r.Header.Get("Authorization"); a != "Bearer sa-token" && a != "Bearer federated" {
				// Only the WIF principal set (deploy.sh) or the account it acts
				// as holds the encrypter role on the key.
				http.Error(w, `{"error":{"code":403,"status":"PERMISSION_DENIED"}}`, 403)
				return
			}
			name, op, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/v1/"), ":")
			g := aeadFor(name)
			var in map[string]string
			json.NewDecoder(r.Body).Decode(&in)
			aad, _ := base64.StdEncoding.DecodeString(in["additionalAuthenticatedData"])
			if op == "encrypt" {
				b, _ := base64.StdEncoding.DecodeString(in["plaintext"])
				nonce := make([]byte, g.NonceSize())
				rand.Read(nonce)
				json.NewEncoder(w).Encode(map[string]any{"ciphertext": base64.StdEncoding.EncodeToString(g.Seal(nonce, nonce, b, aad)), "verifiedPlaintextCrc32c": false, "protectionLevel": "SOFTWARE"})
				return
			}
			b, _ := base64.StdEncoding.DecodeString(in["ciphertext"])
			if len(b) < g.NonceSize() {
				http.Error(w, `{"error":{"code":400,"message":"Decryption failed: the ciphertext is invalid.","status":"INVALID_ARGUMENT"}}`, 400)
				return
			}
			p, err := g.Open(nil, b[:g.NonceSize()], b[g.NonceSize():], aad)
			if err != nil {
				http.Error(w, `{"error":{"code":400,"message":"Decryption failed: the ciphertext is invalid.","status":"INVALID_ARGUMENT"}}`, 400)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"plaintext": base64.StdEncoding.EncodeToString(p), "usedPrimary": true, "protectionLevel": "SOFTWARE"})
		default:
			http.NotFound(w, r)
		}
	}))
}

// The mark log's keys: KMS with aad, nothing in the store. Another aad or
// another KMS key is ErrNotAuthentic; KMS out of reach is another error.
func TestKeysAgainstFakes(t *testing.T) {
	l := NewLauncher(fakeLauncher(t, 1))
	g := fakeGoogle(t)
	defer g.Close()
	kmsOf := func(key string) *KMS {
		return &KMS{L: l, HTTP: g.Client(), Provider: "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/q",
			ServiceAccount: "signer@proj.iam.gserviceaccount.com", Key: key, STSURL: g.URL, IAMURL: g.URL, KMSURL: g.URL}
	}
	ctx := context.Background()
	aad := []byte("signer-mark-key-v1|signer-3")
	keys := Keys{K: kmsOf("projects/p/locations/l/keyRings/r/cryptoKeys/k")}
	k1, blob, err := keys.NewKey(ctx, aad)
	if err != nil || len(k1) != 32 {
		t.Fatal(err)
	}
	k2, err := Keys{K: kmsOf("projects/p/locations/l/keyRings/r/cryptoKeys/k")}.OpenKey(ctx, blob, aad)
	if err != nil || !bytes.Equal(k1, k2) {
		t.Fatalf("open: %v", err)
	}
	if _, err := keys.OpenKey(ctx, blob, []byte("signer-mark-key-v1|signer-4")); !errors.Is(err, platform.ErrNotAuthentic) {
		t.Fatalf("another aad: %v", err)
	}
	if _, err := (Keys{K: kmsOf("projects/p/locations/l/keyRings/r/cryptoKeys/other")}).OpenKey(ctx, blob, aad); !errors.Is(err, platform.ErrNotAuthentic) {
		t.Fatalf("another KMS key: %v", err)
	}
	down := kmsOf("projects/p/locations/l/keyRings/r/cryptoKeys/k")
	down.KMSURL = "http://127.0.0.1:1"
	if _, err := (Keys{K: down}).OpenKey(ctx, blob, aad); err == nil || errors.Is(err, platform.ErrNotAuthentic) {
		t.Fatalf("KMS out of reach: %v, want an error that is not ErrNotAuthentic", err)
	}
}

func TestFlowsAgainstFakes(t *testing.T) {
	iat := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC).Unix()
	l := NewLauncher(fakeLauncher(t, iat))
	g := fakeGoogle(t)
	defer g.Close()
	k := &KMS{L: l, HTTP: g.Client(), Provider: "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/q",
		ServiceAccount: "signer@proj.iam.gserviceaccount.com", Key: "projects/p/locations/l/keyRings/r/cryptoKeys/k",
		STSURL: g.URL, IAMURL: g.URL, KMSURL: g.URL}
	store, _ := filestore.New(t.TempDir())
	ctx := context.Background()
	d1, err := k.dataKey(ctx, store, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	d2, err := k.dataKey(ctx, store, [32]byte{1})
	if err != nil || !bytes.Equal(d1, d2) || len(d1) != 32 {
		t.Fatalf("data key not stable: %v", err)
	}
	a, err := (&Attester{L: l, Audience: DefaultIdentityAudience}).Attest(ctx, nil, []byte{1, 2, 3})
	if err != nil || !strings.Contains(string(a.Document), ".") {
		t.Fatal(a, err)
	}
	c, err := jwtclaims.Claims(string(a.Document))
	if err != nil || c["aud"] != DefaultIdentityAudience {
		t.Fatalf("identity token audience %v, %v", c["aud"], err)
	}
	// The identity token handed to clients is not one the STS fake (the
	// WIF provider) takes.
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "audience": {k.Provider},
		"subject_token": {string(a.Document)}}
	resp, err := g.Client().PostForm(g.URL+"/v1/token", form)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("STS fake took the identity token: %s", resp.Status)
	}
	tm, err := TokenTime{L: l, Audience: "https://signer.example"}.Fetch(ctx)
	if err != nil || tm.Unix() != iat {
		t.Fatal(tm, err)
	}
	if _, err := (&Attester{L: l, Audience: stsAudience}).Attest(ctx, nil, []byte{1}); err == nil {
		t.Fatal("attester with the STS audience made a token")
	}
	if _, err := (TokenTime{L: l, Audience: stsAudience}).Fetch(ctx); err == nil {
		t.Fatal("token-iat clock with the STS audience made a token")
	}
}

func TestIdentityAudience(t *testing.T) {
	for _, aud := range []string{"", " ", stsAudience, stsAudience + "/", "HTTPS://STS.googleapis.com", "sts.googleapis.com",
		"//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/q",
		"https://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/q"} {
		if CheckIdentityAudience(aud) == nil {
			t.Errorf("audience %q accepted", aud)
		}
	}
	for _, aud := range []string{DefaultIdentityAudience, "https://signer.example"} {
		if err := CheckIdentityAudience(aud); err != nil {
			t.Errorf("audience %q refused: %v", aud, err)
		}
	}
	got, err := identityAudience(platform.Options{})
	if err != nil || got != DefaultIdentityAudience {
		t.Fatalf("default audience %q, %v", got, err)
	}
	got, err = identityAudience(platform.Options{Params: map[string]string{"attest_audience": "https://signer.example"}})
	if err != nil || got != "https://signer.example" {
		t.Fatalf("set audience %q, %v", got, err)
	}
	// New refuses the STS audience before it talks to anything: the socket
	// does not exist and no Google endpoint is reached.
	_, err = New(platform.Options{StateDir: t.TempDir(), Params: map[string]string{
		"attest_audience": stsAudience, "socket": filepath.Join(t.TempDir(), "none.sock"),
		"wif_provider": "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/q",
		"kms_key":      "projects/p/locations/l/keyRings/r/cryptoKeys/k"}})
	if err == nil || !strings.Contains(err.Error(), "STS audience") {
		t.Fatalf("New with the STS audience: %v", err)
	}
}
