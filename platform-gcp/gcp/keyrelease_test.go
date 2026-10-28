package gcp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/filestore"
)

const testKey = "projects/p/locations/l/keyRings/r/cryptoKeys/k"

// testKMS is the runner's KMS client against the fakes, as deploy.sh sets
// it up: the federated token of the WIF principal set, no service account.
func testKMS(t *testing.T, g *httptest.Server) *KMS {
	return &KMS{L: NewLauncher(fakeLauncher(t, 1)), HTTP: g.Client(),
		Provider: "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/q",
		Key:      testKey, STSURL: g.URL, IAMURL: g.URL, KMSURL: g.URL}
}

// encryptAs calls KMS encrypt with bearer token tok, as a principal other
// than the runner would, and returns the ciphertext or the HTTP status.
func encryptAs(t *testing.T, g *httptest.Server, tok string, plain, aad []byte) ([]byte, int) {
	t.Helper()
	req := map[string]string{"plaintext": base64.StdEncoding.EncodeToString(plain)}
	if aad != nil {
		req["additionalAuthenticatedData"] = base64.StdEncoding.EncodeToString(aad)
	}
	body, _ := json.Marshal(req)
	r, _ := http.NewRequest(http.MethodPost, g.URL+"/v1/"+testKey+":encrypt", bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+tok)
	resp, err := g.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode
	}
	var out struct{ Ciphertext string }
	json.NewDecoder(resp.Body).Decode(&out)
	ct, _ := base64.StdEncoding.DecodeString(out.Ciphertext)
	return ct, http.StatusOK
}

// A second setup on the same KMS key opens nothing of the first: the
// stored sealing data key does not decrypt under its AAD (the start
// stops), and no key the first wrapped through platform.Keys opens.
func TestAnotherSetupOpensNothing(t *testing.T) {
	g := fakeGoogle(t)
	defer g.Close()
	k := testKMS(t, g)
	ctx := context.Background()
	store, _ := filestore.New(t.TempDir())
	one, other := [32]byte{1}, [32]byte{2}
	if _, err := k.dataKey(ctx, store, one); err != nil {
		t.Fatal(err)
	}
	if _, err := k.dataKey(ctx, store, other); err == nil || !strings.Contains(err.Error(), "does not decrypt") {
		t.Fatalf("the second setup's start on the first setup's store: %v", err)
	}
	_, blob, err := Keys{K: k, Setup: one}.NewKey(ctx, []byte("mark key aad"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (Keys{K: k, Setup: other}).OpenKey(ctx, blob, []byte("mark key aad")); !errors.Is(err, platform.ErrNotAuthentic) {
		t.Fatalf("the second setup opened the first setup's wrapped key: %v", err)
	}
	if _, err := (Keys{K: k, Setup: one}).OpenKey(ctx, blob, []byte("mark key aad")); err != nil {
		t.Fatalf("the first setup: %v", err)
	}
	// The sealing key and the keys of platform.Keys have AADs of their own
	// contexts: a wrapped key does not pass for the sealing key.
	if err := store.Put(dekBlob, blob); err != nil {
		t.Fatal(err)
	}
	if _, err := k.dataKey(ctx, store, one); err == nil {
		t.Fatal("a key of platform.Keys passed for the sealing key")
	}
}

// Planting a data key (review A). Only the WIF principal set holds the
// encrypter role (deploy_test.go checks deploy.sh), so the key admin's
// encrypt is refused. A blob that a holder of the role made for another
// setup, or without the AAD as the runner made it before setup_hash, does
// not decrypt. The AAD is not secret: a principal that holds the role anyway
// (an admin who grants it to itself, an inherited binding) can make a blob
// that does. That is the limit review N accepts for GCP.
func TestPlantedDataKey(t *testing.T) {
	g := fakeGoogle(t)
	defer g.Close()
	k := testKMS(t, g)
	ctx := context.Background()
	setup := [32]byte{7}
	known := make([]byte, 32)
	rand.Read(known)

	if _, status := encryptAs(t, g, "admin-token", known, sealingAAD(setup)); status != http.StatusForbidden {
		t.Fatalf("the key admin's encrypt: status %d, want 403", status)
	}
	for name, aad := range map[string][]byte{"no AAD (before setup_hash)": nil, "another setup's AAD": sealingAAD([32]byte{8})} {
		blob, status := encryptAs(t, g, "federated", known, aad)
		if status != http.StatusOK {
			t.Fatalf("%s: encrypt status %d", name, status)
		}
		store, _ := filestore.New(t.TempDir())
		store.Put(dekBlob, blob)
		if dek, err := k.dataKey(ctx, store, setup); err == nil {
			t.Fatalf("%s: planted key accepted (%x)", name, dek)
		}
	}
	blob, _ := encryptAs(t, g, "federated", known, sealingAAD(setup))
	store, _ := filestore.New(t.TempDir())
	store.Put(dekBlob, blob)
	if dek, err := k.dataKey(ctx, store, setup); err != nil || !bytes.Equal(dek, known) {
		t.Fatalf("a holder of the role with the right AAD: %v", err)
	}
	t.Log("a holder of the encrypter role can still plant a data key with the public AAD: GCP stays outside the admin-proof goal (review N)")
}
