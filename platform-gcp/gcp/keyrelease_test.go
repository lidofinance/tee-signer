package gcp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
	if _, _, err := k.dataKey(ctx, store, one); err != nil {
		t.Fatal(err)
	}
	store.Put(sharePrefix+"aa01", []byte("sealed share"))
	if _, _, err := k.dataKey(ctx, store, other); err == nil || !strings.Contains(err.Error(), "does not decrypt") {
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
	if _, _, err := k.dataKey(ctx, store, one); err == nil {
		t.Fatal("a key of platform.Keys passed for the sealing key")
	}
}

// Planting a data key. Only the WIF principal set holds the encrypter role
// (deploy_test.go checks deploy.sh), so the key admin's encrypt is refused.
// A blob that a holder of the role made for another setup, or without the
// AAD as the runner made it before setup_hash, does not decrypt. The AAD
// is not secret: a principal that holds the role anyway (an admin who
// grants it to itself, an inherited binding) can make a blob that does.
// Next to a share the platform takes it but reports it as stored, so the
// runner needs every stored share to open under it (planting_test.go);
// without a share it is set aside. That stops a holder of encrypt alone.
// A holder of decrypt needs no planted key, it opens the stored one: GCP
// stays outside the admin-proof goal.
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
		store.Put(sharePrefix+"aa01", []byte("sealed share"))
		if dek, _, err := k.dataKey(ctx, store, setup); err == nil {
			t.Fatalf("%s: planted key accepted (%x)", name, dek)
		}
	}
	blob, _ := encryptAs(t, g, "federated", known, sealingAAD(setup))
	store, _ := filestore.New(t.TempDir())
	store.Put(dekBlob, blob)
	store.Put(sharePrefix+"aa01", []byte("sealed share"))
	if dek, stored, err := k.dataKey(ctx, store, setup); err != nil || !bytes.Equal(dek, known) || !stored {
		t.Fatalf("a holder of the role with the right AAD, next to a share: stored %v, %v", stored, err)
	}
}

// The runner releases its key only through the WIF provider and KMS key of
// the project it runs in, as its launcher token names it (submods.gce): a
// setup that names another project's provider or key gets no token to STS
// and no key. The KMS key may name the project by ID or by number.
func TestKeyReleaseStaysInTheRunnersProject(t *testing.T) {
	g := fakeGoogle(t)
	defer g.Close()
	ctx := context.Background()
	for _, c := range []struct {
		name, provider, key, err string
	}{
		{"own project", "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/q", testKey, ""},
		{"key by project number", "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/q",
			"projects/1/locations/l/keyRings/r/cryptoKeys/k", ""},
		{"provider of another project", "//iam.googleapis.com/projects/2/locations/global/workloadIdentityPools/p/providers/q", testKey,
			"wif_provider"},
		{"key of another project", "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/q",
			"projects/other/locations/l/keyRings/r/cryptoKeys/k", "kms_key"},
		{"provider not a WIF resource", "projects/1/locations/global/workloadIdentityPools/p/providers/q", testKey, "wif_provider"},
		{"key path out of the project", "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/q",
			"projects/p/../../v1/projects/other/locations/l/keyRings/r/cryptoKeys/k", "kms_key"},
		{"key with more segments", "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/q",
			testKey + "/cryptoKeyVersions/1", "kms_key"},
		{"provider with more segments", "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/q/x", testKey,
			"wif_provider"},
	} {
		k := testKMS(t, g)
		k.Provider, k.Key = c.provider, c.key
		store, _ := filestore.New(t.TempDir())
		_, _, err := k.dataKey(ctx, store, [32]byte{1})
		switch {
		case c.err == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
			t.Errorf("%s: %v, want an error naming %s", c.name, err, c.err)
		}
	}
}

// With the setup's project_number the VM must run in that project (the
// launcher token's project number): then a KMS key named by project ID,
// which checkProject matches to the token's project ID, is in the setup's
// project too. Cloud KMS takes that form only (rv-d18).
func TestKeyReleaseKeyByIDNeedsTheSetupsProject(t *testing.T) {
	g := fakeGoogle(t)
	defer g.Close()
	for _, c := range []struct{ name, number, err string }{
		{"setup project_number is the VM's", "1", ""},
		{"setup project_number of another project", "2", "setup's project_number"},
	} {
		k := testKMS(t, g)
		k.Provider, k.Key, k.ProjectNumber = "//iam.googleapis.com/projects/"+c.number+"/locations/global/workloadIdentityPools/p/providers/q", testKey, c.number
		if err := checkSetupProject(k.Provider, k.Key, k.ProjectNumber); err != nil {
			t.Fatalf("%s: the setup check refuses a key by project ID: %v", c.name, err)
		}
		store, _ := filestore.New(t.TempDir())
		_, _, err := k.dataKey(context.Background(), store, [32]byte{1})
		switch {
		case c.err == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
			t.Errorf("%s: %v, want an error naming %s", c.name, err, c.err)
		}
	}
}

// A launcher token without the project claims releases no key. A project
// number given as a JSON number instead of a string is read.
func TestKeyReleaseNeedsTheProjectClaims(t *testing.T) {
	g := fakeGoogle(t)
	defer g.Close()
	for _, c := range []struct {
		name    string
		submods map[string]any
		err     string
	}{
		{"no submods.gce", nil, "submods.gce"},
		{"no project_number", map[string]any{"gce": map[string]any{"project_id": "p"}}, "submods.gce"},
		{"project_number as a number", map[string]any{"gce": map[string]any{"project_id": "p", "project_number": 1}}, ""},
	} {
		sock := filepath.Join(t.TempDir(), "teeserver.sock")
		l, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(fakeJWT(map[string]any{"aud": stsAudience, "iat": 1, "swname": "CONFIDENTIAL_SPACE", "submods": c.submods})))
		})}
		go srv.Serve(l)
		t.Cleanup(func() { srv.Close() })
		k := testKMS(t, g)
		k.L = NewLauncher(sock)
		_, err = k.accessToken(context.Background())
		switch {
		case c.err == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
			t.Errorf("%s: %v, want an error naming %s", c.name, err, c.err)
		}
	}
}
