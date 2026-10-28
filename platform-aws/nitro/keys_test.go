package nitro

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/lidofinance/tee-signer/platform"
)

// fakeKMS answers GenerateDataKey and Decrypt with a recipient, as KMS does
// for an enclave: the ciphertext blob is AES-GCM under a key per KMS key
// ID with the encryption context as aad, the plaintext goes back only as a
// CMS envelope to the recipient (made with the openssl CLI, as in
// cms_test.go). A blob that does not open is InvalidCiphertextException.
// Encrypt (no recipient) is the key admin's call: adminMay, if set, is the
// key policy's condition on it (planting_test.go), and a context it
// refuses gets AccessDeniedException.
type fakeKMS struct {
	t        *testing.T
	certPath string // the recipient's certificate, for openssl
	encrypts int
	adminMay func(context map[string]string) bool
}

func (f *fakeKMS) aead(keyID string) cipher.AEAD {
	k := sha256.Sum256([]byte("fake kms|" + keyID))
	b, _ := aes.NewCipher(k[:])
	g, _ := cipher.NewGCM(b)
	return g
}

func contextAAD(c map[string]string) []byte { b, _ := json.Marshal(c); return b } // sorted keys

func (f *fakeKMS) envelope(plain []byte) []byte {
	dir := f.t.TempDir()
	in := filepath.Join(dir, "plain")
	os.WriteFile(in, plain, 0o600)
	out, err := exec.Command("openssl", "cms", "-encrypt", "-binary", "-in", in, "-recip", f.certPath, "-keyid", "-aes256",
		"-keyopt", "rsa_padding_mode:oaep", "-keyopt", "rsa_oaep_md:sha256", "-keyopt", "rsa_mgf1_md:sha256", "-outform", "DER").Output()
	if err != nil {
		f.t.Errorf("openssl: %v", err)
	}
	return out
}

func (f *fakeKMS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fail := func(typ string) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"__type": typ, "message": typ})
	}
	var in struct {
		KeyId             string
		CiphertextBlob    []byte
		Plaintext         []byte
		EncryptionContext map[string]string
		Recipient         *struct{ AttestationDocument []byte }
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail("ValidationException")
		return
	}
	g := f.aead(in.KeyId)
	if r.Header.Get("X-Amz-Target") == "TrentService.Encrypt" {
		if f.adminMay == nil || !f.adminMay(in.EncryptionContext) {
			fail("AccessDeniedException")
			return
		}
		nonce := make([]byte, g.NonceSize())
		rand.Read(nonce)
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		json.NewEncoder(w).Encode(map[string]any{"KeyId": in.KeyId, "CiphertextBlob": g.Seal(nonce, nonce, in.Plaintext, contextAAD(in.EncryptionContext))})
		return
	}
	if in.Recipient == nil || len(in.Recipient.AttestationDocument) == 0 {
		fail("ValidationException") // GenerateDataKey and Decrypt: this fake serves enclaves only
		return
	}
	var plain, blob []byte
	switch r.Header.Get("X-Amz-Target") {
	case "TrentService.GenerateDataKey":
		plain = make([]byte, 32)
		rand.Read(plain)
		nonce := make([]byte, g.NonceSize())
		rand.Read(nonce)
		blob = g.Seal(nonce, nonce, plain, contextAAD(in.EncryptionContext))
		f.encrypts++
	case "TrentService.Decrypt":
		b := in.CiphertextBlob
		var err error
		if len(b) < g.NonceSize() {
			fail("InvalidCiphertextException")
			return
		}
		if plain, err = g.Open(nil, b[:g.NonceSize()], b[g.NonceSize():], contextAAD(in.EncryptionContext)); err != nil {
			fail("InvalidCiphertextException")
			return
		}
	default:
		fail("UnknownOperationException")
		return
	}
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	json.NewEncoder(w).Encode(map[string]any{"KeyId": in.KeyId, "CiphertextBlob": blob, "CiphertextForRecipient": f.envelope(plain)})
}

var staticCreds = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
	return aws.Credentials{AccessKeyID: "AKID", SecretAccessKey: "secret"}, nil
})

func TestKeysAgainstFakeKMS(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "enclave"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), SubjectKeyId: []byte{1, 2, 3, 4}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rsaKey.PublicKey, rsaKey)
	certPath := filepath.Join(t.TempDir(), "cert.pem")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	f := &fakeKMS{t: t, certPath: certPath}
	srv := httptest.NewServer(f)
	defer srv.Close()
	client := kms.New(kms.Options{Region: "eu-central-1", BaseEndpoint: aws.String(srv.URL),
		Credentials: staticCreds, HTTPClient: srv.Client()})
	recipient := func() (*rsa.PrivateKey, *types.RecipientInfo, error) {
		return rsaKey, &types.RecipientInfo{AttestationDocument: []byte("nsm document"),
			KeyEncryptionAlgorithm: types.KeyEncryptionMechanismRsaesOaepSha256}, nil
	}
	keysOf := func(keyID string) Keys { return Keys{Client: client, KeyID: keyID, Recipient: recipient} }
	ctx := context.Background()
	aad := []byte("signer-mark-key-v1|signer-2")
	k1, blob, err := keysOf("key-1").NewKey(ctx, aad)
	if err != nil || len(k1) != 32 {
		t.Fatalf("new key: %v", err)
	}
	k2, err := keysOf("key-1").OpenKey(ctx, blob, aad)
	if err != nil || !bytes.Equal(k1, k2) {
		t.Fatalf("open: %v", err)
	}
	if _, err := keysOf("key-1").OpenKey(ctx, blob, []byte("signer-mark-key-v1|signer-3")); !errors.Is(err, platform.ErrNotAuthentic) {
		t.Fatalf("another context: %v", err)
	}
	if _, err := keysOf("key-2").OpenKey(ctx, blob, aad); !errors.Is(err, platform.ErrNotAuthentic) {
		t.Fatalf("another KMS key: %v", err)
	}
	down := Keys{Client: kms.New(kms.Options{Region: "eu-central-1", BaseEndpoint: aws.String("http://127.0.0.1:1"),
		Credentials: staticCreds, RetryMaxAttempts: 1}), KeyID: "key-1", Recipient: recipient}
	if _, err := down.OpenKey(ctx, blob, aad); err == nil || errors.Is(err, platform.ErrNotAuthentic) || !strings.Contains(err.Error(), "Decrypt") {
		t.Fatalf("KMS out of reach: %v, want an error that is not ErrNotAuthentic", err)
	}
}
