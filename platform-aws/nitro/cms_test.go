package nitro

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestDecryptOpenSSLEnvelopes builds CMS envelopes with the openssl CLI in
// the shape KMS is documented to use (one key-transport recipient by
// subject key identifier, RSAES-OAEP-SHA256, AES-256-CBC), in DER and in
// streamed BER, and opens them.
func TestDecryptOpenSSLEnvelopes(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "enclave"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		SubjectKeyId: []byte{1, 2, 3, 4, 5, 6, 7, 8},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{1, 32, 4096} {
		plain := make([]byte, size)
		rand.Read(plain)
		in := filepath.Join(dir, "plain")
		os.WriteFile(in, plain, 0o600)
		for _, stream := range []bool{false, true} {
			args := []string{"cms", "-encrypt", "-binary", "-in", in, "-recip", certPath, "-keyid", "-aes256",
				"-keyopt", "rsa_padding_mode:oaep", "-keyopt", "rsa_oaep_md:sha256", "-keyopt", "rsa_mgf1_md:sha256",
				"-outform", "DER"}
			if stream {
				args = append(args, "-stream")
			}
			out, err := exec.Command("openssl", args...).Output()
			if err != nil {
				t.Fatalf("openssl %v: %v", args, err)
			}
			got, err := DecryptEnvelopedData(out, key)
			if err != nil {
				t.Fatalf("size %d stream %v: %v", size, stream, err)
			}
			if !bytes.Equal(got, plain) {
				t.Fatalf("size %d stream %v: plaintext differs", size, stream)
			}
			// Indefinite lengths start with 0x30 0x80.
			t.Logf("size=%d stream=%v envelope=%d bytes indefinite=%v", size, stream, len(out), out[1] == 0x80)
			// AES-CBC has no integrity check, so flipping content bytes is
			// not detected here; TLS from KMS into the enclave covers that.
			// A wrong private key must fail.
			if _, err := DecryptEnvelopedData(out, otherKey); err == nil {
				t.Fatal("envelope opened with the wrong key")
			}
		}
	}
	// SHA-1 OAEP (openssl default) must be refused.
	in := filepath.Join(dir, "plain")
	out, err := exec.Command("openssl", "cms", "-encrypt", "-binary", "-in", in, "-recip", certPath, "-keyid",
		"-aes256", "-keyopt", "rsa_padding_mode:oaep", "-outform", "DER").Output()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptEnvelopedData(out, key); err == nil {
		t.Fatal("SHA-1 OAEP accepted")
	}
}
