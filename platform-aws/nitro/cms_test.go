package nitro

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
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

// nested is depth constructed elements with the identifier byte id, each
// of indefinite length, around an empty OCTET STRING.
func nested(id byte, depth int) []byte {
	b := bytes.Repeat([]byte{id, 0x80}, depth)
	b = append(b, 0x04, 0x00)
	return append(b, bytes.Repeat([]byte{0, 0}, depth)...)
}

// chunked is the OCTET STRING "x" inside depth constructed OCTET STRINGs
// of definite length.
func chunked(depth int) []byte {
	b := []byte{0x04, 0x01, 'x'}
	for range depth {
		n := len(b)
		b = append([]byte{0x24, 0x84, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}, b...)
	}
	return b
}

// The BER reader walks at most maxBERDepth constructed levels, in
// indefinite lengths (readTLV) and in constructed OCTET STRINGs (octets),
// so a crafted envelope cannot recurse without bound.
func TestBERDepthCap(t *testing.T) {
	for _, id := range []byte{0x30, 0x24} { // SEQUENCE, constructed OCTET STRING
		if _, _, err := readTLV(nested(id, maxBERDepth)); err != nil {
			t.Errorf("%#x nested %d deep: %v", id, maxBERDepth, err)
		}
		for _, d := range []int{maxBERDepth + 1, 1000} {
			if _, _, err := readTLV(nested(id, d)); !errors.Is(err, errBERDepth) {
				t.Errorf("%#x nested %d deep: %v, want %v", id, d, err, errBERDepth)
			}
		}
	}
	ot, _, err := readTLV(chunked(maxBERDepth))
	if err != nil {
		t.Fatal(err)
	}
	if v, err := ot.octets(); err != nil || string(v) != "x" {
		t.Errorf("OCTET STRING nested %d deep: %q %v", maxBERDepth, v, err)
	}
	for _, d := range []int{maxBERDepth + 1, 1000} {
		ot, _, err := readTLV(chunked(d))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ot.octets(); !errors.Is(err, errBERDepth) {
			t.Errorf("OCTET STRING nested %d deep: %v, want %v", d, err, errBERDepth)
		}
	}
}
