package sealedimport

import (
	"bytes"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

func TestSealOpen(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	var id backend.Identity
	k.Fill(&id)
	kemID, kdfID, aeadID := Suite()
	t.Logf("suite kem=%#04x kdf=%#04x aead=%#04x, public key %d bytes", kemID, kdfID, aeadID, len(id.ImportKey))
	if kemID != 0x647a || len(id.ImportKey) != 1216 {
		t.Fatalf("expected the ML-KEM-768-X25519 hybrid KEM (0x647a, 1216-byte key), got %#04x and %d bytes", kemID, len(id.ImportKey))
	}
	secret := [32]byte{1, 2, 3, 4}
	req := backend.SealedImportRequest{Pubkey: backend.Pubkey{1}, SharePubkey: backend.Pubkey{2}, Index: 9}
	req.Sealed, err = Seal(&id, &req, &secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(req.Sealed, secret[:4]) {
		t.Fatal("secret visible in the sealed blob")
	}
	got, err := k.Open(&req)
	if err != nil || got != secret {
		t.Fatalf("open: %v", err)
	}

	// Any header change breaks the associated data.
	for name, mutate := range map[string]func(r *backend.SealedImportRequest){
		"index":        func(r *backend.SealedImportRequest) { r.Index = 10 },
		"pubkey":       func(r *backend.SealedImportRequest) { r.Pubkey[0] ^= 1 },
		"share pubkey": func(r *backend.SealedImportRequest) { r.SharePubkey[0] ^= 1 },
		"interchange":  func(r *backend.SealedImportRequest) { r.Interchange = &backend.Watermark{HasBlock: true, BlockSlot: 1} },
		"ciphertext": func(r *backend.SealedImportRequest) {
			r.Sealed = append([]byte(nil), r.Sealed...)
			r.Sealed[len(r.Sealed)-1] ^= 1
		},
	} {
		r := req
		mutate(&r)
		if _, err := k.Open(&r); err == nil {
			t.Fatalf("%s changed, open still worked", name)
		}
	}

	// A second key pair (another boot or a clone) cannot open it.
	k2, _ := Generate()
	if _, err := k2.Open(&req); err == nil {
		t.Fatal("other runner opened the share")
	}

	// A runner that offers a classical-only suite is refused.
	weak := id
	weak.ImportKEM = 0x0020
	if _, err := Seal(&weak, &req, &secret); err == nil {
		t.Fatal("downgraded suite accepted")
	}
}
