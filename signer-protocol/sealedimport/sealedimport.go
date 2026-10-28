// Package sealedimport encrypts a threshold share to a runner's attested
// import key with HPKE (RFC 9180) and opens it inside the runner.
//
// Suite: KEM ML-KEM-768 + X25519 hybrid (X-Wing, draft-ietf-hpke-pq), KDF
// HKDF-SHA256, AEAD AES-256-GCM, all from Go's standard library crypto/hpke
// (Go 1.26 or newer). The runner generates the key pair at start and keeps
// the private key in memory only, so a share sealed for one boot cannot be
// opened by a restarted or cloned runner.
//
// The associated data is the request header (wireadmin.SealedHeader): validator
// key, share public key, index and interchange maxima. The host cannot
// change any of them without the open failing.
package sealedimport

import (
	"crypto/hpke"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/lidofinance/tee-signer/signer-protocol"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

const info = "signer-share-import-v1"

var (
	kem  = hpke.MLKEM768X25519()
	kdf  = hpke.HKDFSHA256()
	aead = hpke.AES256GCM()
)

// Suite returns the KEM, KDF and AEAD identifiers this package uses.
func Suite() (kemID, kdfID, aeadID uint16) { return kem.ID(), kdf.ID(), aead.ID() }

// Key is the runner's import key pair.
type Key struct {
	priv hpke.PrivateKey
	pub  []byte
}

// Generate makes a fresh key pair.
func Generate() (*Key, error) {
	priv, err := kem.GenerateKey()
	if err != nil {
		return nil, err
	}
	return &Key{priv: priv, pub: priv.PublicKey().Bytes()}, nil
}

// PublicKey is the serialized public key that goes into Identity.ImportKey.
func (k *Key) PublicKey() []byte { return append([]byte(nil), k.pub...) }

// Fill sets the import fields of id.
func (k *Key) Fill(id *backend.Identity) {
	id.ImportKEM, id.ImportKDF, id.ImportAEAD = Suite()
	id.ImportKey = k.PublicKey()
}

// Seal encrypts secret to the import key in id. The caller must have
// verified id (attestation document, measurements, nonce) first. req.Sealed
// is ignored; the result goes there.
func Seal(id *backend.Identity, req *backend.SealedImportRequest, secret *[32]byte) ([]byte, error) {
	return SealAAD(id, wireadmin.SealedHeader(req), secret)
}

// SealAAD is Seal with the associated data aad instead of a sealed
// import's header: for a share in another message (handover), whose
// header says more. The caller must have verified id first.
func SealAAD(id *backend.Identity, aad []byte, secret *[32]byte) ([]byte, error) {
	k, d, a := Suite()
	if id.ImportKEM != k || id.ImportKDF != d || id.ImportAEAD != a {
		return nil, fmt.Errorf("sealedimport: runner offers suite %#04x/%#04x/%#04x, want %#04x/%#04x/%#04x (hybrid ML-KEM-768-X25519)",
			id.ImportKEM, id.ImportKDF, id.ImportAEAD, k, d, a)
	}
	pub, err := kem.NewPublicKey(id.ImportKey)
	if err != nil {
		return nil, fmt.Errorf("sealedimport: import key: %w", err)
	}
	enc, s, err := hpke.NewSender(pub, kdf, aead, []byte(info))
	if err != nil {
		return nil, err
	}
	ct, err := s.Seal(aad, secret[:])
	if err != nil {
		return nil, err
	}
	out := binary.BigEndian.AppendUint16(nil, uint16(len(enc)))
	out = append(out, enc...)
	return append(out, ct...), nil
}

// Open decrypts the share in req. The caller still checks that the share's
// public key equals req.SharePubkey.
func (k *Key) Open(req *backend.SealedImportRequest) ([32]byte, error) {
	return k.OpenAAD(req.Sealed, wireadmin.SealedHeader(req))
}

// OpenAAD decrypts a share that SealAAD sealed with aad.
func (k *Key) OpenAAD(sealed, aad []byte) ([32]byte, error) {
	var secret [32]byte
	b := sealed
	if len(b) < 2 {
		return secret, errors.New("sealedimport: short sealed share")
	}
	n := int(binary.BigEndian.Uint16(b))
	if len(b) < 2+n {
		return secret, errors.New("sealedimport: short sealed share")
	}
	r, err := hpke.NewRecipient(b[2:2+n], k.priv, kdf, aead, []byte(info))
	if err != nil {
		return secret, fmt.Errorf("sealedimport: %w", err)
	}
	plain, err := r.Open(aad, b[2+n:])
	if err != nil {
		return secret, errors.New("sealedimport: open failed (sealed for another runner, or header changed)")
	}
	defer clear(plain)
	if len(plain) != len(secret) {
		return secret, errors.New("sealedimport: share is not 32 bytes")
	}
	copy(secret[:], plain)
	return secret, nil
}
