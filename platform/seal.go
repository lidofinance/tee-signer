package platform

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// GCMSealer seals with AES-256-GCM: blob = nonce(12) || ciphertext||tag.
// Callers supply the sealing key; key release belongs to the platform backend.
type GCMSealer struct{ aead cipher.AEAD }

func NewGCMSealer(key []byte) (*GCMSealer, error) {
	if len(key) != 32 {
		return nil, errors.New("sealer: want a 32-byte key")
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	return &GCMSealer{aead: g}, nil
}

func (s *GCMSealer) Seal(plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, plaintext, aad), nil
}

func (s *GCMSealer) Unseal(blob, aad []byte) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(blob) < n+s.aead.Overhead() {
		return nil, errors.New("sealer: blob too short")
	}
	return s.aead.Open(nil, blob[:n], blob[n:], aad)
}
