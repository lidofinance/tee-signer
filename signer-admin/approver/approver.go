// Package approver loads approver keys and signs what approvers sign:
// config updates, handover orders, import orders and exit
// approvals. An approver signs one of
// two forms of the same body: the direct form, Ed25519 over the kind's
// context and the body, or the hashed form, Ed25519 over 32 bytes, the
// SHA-256 of the kind's hash context and SHA-256 of the direct form
// (setupwire.ApprovalMessage). The runner takes either.
//
// A key is named by a URI:
//
//	PATH, file:PATH   a file that holds the hex Ed25519 seed, a regular
//	                  file of mode 0600 or stricter (tests, devnets)
//	openpgp:KEYGRIP   an Ed25519 signing key in gpg-agent, on an OpenPGP
//	                  card such as a YubiKey (openpgp.go); signs the
//	                  hashed form only
//
// The key never goes on a command line, into an environment variable or a
// log; only its path or keygrip does.
package approver

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// Signer is one approver key.
type Signer interface {
	Public() ed25519.PublicKey
	// Sign returns the Ed25519 signature of message.
	Sign(message []byte) ([]byte, error)
}

// Key is the public key of s as the approver sets hold it.
func Key(s Signer) [32]byte { return [32]byte(s.Public()) }

// fileSigner is a key read from a seed file.
type fileSigner struct{ priv ed25519.PrivateKey }

func (f *fileSigner) Public() ed25519.PublicKey { return f.priv.Public().(ed25519.PublicKey) }

func (f *fileSigner) Sign(message []byte) ([]byte, error) { return ed25519.Sign(f.priv, message), nil }

// Open returns the signer a key URI names: PATH, file:PATH or
// openpgp:KEYGRIP. Other schemes are refused.
func Open(uri string) (Signer, error) {
	path := uri
	if scheme, rest, ok := strings.Cut(uri, ":"); ok && len(scheme) > 1 && !strings.ContainsAny(scheme, `/\.`) {
		switch scheme {
		case "file":
			path = rest
		case "openpgp":
			return openOpenPGP(rest)
		default:
			return nil, fmt.Errorf("approver key %q: scheme %q is not supported (a path, file:PATH or openpgp:KEYGRIP)", uri, scheme)
		}
	}
	if path == "" {
		return nil, errors.New("approver key: empty path")
	}
	priv, err := ReadKeyFile(path)
	if err != nil {
		return nil, err
	}
	return &fileSigner{priv: priv}, nil
}

// ReadKeyFile reads an approver key file: the hex Ed25519 seed (32 bytes),
// as ta/test-pki holds them. The file must be a regular file readable by
// its owner only.
func ReadKeyFile(path string) (ed25519.PrivateKey, error) {
	if err := CheckPrivateFile(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(string(data)), "0x"))
	clear(data)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s: want the 32-byte Ed25519 seed as hex", path)
	}
	defer clear(seed)
	return ed25519.NewKeyFromSeed(seed), nil
}

// CheckPrivateFile refuses a path that is not a regular file of mode 0600
// or stricter. The CA keys of issue-client-cert take the same check.
func CheckPrivateFile(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s has mode %04o; a private key file must be readable by its owner only (chmod 600)", path, fi.Mode().Perm())
	}
	return nil
}

// Sign is s's signature over body under the approver context c, in the
// direct or the hashed form.
func Sign(s Signer, c setupwire.Context, hashed bool, body ...[]byte) ([64]byte, error) {
	if _, ok := setupwire.HashedContext(c); !ok {
		return [64]byte{}, fmt.Errorf("approver: %s is not an approver context", c)
	}
	if !hashed && HashedOnly(s) {
		return [64]byte{}, errors.New("approver: this key signs the hashed form only (sign -hashed)")
	}
	sig, err := s.Sign(setupwire.ApprovalMessage(c, hashed, body...))
	if err != nil {
		return [64]byte{}, err
	}
	if len(sig) != ed25519.SignatureSize {
		return [64]byte{}, fmt.Errorf("approver: signature of %d bytes", len(sig))
	}
	return [64]byte(sig), nil
}

// Verify reports whether sig is key's signature over body under c, and in
// which form.
func Verify(key [32]byte, c setupwire.Context, sig [64]byte, body ...[]byte) (ok, hashed bool) {
	pub := ed25519.PublicKey(key[:])
	if ed25519.Verify(pub, setupwire.ApprovalMessage(c, false, body...), sig[:]) {
		return true, false
	}
	if ed25519.Verify(pub, setupwire.ApprovalMessage(c, true, body...), sig[:]) {
		return true, true
	}
	return false, false
}

// Form names a signature form for output.
func Form(hashed bool) string {
	if hashed {
		return "hashed"
	}
	return "direct"
}
