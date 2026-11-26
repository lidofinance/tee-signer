// Package clientcert holds the bounds the runner puts on the certificate
// list a TLS client sends (docs/protocol.md, "Client roles"). The runner
// (tee-signer/attls) refuses a list outside them before it checks any
// signature; the clients check their own certificate file with the same
// rule when they load it, so a file the runner would refuse fails at
// start and not with the TLS alert "bad certificate".
package clientcert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
)

// A client chain of the role model is the leaf, its role intermediate and
// the root: MaxCerts certificates at most. A leaf straight under the root
// has one or two. Each is at most MaxCertBytes long and has an ECDSA P-256
// or P-384, Ed25519, or RSA key of 2048 to 4096 bits. crypto/x509 takes
// every certificate of the list as a candidate intermediate and checks up
// to 100 signatures to build a chain, so these bounds keep that work
// small. A copy of a CA the runner pins, sent after the leaf, is not
// counted or checked: the runner has it already.
const (
	MaxCerts     = 3
	MaxCertBytes = 8 << 10
)

// maxNameBytes is the most of a subject name an error prints.
const maxNameBytes = 64

// Check refuses a certificate list (leaf first) outside the bounds. It
// checks no signature. pinned, if not nil, reports whether a certificate
// is a copy of a CA the runner pins; such a copy after the leaf neither
// counts nor meets the key rule. Check returns the list with each
// certificate once. It keeps the pinned copies: a pinned intermediate
// sent along still gives the chain through it to the root.
func Check(certs []*x509.Certificate, pinned func(*x509.Certificate) bool) ([]*x509.Certificate, error) {
	if len(certs) == 0 {
		return nil, errors.New("no client certificate")
	}
	out := []*x509.Certificate{certs[0]}
	seen := map[[32]byte]bool{sha256.Sum256(certs[0].Raw): true}
	counted := []int{0} // positions in out that count
	for _, c := range certs[1:] {
		h := sha256.Sum256(c.Raw)
		if seen[h] {
			continue
		}
		seen[h] = true
		if pinned == nil || !pinned(c) {
			counted = append(counted, len(out))
		}
		out = append(out, c)
	}
	if len(counted) > MaxCerts {
		return nil, fmt.Errorf("%d certificates besides copies of a pinned CA; a client chain has at most %d (leaf, intermediate, root)", len(counted), MaxCerts)
	}
	for _, i := range counted {
		c := out[i]
		if len(c.Raw) > MaxCertBytes {
			return nil, fmt.Errorf("%s is %d bytes, more than %d", name(i, c), len(c.Raw), MaxCertBytes)
		}
		if !keyOK(c.PublicKey) {
			return nil, fmt.Errorf("%s has a %s key; a client chain takes ECDSA P-256 or P-384, Ed25519, or RSA of 2048 to 4096 bits", name(i, c), keyKind(c.PublicKey))
		}
	}
	return out, nil
}

// CheckFile is Check for a client's own certificate list (DER, leaf
// first), before it connects. The client does not know the CAs the runner
// pins, so a self-signed certificate after the leaf counts as a copy of a
// pinned root. A runner that does not pin it refuses the chain anyway.
func CheckFile(chain [][]byte) error {
	certs := make([]*x509.Certificate, len(chain))
	for i, der := range chain {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("certificate %d: %w", i, err)
		}
		certs[i] = c
	}
	_, err := Check(certs, func(c *x509.Certificate) bool {
		return bytes.Equal(c.RawSubject, c.RawIssuer) && c.CheckSignatureFrom(c) == nil
	})
	return err
}

// name names certificate i of a list for an error: its position, a hash
// prefix and at most maxNameBytes of its common name. The certificate is
// unchecked, and the error may go to a log.
func name(i int, c *x509.Certificate) string {
	cn := c.Subject.CommonName
	if len(cn) > maxNameBytes {
		cn = cn[:maxNameBytes] + "..."
	}
	h := sha256.Sum256(c.Raw)
	return fmt.Sprintf("certificate %d (%q, sha256 %x)", i, cn, h[:6])
}

func keyOK(k any) bool {
	switch k := k.(type) {
	case *ecdsa.PublicKey:
		return k.Curve == elliptic.P256() || k.Curve == elliptic.P384()
	case ed25519.PublicKey:
		return true
	case *rsa.PublicKey:
		n := k.N.BitLen()
		return n >= 2048 && n <= 4096
	}
	return false
}

// keyKind names the key k for an error.
func keyKind(k any) string {
	switch k := k.(type) {
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d bit", k.N.BitLen())
	}
	return fmt.Sprintf("%T", k)
}
