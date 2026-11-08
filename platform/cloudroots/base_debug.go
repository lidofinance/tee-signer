//go:build debugimport

package cloudroots

import "crypto/x509"

// basePool in a debug build also holds the system roots, so the tests
// with fake cloud endpoints can name their CA in SSL_CERT_FILE. No image
// is a debug build.
func basePool() *x509.CertPool {
	if p, err := x509.SystemCertPool(); err == nil {
		return p
	}
	return x509.NewCertPool()
}
