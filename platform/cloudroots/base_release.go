//go:build !debugimport

package cloudroots

import "crypto/x509"

func basePool() *x509.CertPool { return x509.NewCertPool() }
