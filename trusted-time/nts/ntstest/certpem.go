//go:build nts

package ntstest

import (
	"crypto/tls"
	"encoding/pem"
	"time"
)

// CertificatePEM is Certificate with the CA in PEM form instead of a pool,
// for a runner process that reads its roots from a file (runner/e2e).
func CertificatePEM(host string, notBefore, notAfter time.Time) (tls.Certificate, []byte, error) {
	cert, ca, err := newCertificate(host, notBefore, notAfter)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), nil
}
