package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"time"

	adminapprover "github.com/lidofinance/tee-signer/signer-admin/approver"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

// Client certificates of the roles (docs/protocol.md, "Client roles"). The runner reads the role from the
// verified chain:
//
//	admin        the leaf and its issuing intermediate carry AdminClientOID
//	attest-only  the leaf or a CA carries AttestOnlyClientOID
//	signing      anything else
//
// issue-client-cert issues one leaf of one role from an existing CA or
// intermediate key, or, with -make-intermediate, a role intermediate from a
// root. It refuses what would not give the role asked for: an admin leaf
// from an issuer without the admin mark or from a root, a signing leaf
// from a marked issuer, and an intermediate from an issuer that is not a
// root.
//
//	signer-admin issue-client-cert -ca-cert FILE -ca-key FILE -role admin|attest|signing -name CN -out DIR [-valid 24h]
//	signer-admin issue-client-cert -ca-cert FILE -ca-key FILE -make-intermediate admin|attest|signing -name CN -out DIR [-valid 8760h]
//
// A leaf goes to DIR/CN.pem (the leaf, then the issuer when the issuer is
// an intermediate, the file a client sends) and DIR/CN-key.pem (mode 0600).
// An intermediate goes to DIR/CN-ca.pem and DIR/CN-ca-key.pem. Keys are
// ECDSA P-256. The CA key file must be mode 0600, as an approver key.

var certNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func cmdIssueClientCert(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("issue-client-cert", flag.ContinueOnError)
	caCert := fs.String("ca-cert", "", "the issuer's certificate (PEM)")
	caKey := fs.String("ca-key", "", "the issuer's private key (PEM, mode 0600)")
	role := fs.String("role", "", "the leaf's role: admin, attest or signing")
	inter := fs.String("make-intermediate", "", "issue a role intermediate (admin, attest or signing) from a root instead of a leaf")
	name := fs.String("name", "", "the certificate's common name, also the file name")
	dir := fs.String("out", "", "output folder")
	valid := fs.Duration("valid", 0, "validity from now (default 24h for a leaf, 8760h for an intermediate)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *caCert == "" || *caKey == "" || *name == "" || *dir == "" || (*role == "") == (*inter == "") {
		return errors.New("usage: signer-admin issue-client-cert -ca-cert FILE -ca-key FILE (-role admin|attest|signing | -make-intermediate ROLE) -name CN -out DIR [-valid D]")
	}
	if !certNameRE.MatchString(*name) {
		return fmt.Errorf("-name %q: letters, digits, '.', '_' and '-' only", *name)
	}
	r := *role + *inter
	if r != "admin" && r != "attest" && r != "signing" {
		return fmt.Errorf("role %q: admin, attest or signing", r)
	}
	issuer, err := readCertFile(*caCert)
	if err != nil {
		return err
	}
	if err := adminapprover.CheckPrivateFile(*caKey); err != nil {
		return err
	}
	signer, err := readKeyPEM(*caKey)
	if err != nil {
		return err
	}
	if !samePublic(signer.Public(), issuer.PublicKey) {
		return fmt.Errorf("%s is not the key of %s", *caKey, *caCert)
	}
	if !issuer.IsCA || issuer.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("%s is not a CA certificate that may sign certificates", *caCert)
	}
	root := isRoot(issuer)
	admin, attest := hasMark(issuer, cloud.AdminClientOID), hasMark(issuer, cloud.AttestOnlyClientOID)
	if *inter != "" {
		if !root {
			return fmt.Errorf("-make-intermediate: %s is not a root (self-signed); a role intermediate sits straight under the root in allowed_client_ca", *caCert)
		}
		return issue(out, issuer, signer, r, *name, *dir, cmpDur(*valid, 365*24*time.Hour), true)
	}
	switch {
	case r == "admin" && root:
		return errors.New("-role admin: the issuer is a root; the runner counts the admin mark only under an admin intermediate (make one with -make-intermediate admin)")
	case r == "admin" && !admin:
		return errors.New("-role admin: the issuer does not carry the admin mark (AdminClientOID); a leaf it issues would be a signing certificate")
	case r == "admin" && attest:
		return errors.New("-role admin: the issuer carries the attest-only mark, which makes every certificate below it attest-only")
	case r == "signing" && (admin || attest):
		return errors.New("-role signing: the issuer carries a role mark; issue signing certificates from the signing intermediate")
	case r == "attest" && admin:
		return errors.New("-role attest: the issuer is an admin intermediate; issue attest-only certificates from the attest or the signing intermediate")
	}
	return issue(out, issuer, signer, r, *name, *dir, cmpDur(*valid, 24*time.Hour), false)
}

func cmpDur(d, def time.Duration) time.Duration {
	if d == 0 {
		return def
	}
	return d
}

// issue makes the key and the certificate and writes both.
func issue(out io.Writer, issuer *x509.Certificate, signer crypto.Signer, role, name, dir string, valid time.Duration, ca bool) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return err
	}
	t := now()
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: name},
		// Five minutes back for clocks a little behind.
		NotBefore: t.Add(-5 * time.Minute), NotAfter: t.Add(valid),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	switch role {
	case "admin":
		tmpl.UnknownExtKeyUsage = []asn1.ObjectIdentifier{cloud.AdminClientOID}
	case "attest":
		tmpl.UnknownExtKeyUsage = []asn1.ObjectIdentifier{cloud.AttestOnlyClientOID}
	}
	if ca {
		tmpl.IsCA, tmpl.BasicConstraintsValid, tmpl.MaxPathLenZero = true, true, true
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		tmpl.BasicConstraintsValid = true
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	}
	if tmpl.NotAfter.After(issuer.NotAfter) {
		tmpl.NotAfter = issuer.NotAfter
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, &key.PublicKey, signer)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	certPath, keyPath := filepath.Join(dir, name+".pem"), filepath.Join(dir, name+"-key.pem")
	if ca {
		certPath, keyPath = filepath.Join(dir, name+"-ca.pem"), filepath.Join(dir, name+"-ca-key.pem")
	}
	for _, p := range []string{certPath, keyPath} {
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("%s exists; not overwriting it", p)
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	certs := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if !ca && !isRoot(issuer) {
		certs = append(certs, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Raw})...)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(certPath, certs, 0o644); err != nil {
		return err
	}
	what := "client certificate"
	if ca {
		what = "intermediate CA"
	}
	fprintf(out, "%s %s, role %s, issued by %q, valid until %s\nwrote %s and %s\n", what, name, role, issuer.Subject.CommonName,
		tmpl.NotAfter.UTC().Format(time.RFC3339), certPath, keyPath)
	return nil
}

func readCertFile(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s: no PEM certificate", path)
	}
	return x509.ParseCertificate(blk.Bytes)
}

func readKeyPEM(path string) (crypto.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer clear(b)
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("%s: no PEM key", path)
	}
	defer clear(blk.Bytes)
	if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
		if s, ok := k.(crypto.Signer); ok {
			return s, nil
		}
	}
	if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	return nil, fmt.Errorf("%s: not a PKCS #8 or EC private key", path)
}

func samePublic(a crypto.PublicKey, b any) bool {
	ma, err1 := x509.MarshalPKIXPublicKey(a)
	mb, err2 := x509.MarshalPKIXPublicKey(b)
	return err1 == nil && err2 == nil && bytes.Equal(ma, mb)
}

// isRoot reports whether c is self-signed.
func isRoot(c *x509.Certificate) bool {
	return bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignatureFrom(c) == nil
}

func hasMark(c *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, u := range c.UnknownExtKeyUsage {
		if u.Equal(oid) {
			return true
		}
	}
	return false
}
