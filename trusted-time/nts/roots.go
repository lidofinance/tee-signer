//go:build nts

package nts

import (
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/lidofinance/tee-signer/trusted-time/ntscatalog"
)

// The pinned root certificates, one small set per operator. Each server's
// certificate must chain to a root of its own operator's set, not to any CA
// of a general store.
//
// Where they came from: the Ubuntu 24.04 store, package ca-certificates
// 20260601~24.04.1 (Mozilla's list), /usr/share/ca-certificates/mozilla/<name>.crt.
// Which root each operator uses was read from one TLS handshake per server
// on port 4460 (the verified chain, nothing sent):
//
//	file                              subject                                          sha256 of the DER
//	sslcom-root-ecc.pem               SSL.com Root Certification Authority ECC         3417bb06cc6007da1b961c920b8ab4ce3fad820e4aa30b9acbc4a74ebdcebc65
//	isrg-root-x1.pem                  ISRG Root X1                                     96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6
//	isrg-root-x2.pem                  ISRG Root X2                                     69729b8e15a86efc177a57afb7171dfc64add28c2fca8cf1507e34453ccb1470
//	sectigo-server-auth-root-r46.pem  Sectigo Public Server Authentication Root R46    7bb647a62aeeac88bf257aa522d01ffea395e0ab45c73f93f65654ec38f25a06
//	digicert-global-root-g2.pem       DigiCert Global Root G2                          cb3ccbb76031e5e0138f8dd39a23f9de47ffc35e43c1144cea27d46a5ab1cb5f
//	harica-tls-rsa-root-2021.pem      HARICA TLS RSA Root CA 2021                      d95d0e8eda79525bf9beb11b14d2100d3294985f0c62d9fabd9cd999eccb7b1d
//	harica-root-2015.pem              Hellenic Academic and Research Institutions      a040929a02ce53b4acf4f2ffc6981ce4496f755e6d45fe0b2a692bcd52523f36
//	                                  RootCA 2015
//
//	time.cloudflare.com     leaf <- SSL.com SSL Intermediate CA ECC R2 <- SSL.com Root CA ECC
//	nts.netnod.se           leaf <- Let's Encrypt YR1 <- ISRG Root YR <- ISRG Root X1
//	ptbtime1.ptb.de         leaf <- Let's Encrypt YR2 <- ISRG Root YR <- ISRG Root X1
//	ntppool1.time.nl        leaf <- Let's Encrypt YE2 <- ISRG Root YE <- ISRG Root X2 (also cross-signed by X1)
//
// Added 2026-11-10 from package ca-certificates 20260816ubuntu0.24.04.2, for
// the catalog's candidates (not dialed by default):
//
//	bevtime1.metrologie.at  leaf <- Let's Encrypt YR1 <- ISRG Root YR <- ISRG Root X1
//	nts1.ntp.hr             leaf <- Sectigo DV R36 <- Sectigo Public Server Authentication Root R46
//	nts.meta.com            leaf <- DigiCert Global G2 TLS RSA SHA256 2020 CA1 <- DigiCert Global Root G2
//	ntp0.cam.ac.uk          leaf <- DigiCert Global G2 TLS RSA SHA256 2020 CA1 <- DigiCert Global Root G2
//	ntp.obspm.fr            leaf <- GEANT TLS RSA 1 <- HARICA TLS RSA Root CA 2021, sent cross-signed by
//	                        the Hellenic RootCA 2015, so both are pinned
//	time1.mbix.ca, a.st1.ntp.br  <- ISRG Root X1
//	ntp1.wiktel.com         leaf <- Let's Encrypt YE1 <- ISRG Root YE <- ISRG Root X2 (cross-signed by X1)
//
// The Let's Encrypt operators get both ISRG roots, since Let's Encrypt moves
// between them. A CA change by an operator outside its set makes NTS-KE to
// that server fail until the set is updated; the quorum then runs on the
// others. The catalog (trusted-time/ntscatalog) names each operator's files.
//
//go:embed roots/*.pem
var rootFiles embed.FS

// rootSHA256 pins each file's certificate, so a changed file fails at start.
var rootSHA256 = map[string]string{
	"sslcom-root-ecc.pem":              "3417bb06cc6007da1b961c920b8ab4ce3fad820e4aa30b9acbc4a74ebdcebc65",
	"isrg-root-x1.pem":                 "96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6",
	"isrg-root-x2.pem":                 "69729b8e15a86efc177a57afb7171dfc64add28c2fca8cf1507e34453ccb1470",
	"sectigo-server-auth-root-r46.pem": "7bb647a62aeeac88bf257aa522d01ffea395e0ab45c73f93f65654ec38f25a06",
	"digicert-global-root-g2.pem":      "cb3ccbb76031e5e0138f8dd39a23f9de47ffc35e43c1144cea27d46a5ab1cb5f",
	"harica-tls-rsa-root-2021.pem":     "d95d0e8eda79525bf9beb11b14d2100d3294985f0c62d9fabd9cd999eccb7b1d",
	"harica-root-2015.pem":             "a040929a02ce53b4acf4f2ffc6981ce4496f755e6d45fe0b2a692bcd52523f36",
}

// PublicServer is a public NTS server and who runs it.
type PublicServer struct {
	Host     string
	Operator string
	Roots    []string // files under roots/
}

// PublicServers are the Default entries of the built-in catalog that are
// not withdrawn (ntscatalog Dialed). The runner dials them plus the entries
// a deployment names in -nts-terms-confirmed.
var PublicServers = publicServers(ntscatalog.Builtin.Dialed())

func publicServers(in []ntscatalog.NTSServer) []PublicServer {
	out := make([]PublicServer, 0, len(in))
	for _, e := range in {
		out = append(out, PublicServer{Host: e.Host, Operator: e.Operator, Roots: append([]string(nil), e.Roots...)})
	}
	return out
}

// RootsPEM is the named root files as one PEM, each checked against its
// pinned hash: what a Server carries into the core, which hands it to the
// key exchange. No file named is an error: a server without roots could
// only fail later, at its key exchange.
func RootsPEM(files []string) ([]byte, error) {
	if len(files) == 0 {
		return nil, errors.New("nts: no pinned root named")
	}
	var out []byte
	for _, name := range files {
		block, _, err := pinnedRoot(name)
		if err != nil {
			return nil, err
		}
		out = append(out, pem.EncodeToMemory(block)...)
	}
	return out, nil
}

// RootPool builds the pool of the named root files, each checked against
// its pinned hash.
func RootPool(files []string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if err := AddRoots(pool, files); err != nil {
		return nil, err
	}
	return pool, nil
}

// AddRoots adds the named root files to pool, each checked against its
// pinned hash: the coarse check's HTTP client trusts the operators' roots
// too.
func AddRoots(pool *x509.CertPool, files []string) error {
	for _, name := range files {
		_, cert, err := pinnedRoot(name)
		if err != nil {
			return err
		}
		pool.AddCert(cert)
	}
	return nil
}

// pinnedRoot reads one embedded root and checks it against its pinned hash.
func pinnedRoot(name string) (*pem.Block, *x509.Certificate, error) {
	want, ok := rootSHA256[name]
	if !ok {
		return nil, nil, fmt.Errorf("nts: no pinned root %q", name)
	}
	data, err := rootFiles.ReadFile("roots/" + name)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("nts: roots/%s is not a PEM certificate", name)
	}
	if sum := sha256.Sum256(block.Bytes); hex.EncodeToString(sum[:]) != want {
		return nil, nil, fmt.Errorf("nts: roots/%s has sha256 %x, pinned %s", name, sum, want)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("nts: roots/%s: %w", name, err)
	}
	return block, cert, nil
}
