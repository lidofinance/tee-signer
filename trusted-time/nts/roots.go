//go:build nts

package nts

import (
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/pem"
	"fmt"
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
//	file                 subject                                   sha256 of the DER
//	sslcom-root-ecc.pem  SSL.com Root Certification Authority ECC  3417bb06cc6007da1b961c920b8ab4ce3fad820e4aa30b9acbc4a74ebdcebc65
//	isrg-root-x1.pem     ISRG Root X1                              96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6
//	isrg-root-x2.pem     ISRG Root X2                              69729b8e15a86efc177a57afb7171dfc64add28c2fca8cf1507e34453ccb1470
//
//	time.cloudflare.com  leaf <- SSL.com SSL Intermediate CA ECC R2 <- SSL.com Root CA ECC
//	nts.netnod.se        leaf <- Let's Encrypt YR1 <- ISRG Root YR <- ISRG Root X1
//	ptbtime1.ptb.de      leaf <- Let's Encrypt YR2 <- ISRG Root YR <- ISRG Root X1
//	ntppool1.time.nl     leaf <- Let's Encrypt YE2 <- ISRG Root YE <- ISRG Root X2 (also cross-signed by X1)
//
// The Let's Encrypt operators get both ISRG roots, since Let's Encrypt moves
// between them. A CA change by an operator outside its set makes NTS-KE to
// that server fail until the set is updated; the quorum then runs on the
// other three.
//
//go:embed roots/*.pem
var rootFiles embed.FS

// rootSHA256 pins each file's certificate, so a changed file fails at start.
var rootSHA256 = map[string]string{
	"sslcom-root-ecc.pem": "3417bb06cc6007da1b961c920b8ab4ce3fad820e4aa30b9acbc4a74ebdcebc65",
	"isrg-root-x1.pem":    "96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6",
	"isrg-root-x2.pem":    "69729b8e15a86efc177a57afb7171dfc64add28c2fca8cf1507e34453ccb1470",
}

// Server is a public NTS server and who runs it.
type Server struct {
	Host     string
	Operator string
	Roots    []string // files under roots/
}

// PublicServers are the four operators of the PoC. PTB runs ptbtime1, 2
// and 3; one of them counts, since the quorum needs distinct operators.
var PublicServers = []Server{
	{Host: "time.cloudflare.com", Operator: "cloudflare", Roots: []string{"sslcom-root-ecc.pem"}},
	{Host: "nts.netnod.se", Operator: "netnod", Roots: []string{"isrg-root-x1.pem", "isrg-root-x2.pem"}},
	{Host: "ptbtime1.ptb.de", Operator: "ptb", Roots: []string{"isrg-root-x1.pem", "isrg-root-x2.pem"}},
	{Host: "ntppool1.time.nl", Operator: "time.nl", Roots: []string{"isrg-root-x1.pem", "isrg-root-x2.pem"}},
}

// RootPool builds the pool of the named root files, each checked against
// its pinned hash.
func RootPool(files []string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	for _, name := range files {
		want, ok := rootSHA256[name]
		if !ok {
			return nil, fmt.Errorf("nts: no pinned root %q", name)
		}
		data, err := rootFiles.ReadFile("roots/" + name)
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("nts: roots/%s is not a PEM certificate", name)
		}
		if sum := sha256.Sum256(block.Bytes); hex.EncodeToString(sum[:]) != want {
			return nil, fmt.Errorf("nts: roots/%s has sha256 %x, pinned %s", name, sum, want)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("nts: roots/%s: %w", name, err)
		}
		pool.AddCert(cert)
	}
	return pool, nil
}
