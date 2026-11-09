//go:build nts

package nts

import (
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/pem"
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
// others. The catalog (trusted-time/ntscatalog) names each operator's files.
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

// PublicServers are the NTS servers the runner uses: the entries of the
// built-in catalog that are not withdrawn (trusted-time/ntscatalog).
var PublicServers = publicServers(ntscatalog.Builtin.Dialed())

func publicServers(in []ntscatalog.NTSServer) []Server {
	out := make([]Server, 0, len(in))
	for _, e := range in {
		out = append(out, Server{Host: e.Host, Operator: e.Operator, Roots: append([]string(nil), e.Roots...)})
	}
	return out
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
// pinned hash.
func AddRoots(pool *x509.CertPool, files []string) error {
	for _, name := range files {
		want, ok := rootSHA256[name]
		if !ok {
			return fmt.Errorf("nts: no pinned root %q", name)
		}
		data, err := rootFiles.ReadFile("roots/" + name)
		if err != nil {
			return err
		}
		block, _ := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return fmt.Errorf("nts: roots/%s is not a PEM certificate", name)
		}
		if sum := sha256.Sum256(block.Bytes); hex.EncodeToString(sum[:]) != want {
			return fmt.Errorf("nts: roots/%s has sha256 %x, pinned %s", name, sum, want)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("nts: roots/%s: %w", name, err)
		}
		pool.AddCert(cert)
	}
	return nil
}
