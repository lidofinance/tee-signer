// Package cloudroots holds the TLS roots the runner trusts for each cloud's
// API endpoints. A cloud client trusts its provider's roots only, never the
// system store or a general bundle: a certificate that another CA issued
// for a KMS, STS, object store or key vault host is refused.
//
// Where they came from (fetched 2026-11-06, the DigiCert G5 roots
// 2026-11-07), and the SHA-256 of each DER.
// Every hash also matches the Mozilla list (https://curl.se/ca/cacert.pem);
// the AWS page lists the same SHA-256 and the Azure page the same SHA-1.
//
//	AWS     https://www.amazontrust.com/repository/
//	Google  https://pki.goog/repository/ (https://i.pki.goog/r1.pem, r3.pem, r4.pem)
//	Azure   https://learn.microsoft.com/azure/security/fundamentals/azure-ca-details
//	        (DigiCert files from cacerts.digicert.com, Microsoft files
//	        from www.microsoft.com/pkiops/certs)
//
// The anchors the chains seen that day verify to: Amazon Root CA 1 for KMS,
// STS and S3, GTS Root R4 for Google's APIs, and DigiCert Global Root G2
// for MAA, Key Vault, Blob, login.microsoftonline.com and
// management.azure.com. Starfield Services Root G2 cross-signs Amazon Root
// CA 1 and is in the AWS set too.
//
// The Azure set is the roots the Azure page lists: DigiCert Global Root G2
// and G3, DigiCert TLS ECC P384 Root G5 and TLS RSA4096 Root G5, and
// Microsoft's RSA and ECC roots of 2017. It leaves out DigiCert Global
// Root CA (G1): no chain the runner sees ends there, and the Mozilla list
// no longer has it.
//
// Each provider has several roots, so a move to another of its own roots
// does not break a running signer. A move to a root outside its set fails
// the TLS handshake: the fix is a new image with the root added here.
package cloudroots

import (
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/pem"
	"fmt"
)

//go:embed roots/*.pem
var rootFiles embed.FS

// Provider is a cloud whose roots a client trusts.
type Provider int

const (
	AWS Provider = iota
	Google
	Azure
)

// root is one embedded file and the SHA-256 of its certificate.
type root struct{ file, sha256 string }

var roots = map[Provider][]root{
	AWS: {
		{"amazon-root-ca-1.pem", "8ecde6884f3d87b1125ba31ac3fcb13d7016de7f57cc904fe1cb97c6ae98196e"},
		{"amazon-root-ca-2.pem", "1ba5b2aa8c65401a82960118f80bec4f62304d83cec4713a19c39c011ea46db4"},
		{"amazon-root-ca-3.pem", "18ce6cfe7bf14e60b2e347b8dfe868cb31d02ebb3ada271569f50343b46db3a4"},
		{"amazon-root-ca-4.pem", "e35d28419ed02025cfa69038cd623962458da5c695fbdea3c22b0bfb25897092"},
		{"starfield-services-root-g2.pem", "568d6905a2c88708a4b3025190edcfedb1974a606a13c6e5290fcb2ae63edab5"},
	},
	Google: {
		{"gts-root-r1.pem", "d947432abde7b7fa90fc2e6b59101b1280e0e1c7e4e40fa3c6887fff57a7f4cf"},
		{"gts-root-r3.pem", "34d8a73ee208d9bcdb0d956520934b4e40e69482596e8b6f73c8426b010a6f48"},
		{"gts-root-r4.pem", "349dfa4058c5e263123b398ae795573c4e1313c83fe68f93556cd5e8031b3c7d"},
	},
	Azure: {
		{"digicert-global-root-g2.pem", "cb3ccbb76031e5e0138f8dd39a23f9de47ffc35e43c1144cea27d46a5ab1cb5f"},
		{"digicert-global-root-g3.pem", "31ad6648f8104138c738f39ea4320133393e3a18cc02296ef97c2ac9ef6731d0"},
		{"digicert-tls-ecc-p384-root-g5.pem", "018e13f0772532cf809bd1b17281867283fc48c6e13be9c69812854a490c1b05"},
		{"digicert-tls-rsa4096-root-g5.pem", "371a00dc0533b3721a7eeb40e8419e70799d2b0a0f2c1d80693165f7cec4ad75"},
		{"microsoft-rsa-root-2017.pem", "c741f70f4b2a8d88bf2e71c14122ef53ef10eba0cfa5e64cfa20f418853073e0"},
		{"microsoft-ecc-root-2017.pem", "358df39d764af9e1b766e9c972df352ee15cfac227af6ad1d70e8e4a6edcba02"},
	},
}

// Pool returns a new pool with the roots of the given providers. It panics
// if an embedded file does not match its hash, which the tests rule out.
func Pool(ps ...Provider) *x509.CertPool {
	pool := basePool()
	for _, p := range ps {
		for _, r := range roots[p] {
			c, err := load(r)
			if err != nil {
				panic(err)
			}
			pool.AddCert(c)
		}
	}
	return pool
}

func load(r root) (*x509.Certificate, error) {
	data, err := rootFiles.ReadFile("roots/" + r.file)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		return nil, fmt.Errorf("cloudroots: roots/%s is not one PEM certificate", r.file)
	}
	if sum := sha256.Sum256(block.Bytes); hex.EncodeToString(sum[:]) != r.sha256 {
		return nil, fmt.Errorf("cloudroots: roots/%s has sha256 %x, pinned %s", r.file, sum, r.sha256)
	}
	return x509.ParseCertificate(block.Bytes)
}
