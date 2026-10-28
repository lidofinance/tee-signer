//go:build !peerselect || peer_aws

package attest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// NitroRootPEM is the AWS Nitro Enclaves root certificate G1 for the
// commercial AWS partitions (CN=aws.nitro-enclaves, C=US, O=Amazon,
// OU=AWS, valid 2019-10-28 to 2049-10-28). AWS publishes it as
// https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
// and gives its fingerprint on
// https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html.
const NitroRootPEM = `-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----
`

// NitroRootSHA256 is the SHA-256 of the DER root certificate as printed on
// the AWS page above (64:1A:03:21:...:79:BB:5B). The package refuses to
// load if NitroRootPEM does not hash to it.
const NitroRootSHA256 = "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"

var nitroRoot = mustNitroRoot()

func mustNitroRoot() *x509.Certificate {
	blk, _ := pem.Decode([]byte(NitroRootPEM))
	if blk == nil {
		panic("attest: NitroRootPEM is not PEM")
	}
	sum := sha256.Sum256(blk.Bytes)
	if hex.EncodeToString(sum[:]) != NitroRootSHA256 {
		panic("attest: NitroRootPEM does not match the pinned SHA-256")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		panic("attest: NitroRootPEM: " + err.Error())
	}
	return c
}

// NitroRoot returns the pinned AWS Nitro Enclaves root certificate.
func NitroRoot() *x509.Certificate { return nitroRoot }

// NitroOptions configures VerifyNitro.
type NitroOptions struct {
	// Roots are the trust anchors. nil means the pinned AWS root only.
	// Tests pass a local test CA here.
	Roots []*x509.Certificate
	// Now is the time used for certificate validity and freshness. Zero
	// means time.Now(). AWS leaf certificates are short-lived, so old
	// sample documents verify only with Now set to their own time.
	Now time.Time
	// PCRs maps a PCR index to the value it must hold. Required unless
	// AcceptAnyPCRs is set.
	PCRs map[int][]byte
	// AcceptAnyPCRs skips the PCR comparison. For inspecting a document
	// only; a verifier that accepts any PCRs accepts any enclave image.
	AcceptAnyPCRs bool
	// Nonce, if not nil, must equal the document's nonce. The caller
	// issues a fresh random nonce per request.
	Nonce []byte
	// UserData, if not nil, must equal the document's user data.
	UserData []byte
	// MaxAge, if positive, bounds the age of the document timestamp.
	// Either Nonce or MaxAge must be set.
	MaxAge time.Duration
	// Skew is how far the document timestamp may lie ahead of Now. Zero
	// means DefaultSkew.
	Skew time.Duration
	// AllowDebug accepts documents from debug-mode enclaves (PCR0, PCR1
	// and PCR2 all zero). Never set it in production.
	AllowDebug bool
}

// NitroDocument is a verified NSM attestation document.
type NitroDocument struct {
	ModuleID  string
	Timestamp time.Time
	Digest    string
	// PCRs holds every PCR in the document by index. VerifyNitro checks
	// that PCR0 to PCR8 are present.
	PCRs        map[int][]byte
	PublicKey   []byte
	UserData    []byte
	Nonce       []byte
	Certificate *x509.Certificate
	// Debug is true when PCR0, PCR1 and PCR2 are all zero.
	Debug bool
}

// PCR returns the value of PCR i, or nil.
func (d *NitroDocument) PCR(i int) []byte { return d.PCRs[i] }

// coseAlgES384 is the COSE algorithm id of ECDSA with SHA-384 (RFC 9053).
const coseAlgES384 = -35

var nitroDec = func() cbor.DecMode {
	m, err := cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		MaxNestedLevels:   8,
		FieldNameMatching: cbor.FieldNameMatchingCaseSensitive,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	return m
}()

// nitroPayloadDec decodes the signed payload. The NSM of a real enclave
// encodes the payload's top-level map with an indefinite length (0xbf ...
// 0xff), as testdata/nitro/aws-signer-2 shows. The signature covers the payload byte for
// byte, so allowing this encoding lets nothing through that the signature
// does not cover. Everything else stays as strict as in nitroDec: duplicate
// keys, tags and nesting depth. The COSE_Sign1 array and the headers keep
// forbidding indefinite lengths.
var nitroPayloadDec = func() cbor.DecMode {
	m, err := cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthAllowed,
		TagsMd:            cbor.TagsForbidden,
		MaxNestedLevels:   8,
		FieldNameMatching: cbor.FieldNameMatchingCaseSensitive,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	return m
}()

type coseSign1 struct {
	protected []byte
	payload   []byte
	signature []byte
}

// nitroPayload follows the CDDL on the AWS verify-root page.
type nitroPayload struct {
	ModuleID    string            `cbor:"module_id"`
	Timestamp   uint64            `cbor:"timestamp"`
	Digest      string            `cbor:"digest"`
	PCRs        map[uint64][]byte `cbor:"pcrs"`
	Certificate []byte            `cbor:"certificate"`
	CABundle    [][]byte          `cbor:"cabundle"`
	PublicKey   []byte            `cbor:"public_key"`
	UserData    []byte            `cbor:"user_data"`
	Nonce       []byte            `cbor:"nonce"`
}

func formatErr(f string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrFormat, fmt.Sprintf(f, a...))
}

// decodeCOSESign1 accepts the tagged (tag 18) and the untagged form.
func decodeCOSESign1(b []byte) (*coseSign1, error) {
	if len(b) > 0 && b[0] == 0xd2 { // tag 18, COSE_Sign1
		b = b[1:]
	}
	var arr []cbor.RawMessage
	if err := nitroDec.Unmarshal(b, &arr); err != nil {
		return nil, formatErr("COSE_Sign1: %v", err)
	}
	if len(arr) != 4 {
		return nil, formatErr("COSE_Sign1 has %d elements, want 4", len(arr))
	}
	var m coseSign1
	for i, dst := range []*[]byte{&m.protected, nil, &m.payload, &m.signature} {
		if dst == nil {
			continue
		}
		if len(arr[i]) == 0 || arr[i][0]>>5 != 2 { // major type 2: byte string
			return nil, formatErr("COSE_Sign1 element %d is not a byte string", i)
		}
		if err := nitroDec.Unmarshal(arr[i], dst); err != nil {
			return nil, formatErr("COSE_Sign1 element %d: %v", i, err)
		}
	}
	var unprotected map[int64]cbor.RawMessage
	if err := nitroDec.Unmarshal(arr[1], &unprotected); err != nil || unprotected == nil {
		return nil, formatErr("COSE_Sign1 unprotected header is not a map")
	}
	var hdr map[int64]cbor.RawMessage
	if err := nitroDec.Unmarshal(m.protected, &hdr); err != nil {
		return nil, formatErr("protected header: %v", err)
	}
	var alg int64
	if raw, ok := hdr[1]; !ok {
		return nil, formatErr("protected header has no alg")
	} else if err := nitroDec.Unmarshal(raw, &alg); err != nil {
		return nil, formatErr("protected header alg: %v", err)
	}
	if alg != coseAlgES384 {
		return nil, formatErr("alg %d, want ES384 (-35)", alg)
	}
	if _, ok := hdr[2]; ok {
		return nil, formatErr("protected header has crit, not supported")
	}
	if len(m.payload) == 0 {
		return nil, formatErr("empty or detached payload")
	}
	if len(m.signature) != 96 {
		return nil, formatErr("signature is %d bytes, want 96 (ES384)", len(m.signature))
	}
	return &m, nil
}

func decodeNitroPayload(b []byte) (*nitroPayload, error) {
	var p nitroPayload
	if err := nitroPayloadDec.Unmarshal(b, &p); err != nil {
		return nil, formatErr("payload: %v", err)
	}
	switch {
	case p.ModuleID == "":
		return nil, formatErr("no module_id")
	case p.Timestamp == 0:
		return nil, formatErr("no timestamp")
	case p.Digest != "SHA384":
		return nil, formatErr("digest %q, want SHA384", p.Digest)
	case len(p.PCRs) == 0:
		return nil, formatErr("no pcrs")
	case len(p.Certificate) == 0 || len(p.Certificate) > 1024:
		return nil, formatErr("certificate size %d", len(p.Certificate))
	case len(p.CABundle) == 0:
		return nil, formatErr("empty cabundle")
	case len(p.PublicKey) > 1024 || len(p.UserData) > 1024 || len(p.Nonce) > 1024:
		return nil, formatErr("public_key, user_data or nonce over 1024 bytes")
	}
	for i, c := range p.CABundle {
		if len(c) == 0 || len(c) > 1024 {
			return nil, formatErr("cabundle[%d] size %d", i, len(c))
		}
	}
	for idx, v := range p.PCRs {
		if idx > 31 {
			return nil, formatErr("pcr index %d", idx)
		}
		if len(v) != 48 {
			return nil, formatErr("pcr%d is %d bytes, want 48 (SHA384)", idx, len(v))
		}
	}
	for i := uint64(0); i <= 8; i++ {
		if _, ok := p.PCRs[i]; !ok {
			return nil, formatErr("pcr%d missing", i)
		}
	}
	return &p, nil
}

// verifyNitroChain checks that cabundle starts with a trusted root and that
// the signing certificate chains to it at time now.
func verifyNitroChain(p *nitroPayload, roots []*x509.Certificate, now time.Time) (*x509.Certificate, error) {
	if roots == nil {
		roots = []*x509.Certificate{nitroRoot}
	}
	rootPool := x509.NewCertPool()
	first := false
	for _, r := range roots {
		rootPool.AddCert(r)
		if bytes.Equal(r.Raw, p.CABundle[0]) {
			first = true
		}
	}
	if !first {
		return nil, fmt.Errorf("%w: cabundle[0] is not a pinned root", ErrChain)
	}
	inter := x509.NewCertPool()
	for i, der := range p.CABundle[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, formatErr("cabundle[%d]: %v", i+1, err)
		}
		inter.AddCert(c)
	}
	leaf, err := x509.ParseCertificate(p.Certificate)
	if err != nil {
		return nil, formatErr("certificate: %v", err)
	}
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: inter,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrChain, err)
	}
	return leaf, nil
}

func verifyCOSESignature(m *coseSign1, leaf *x509.Certificate) error {
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P384() {
		return fmt.Errorf("%w: signing certificate key is not ECDSA P-384", ErrSignature)
	}
	// Sig_structure for COSE_Sign1 (RFC 9052 section 4.4) with empty
	// external_aad; the protected header goes in as the bytes received.
	tbs, err := cbor.Marshal([]any{"Signature1", m.protected, []byte{}, m.payload})
	if err != nil {
		return err
	}
	h := sha512.Sum384(tbs)
	r := new(big.Int).SetBytes(m.signature[:48])
	s := new(big.Int).SetBytes(m.signature[48:])
	if !ecdsa.Verify(pub, h[:], r, s) {
		return fmt.Errorf("%w: COSE_Sign1 signature does not verify", ErrSignature)
	}
	return nil
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// VerifyNitro verifies an NSM attestation document: COSE_Sign1 structure,
// certificate chain to the pinned root, ES384 signature, then debug mode,
// PCRs, nonce, user data and timestamp.
func VerifyNitro(doc []byte, o NitroOptions) (*NitroDocument, error) {
	if len(o.PCRs) == 0 && !o.AcceptAnyPCRs {
		return nil, fmt.Errorf("%w: no expected PCRs", ErrConfig)
	}
	if o.Nonce == nil && o.MaxAge <= 0 {
		return nil, fmt.Errorf("%w: set Nonce or MaxAge", ErrConfig)
	}
	now := nowOr(o.Now)
	m, err := decodeCOSESign1(doc)
	if err != nil {
		return nil, err
	}
	p, err := decodeNitroPayload(m.payload)
	if err != nil {
		return nil, err
	}
	leaf, err := verifyNitroChain(p, o.Roots, now)
	if err != nil {
		return nil, err
	}
	if err := verifyCOSESignature(m, leaf); err != nil {
		return nil, err
	}

	d := &NitroDocument{
		ModuleID:    p.ModuleID,
		Timestamp:   time.UnixMilli(int64(p.Timestamp)).UTC(),
		Digest:      p.Digest,
		PCRs:        make(map[int][]byte, len(p.PCRs)),
		PublicKey:   p.PublicKey,
		UserData:    p.UserData,
		Nonce:       p.Nonce,
		Certificate: leaf,
	}
	for i, v := range p.PCRs {
		d.PCRs[int(i)] = v
	}
	d.Debug = allZero(d.PCRs[0]) && allZero(d.PCRs[1]) && allZero(d.PCRs[2])
	if d.Debug && !o.AllowDebug {
		return nil, fmt.Errorf("%w: PCR0, PCR1 and PCR2 are zero (enclave started with --debug-mode)", ErrDebug)
	}
	if !o.AcceptAnyPCRs {
		for i, want := range o.PCRs {
			if got := d.PCRs[i]; !bytes.Equal(got, want) {
				return nil, fmt.Errorf("%w: pcr%d is %x, want %x", ErrMeasurement, i, got, want)
			}
		}
	}
	if o.Nonce != nil && !bytes.Equal(d.Nonce, o.Nonce) {
		return nil, fmt.Errorf("%w: document nonce %x, want %x", ErrNonce, d.Nonce, o.Nonce)
	}
	if o.UserData != nil && !bytes.Equal(d.UserData, o.UserData) {
		return nil, fmt.Errorf("%w: document user_data %x, want %x", ErrUserData, d.UserData, o.UserData)
	}
	if d.Timestamp.After(now.Add(skewOr(o.Skew))) {
		return nil, fmt.Errorf("%w: timestamp %s is after %s", ErrStale, d.Timestamp.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	if o.MaxAge > 0 && now.Sub(d.Timestamp) > o.MaxAge {
		return nil, fmt.Errorf("%w: timestamp %s is older than %s", ErrStale, d.Timestamp.Format(time.RFC3339), o.MaxAge)
	}
	return d, nil
}
