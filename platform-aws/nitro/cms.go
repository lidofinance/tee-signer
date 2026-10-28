package nitro

// KMS returns CiphertextForRecipient as CMS EnvelopedData (RFC 5652) with
// one KeyTransRecipientInfo: the content key wrapped with RSAES-OAEP-SHA256
// to the public key from the attestation document, and the content
// encrypted with AES-256-CBC. The reference parser in
// aws-nitro-enclaves-sdk-c (source/cms.c) expects exactly that and accepts
// BER, so this parser handles indefinite lengths and constructed OCTET
// STRINGs. Tested against `openssl cms -encrypt` output (cms_test.go), not
// against real KMS output.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
)

var (
	oidEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidRSAESOAEP     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 7}
	oidSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidAES256CBC     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

// tlv is one BER element. content holds the bytes inside it; for an
// indefinite-length element it excludes the end-of-contents marker.
type tlv struct {
	class       int
	constructed bool
	tag         int
	content     []byte
}

var errBER = errors.New("cms: malformed BER")

// readTLV reads one element from b and returns it and the rest.
func readTLV(b []byte) (tlv, []byte, error) {
	if len(b) < 2 {
		return tlv{}, nil, errBER
	}
	t := tlv{class: int(b[0] >> 6), constructed: b[0]&0x20 != 0, tag: int(b[0] & 0x1f)}
	i := 1
	if t.tag == 0x1f { // high tag number
		t.tag = 0
		for {
			if i >= len(b) || i > 4 {
				return tlv{}, nil, errBER
			}
			t.tag = t.tag<<7 | int(b[i]&0x7f)
			i++
			if b[i-1]&0x80 == 0 {
				break
			}
		}
	}
	if i >= len(b) {
		return tlv{}, nil, errBER
	}
	l := int(b[i])
	i++
	switch {
	case l == 0x80: // indefinite: walk children until 00 00
		if !t.constructed {
			return tlv{}, nil, errBER
		}
		start := i
		rest := b[i:]
		for {
			if len(rest) >= 2 && rest[0] == 0 && rest[1] == 0 {
				t.content = b[start : len(b)-len(rest)]
				return t, rest[2:], nil
			}
			var err error
			if _, rest, err = readTLV(rest); err != nil {
				return tlv{}, nil, err
			}
		}
	case l&0x80 != 0:
		n := l & 0x7f
		if n == 0 || n > 4 || i+n > len(b) {
			return tlv{}, nil, errBER
		}
		l = 0
		for _, c := range b[i : i+n] {
			l = l<<8 | int(c)
		}
		i += n
	}
	if l < 0 || i+l > len(b) {
		return tlv{}, nil, errBER
	}
	t.content = b[i : i+l]
	return t, b[i+l:], nil
}

// children splits a constructed element into its elements.
func (t tlv) children() ([]tlv, error) {
	if !t.constructed {
		return nil, errBER
	}
	var out []tlv
	rest := t.content
	for len(rest) > 0 {
		c, r, err := readTLV(rest)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
		rest = r
	}
	return out, nil
}

// octets returns the value of an OCTET STRING, joining BER chunks.
func (t tlv) octets() ([]byte, error) {
	if !t.constructed {
		return t.content, nil
	}
	kids, err := t.children()
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	for _, k := range kids {
		v, err := k.octets()
		if err != nil {
			return nil, err
		}
		buf.Write(v)
	}
	return buf.Bytes(), nil
}

func (t tlv) oid() (asn1.ObjectIdentifier, error) {
	if t.class != 0 || t.tag != 6 {
		return nil, errBER
	}
	var o asn1.ObjectIdentifier
	full := append([]byte{0x06, byte(len(t.content))}, t.content...)
	if len(t.content) > 127 {
		return nil, errBER
	}
	_, err := asn1.Unmarshal(full, &o)
	return o, err
}

func isUniversal(t tlv, tag int) bool { return t.class == 0 && t.tag == tag }

// algorithm parses an AlgorithmIdentifier: OID and optional parameters.
func algorithm(t tlv) (asn1.ObjectIdentifier, *tlv, error) {
	if !isUniversal(t, 16) {
		return nil, nil, errBER
	}
	kids, err := t.children()
	if err != nil || len(kids) == 0 {
		return nil, nil, errBER
	}
	o, err := kids[0].oid()
	if err != nil {
		return nil, nil, err
	}
	if len(kids) > 1 && !isUniversal(kids[1], 5) { // 5 = NULL
		return o, &kids[1], nil
	}
	return o, nil, nil
}

// checkOAEPParams accepts absent parameters (KMS documents only
// RSAES_OAEP_SHA_256, and the AWS C SDK ignores them) or parameters whose
// hash is SHA-256. The MGF1 hash is assumed to match.
func checkOAEPParams(p *tlv) error {
	if p == nil {
		return nil
	}
	kids, err := p.children()
	if err != nil {
		return err
	}
	for _, k := range kids {
		if k.class == 2 && k.tag == 0 { // [0] hashAlgorithm
			inner, _, err := readTLV(k.content)
			if err != nil {
				return err
			}
			h, _, err := algorithm(inner)
			if err != nil {
				return err
			}
			if !h.Equal(oidSHA256) {
				return fmt.Errorf("cms: OAEP hash %v, want SHA-256", h)
			}
			return nil
		}
	}
	return errors.New("cms: OAEP parameters without a hash (SHA-1 default) are not supported")
}

// DecryptEnvelopedData opens a CMS EnvelopedData addressed to key.
func DecryptEnvelopedData(der []byte, key *rsa.PrivateKey) ([]byte, error) {
	ci, rest, err := readTLV(der)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 && !bytes.Equal(rest, []byte{0, 0}) {
		return nil, errors.New("cms: trailing data")
	}
	kids, err := ci.children()
	if err != nil || len(kids) != 2 {
		return nil, errors.New("cms: bad ContentInfo")
	}
	if o, err := kids[0].oid(); err != nil || !o.Equal(oidEnvelopedData) {
		return nil, errors.New("cms: not EnvelopedData")
	}
	if kids[1].class != 2 || kids[1].tag != 0 {
		return nil, errors.New("cms: missing [0] content")
	}
	ed, _, err := readTLV(kids[1].content)
	if err != nil {
		return nil, err
	}
	fields, err := ed.children()
	if err != nil || len(fields) < 3 {
		return nil, errors.New("cms: bad EnvelopedData")
	}
	i := 1 // skip version
	if fields[i].class == 2 && fields[i].tag == 0 {
		i++ // originatorInfo
	}
	if i+1 >= len(fields) || !isUniversal(fields[i], 17) {
		return nil, errors.New("cms: missing recipientInfos")
	}
	ris, err := fields[i].children()
	if err != nil || len(ris) != 1 {
		return nil, fmt.Errorf("cms: want exactly one recipient, got %d", len(ris))
	}
	ktri, err := ris[0].children()
	if err != nil || len(ktri) != 4 || !isUniversal(ris[0], 16) {
		return nil, errors.New("cms: recipient is not a KeyTransRecipientInfo")
	}
	kea, params, err := algorithm(ktri[2])
	if err != nil {
		return nil, err
	}
	if !kea.Equal(oidRSAESOAEP) {
		return nil, fmt.Errorf("cms: key transport %v, want RSAES-OAEP", kea)
	}
	if err := checkOAEPParams(params); err != nil {
		return nil, err
	}
	wrapped, err := ktri[3].octets()
	if err != nil {
		return nil, err
	}
	cek, err := rsa.DecryptOAEP(sha256.New(), nil, key, wrapped, nil)
	if err != nil {
		return nil, fmt.Errorf("cms: unwrap content key: %w", err)
	}
	defer clear(cek)

	eci, err := fields[i+1].children()
	if err != nil || len(eci) < 3 {
		return nil, errors.New("cms: no encrypted content")
	}
	cea, ivT, err := algorithm(eci[1])
	if err != nil {
		return nil, err
	}
	if !cea.Equal(oidAES256CBC) || ivT == nil {
		return nil, fmt.Errorf("cms: content cipher %v, want AES-256-CBC", cea)
	}
	iv, err := ivT.octets()
	if err != nil || len(iv) != aes.BlockSize {
		return nil, errors.New("cms: bad IV")
	}
	if eci[2].class != 2 || eci[2].tag != 0 {
		return nil, errors.New("cms: missing [0] encryptedContent")
	}
	ct, err := eci[2].octets()
	if err != nil {
		return nil, err
	}
	if len(cek) != 32 || len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, errors.New("cms: bad content key or ciphertext length")
	}
	blk, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(blk, iv).CryptBlocks(pt, ct)
	pad := int(pt[len(pt)-1])
	if pad == 0 || pad > aes.BlockSize {
		return nil, errors.New("cms: bad padding")
	}
	for _, c := range pt[len(pt)-pad:] {
		if int(c) != pad {
			return nil, errors.New("cms: bad padding")
		}
	}
	return pt[:len(pt)-pad], nil
}
