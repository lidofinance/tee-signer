package approver

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// OpenPGPKey is an Ed25519 key or subkey of an exported OpenPGP public key
// (gpg --export), the form an approver hands out without the card.
type OpenPGPKey struct {
	Fingerprint [20]byte // v4
	Public      ed25519.PublicKey
	Subkey      bool
	// CanSign: a self-signature's key flags give the key the sign flag.
	// The flags are read, not checked: the signatures are not verified.
	CanSign bool
}

// KeyID is the last 8 bytes of the fingerprint, as hex.
func (k OpenPGPKey) KeyID() string { return strings.ToUpper(hex.EncodeToString(k.Fingerprint[12:])) }

// ed25519OID is the curve OID of an EdDSALegacy key (RFC 9580, 9.2).
var ed25519OID = []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01}

// OpenPGPEd25519Keys lists the Ed25519 keys of an exported public key,
// armored or binary, in packet order. Other keys (Curve25519, RSA) are left
// out.
func OpenPGPEd25519Keys(data []byte) ([]OpenPGPKey, error) {
	if bytes.Contains(data, []byte("-----BEGIN PGP")) {
		var err error
		if data, err = dearmor(data); err != nil {
			return nil, err
		}
	}
	var keys []OpenPGPKey
	cur := -1 // index in keys of the last key packet, -1 if not Ed25519
	sawKey := false
	for len(data) > 0 {
		tag, body, rest, err := nextPacket(data)
		if err != nil {
			return nil, err
		}
		data = rest
		switch tag {
		case 6, 14: // public key, public subkey
			if tag == 6 && sawKey {
				return nil, errors.New("more than one primary key; export one key")
			}
			sawKey = true
			cur = -1
			k, ok, err := parseKeyPacket(body)
			if err != nil {
				return nil, err
			}
			if ok {
				k.Subkey = tag == 14
				keys = append(keys, k)
				cur = len(keys) - 1
			}
		case 2: // signature
			if cur < 0 {
				continue
			}
			flags, typ, ok := sigKeyFlags(body)
			// Subkey binding (0x18) for a subkey; certification
			// (0x10-0x13) or direct key (0x1f) for the primary.
			bind := keys[cur].Subkey && typ == 0x18 || !keys[cur].Subkey && (typ >= 0x10 && typ <= 0x13 || typ == 0x1f)
			if ok && bind && flags&0x02 != 0 {
				keys[cur].CanSign = true
			}
		}
	}
	if !sawKey {
		return nil, errors.New("no OpenPGP public key packet")
	}
	return keys, nil
}

// SelectOpenPGPKey picks the approver key from keys: the one whose
// fingerprint or key ID ends in want, or, with want empty, the one Ed25519
// subkey that can sign (or the primary key when no subkey can).
func SelectOpenPGPKey(keys []OpenPGPKey, want string) (OpenPGPKey, error) {
	want = strings.ToUpper(strings.TrimPrefix(strings.ReplaceAll(want, " ", ""), "0x"))
	var c []OpenPGPKey
	for _, k := range keys {
		switch {
		case want != "":
			if len(want) >= 16 && strings.HasSuffix(strings.ToUpper(hex.EncodeToString(k.Fingerprint[:])), want) {
				c = append(c, k)
			}
		case k.CanSign && k.Subkey:
			c = append(c, k)
		}
	}
	if want == "" && len(c) == 0 {
		for _, k := range keys {
			if k.CanSign && !k.Subkey {
				c = append(c, k)
			}
		}
	}
	switch {
	case len(c) == 1:
		return c[0], nil
	case want != "":
		return OpenPGPKey{}, fmt.Errorf("no Ed25519 key with fingerprint or key ID %s (at least 16 hex digits)", want)
	case len(c) == 0:
		return OpenPGPKey{}, errors.New("no Ed25519 key with the sign flag")
	}
	var ids []string
	for _, k := range c {
		ids = append(ids, k.KeyID())
	}
	return OpenPGPKey{}, fmt.Errorf("%d Ed25519 signing keys (%s); name one with -fingerprint", len(c), strings.Join(ids, ", "))
}

// parseKeyPacket reads a v4 key packet; ok is false for a key that is not
// Ed25519.
func parseKeyPacket(body []byte) (OpenPGPKey, bool, error) {
	if len(body) < 6 {
		return OpenPGPKey{}, false, errors.New("short key packet")
	}
	if body[0] != 4 {
		// v6 keys (RFC 9580) have a SHA-256 fingerprint; GnuPG 2.4 makes v4.
		return OpenPGPKey{}, false, nil
	}
	var pub []byte
	switch algo, p := body[5], body[6:]; algo {
	case 22: // EdDSALegacy: OID, then the point as an MPI, 0x40 || key
		if len(p) < 1 || len(p) < 1+int(p[0]) {
			return OpenPGPKey{}, false, errors.New("short EdDSA key packet")
		}
		if !bytes.Equal(p[1:1+int(p[0])], ed25519OID) {
			return OpenPGPKey{}, false, nil
		}
		p = p[1+int(p[0]):]
		if len(p) < 2 {
			return OpenPGPKey{}, false, errors.New("short EdDSA key packet")
		}
		n := (int(binary.BigEndian.Uint16(p)) + 7) / 8
		if len(p) < 2+n || n != 33 || p[2] != 0x40 {
			return OpenPGPKey{}, false, errors.New("EdDSA key packet: want the 0x40-prefixed 32-byte point")
		}
		pub = p[3 : 2+n]
	case 27: // Ed25519 (RFC 9580): 32 bytes
		if len(p) < 32 {
			return OpenPGPKey{}, false, errors.New("short Ed25519 key packet")
		}
		pub = p[:32]
	default:
		return OpenPGPKey{}, false, nil
	}
	h := sha1.New()
	h.Write([]byte{0x99, byte(len(body) >> 8), byte(len(body))})
	h.Write(body)
	k := OpenPGPKey{Public: ed25519.PublicKey(bytes.Clone(pub))}
	copy(k.Fingerprint[:], h.Sum(nil))
	return k, true, nil
}

// sigKeyFlags returns the first key flags octet of a v4 signature's hashed
// subpackets and the signature type.
func sigKeyFlags(body []byte) (flags, typ byte, ok bool) {
	if len(body) < 6 || body[0] != 4 {
		return 0, 0, false
	}
	typ = body[1]
	n := int(binary.BigEndian.Uint16(body[4:6]))
	sub := body[6:]
	if len(sub) < n {
		return 0, typ, false
	}
	sub = sub[:n]
	for len(sub) > 0 {
		var l int
		switch o := sub[0]; {
		case o < 192:
			l, sub = int(o), sub[1:]
		case o < 255:
			if len(sub) < 2 {
				return 0, typ, false
			}
			l, sub = (int(o)-192)<<8+int(sub[1])+192, sub[2:]
		default:
			if len(sub) < 5 {
				return 0, typ, false
			}
			l, sub = int(binary.BigEndian.Uint32(sub[1:5])), sub[5:]
		}
		if l < 1 || len(sub) < l {
			return 0, typ, false
		}
		if sub[0]&0x7f == 27 && l >= 2 {
			return sub[1], typ, true
		}
		sub = sub[l:]
	}
	return 0, typ, false
}

// nextPacket splits the first OpenPGP packet off data.
func nextPacket(data []byte) (tag byte, body, rest []byte, err error) {
	h := data[0]
	if h&0x80 == 0 {
		return 0, nil, nil, errors.New("not an OpenPGP packet")
	}
	var n, hl int
	if h&0x40 != 0 { // new format
		tag = h & 0x3f
		if len(data) < 2 {
			return 0, nil, nil, errors.New("truncated packet")
		}
		switch o := data[1]; {
		case o < 192:
			n, hl = int(o), 2
		case o < 224:
			if len(data) < 3 {
				return 0, nil, nil, errors.New("truncated packet")
			}
			n, hl = (int(o)-192)<<8+int(data[2])+192, 3
		case o == 255:
			if len(data) < 6 {
				return 0, nil, nil, errors.New("truncated packet")
			}
			n, hl = int(binary.BigEndian.Uint32(data[2:6])), 6
		default:
			return 0, nil, nil, errors.New("partial body length in a key export")
		}
	} else { // old format
		tag = (h >> 2) & 0x0f
		switch h & 3 {
		case 0:
			hl = 2
		case 1:
			hl = 3
		case 2:
			hl = 5
		default:
			return 0, nil, nil, errors.New("indeterminate packet length")
		}
		if len(data) < hl {
			return 0, nil, nil, errors.New("truncated packet")
		}
		for _, b := range data[1:hl] {
			n = n<<8 | int(b)
		}
	}
	if n < 0 || len(data)-hl < n {
		return 0, nil, nil, errors.New("truncated packet")
	}
	return tag, data[hl : hl+n], data[hl+n:], nil
}

// dearmor decodes the first ASCII-armored block of data.
func dearmor(data []byte) ([]byte, error) {
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	i := 0
	for i < len(lines) && !strings.HasPrefix(lines[i], "-----BEGIN PGP") {
		i++
	}
	i++
	for i < len(lines) && strings.TrimSpace(lines[i]) != "" { // armor headers
		i++
	}
	var b64 strings.Builder
	for i++; i < len(lines); i++ {
		l := strings.TrimSpace(lines[i])
		if strings.HasPrefix(l, "-----END PGP") || strings.HasPrefix(l, "=") && len(l) == 5 {
			out, err := base64.StdEncoding.DecodeString(b64.String())
			if err != nil {
				return nil, fmt.Errorf("armor: %w", err)
			}
			return out, nil
		}
		b64.WriteString(l)
	}
	return nil, errors.New("armor: no END line")
}
