package approver

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/devkit/fuzzcheck"
)

// Fuzz targets for the bytes an approver tool reads from others: the
// exported OpenPGP public key of approver-key -openpgp, and the
// s-expressions a gpg-agent answers with.

// pgpPacket wraps body in a new-format packet header with tag.
func pgpPacket(tag byte, body []byte) []byte {
	out := []byte{0xc0 | tag}
	switch n := len(body); {
	case n < 192:
		out = append(out, byte(n))
	case n < 8384:
		n -= 192
		out = append(out, byte(n>>8)+192, byte(n))
	default:
		out = append(out, 255, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	return append(out, body...)
}

// pgpEdDSAKey is a v4 EdDSALegacy key packet body (algorithm 22, the
// Ed25519 OID, a 0x40-prefixed point of fill bytes).
func pgpEdDSAKey(fill byte) []byte {
	b := append([]byte{4, 0x65, 0, 0, 0, 22, byte(len(ed25519OID))}, ed25519OID...)
	b = append(b, 0x01, 0x07, 0x40)
	return append(b, bytes.Repeat([]byte{fill}, 32)...)
}

// pgpEd25519Key is a v4 RFC 9580 Ed25519 (algorithm 27) key packet body.
func pgpEd25519Key(fill byte) []byte {
	return append([]byte{4, 0x65, 0, 0, 0, 27}, bytes.Repeat([]byte{fill}, 32)...)
}

// pgpSig is a v4 signature packet body of type typ whose hashed area holds
// a key flags subpacket with flags; the MPIs are not a real signature
// (the parser reads the flags, it does not verify).
func pgpSig(typ, flags byte) []byte {
	hashed := []byte{2, 27, flags, 5, 2, 0x65, 0, 0, 0}
	b := append([]byte{4, typ, 22, 8, byte(len(hashed) >> 8), byte(len(hashed))}, hashed...)
	return append(b, 0, 0, 0xab, 0xcd, 0, 8, 1, 0, 8, 1)
}

// pgpExport is the shape of gpg --export of an approver key: a primary
// key with a user ID and certification, an EdDSALegacy signing subkey and
// an RFC 9580 Ed25519 signing subkey, each with its binding.
func pgpExport() []byte {
	return bytes.Join([][]byte{
		pgpPacket(6, pgpEdDSAKey(0x11)),
		pgpPacket(13, []byte("approver <approver@example.invalid>")),
		pgpPacket(2, pgpSig(0x13, 0x03)),
		pgpPacket(14, pgpEdDSAKey(0x22)),
		pgpPacket(2, pgpSig(0x18, 0x02)),
		pgpPacket(14, pgpEd25519Key(0x33)),
		pgpPacket(2, pgpSig(0x18, 0x02)),
	}, nil)
}

// pgpArmor is the armored form of a binary export (the checksum line is
// not checked by the parser).
func pgpArmor(b []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(b)
	var s strings.Builder
	s.WriteString("-----BEGIN PGP PUBLIC KEY BLOCK-----\nComment: test\n\n")
	for len(enc) > 64 {
		s.WriteString(enc[:64] + "\n")
		enc = enc[64:]
	}
	s.WriteString(enc + "\n=ABCD\n-----END PGP PUBLIC KEY BLOCK-----\n")
	return []byte(s.String())
}

// The seed export gives its three Ed25519 keys, armored or not.
func TestOpenPGPExportSeed(t *testing.T) {
	for _, in := range [][]byte{pgpExport(), pgpArmor(pgpExport())} {
		keys, err := OpenPGPEd25519Keys(in)
		if err != nil || len(keys) != 3 || !keys[1].CanSign || !keys[2].CanSign {
			t.Fatalf("seed export: %+v %v", keys, err)
		}
	}
}

// Any bytes as an exported key: no panic, every key returned has a 32-byte
// public key, and a binary export the parser takes reads the same in its
// armored form.
func FuzzOpenPGPEd25519Keys(f *testing.F) {
	bin, arm := pgpExport(), pgpArmor(pgpExport())
	f.Add(bin)
	f.Add(arm)
	for _, n := range []int{1, 2, 20, len(bin) / 2, len(bin) - 1} {
		f.Add(bin[:n])
	}
	f.Add(arm[:len(arm)/2])
	f.Add(pgpPacket(6, pgpEd25519Key(0x44)))
	f.Add([]byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzcheck.Watch(t)
		keys, err := OpenPGPEd25519Keys(data)
		if err != nil {
			return
		}
		for _, k := range keys {
			if len(k.Public) != 32 {
				t.Fatalf("key with a %d-byte public key", len(k.Public))
			}
		}
		if k, err := SelectOpenPGPKey(keys, ""); err == nil && len(k.Public) != 32 {
			t.Fatalf("selected a key with a %d-byte public key", len(k.Public))
		}
		if bytes.Contains(data, []byte("-----BEGIN PGP")) {
			return
		}
		armored, err := OpenPGPEd25519Keys(pgpArmor(data))
		if err != nil || !reflect.DeepEqual(armored, keys) {
			t.Fatalf("the armored form reads differently: %+v %v, binary %+v", armored, err, keys)
		}
	})
}

// encodeSexp writes s in canonical form.
func encodeSexp(s sexp) []byte {
	if s.atom != nil {
		return fmt.Appendf(nil, "%d:%s", len(s.atom), s.atom)
	}
	out := []byte{'('}
	for _, e := range s.list {
		out = append(out, encodeSexp(e)...)
	}
	return append(out, ')')
}

// Any bytes as a gpg-agent answer: no panic, a key is 32 bytes and a
// signature 64, and what parseSexp takes reads back the same from its
// canonical form.
func FuzzParseSexp(f *testing.F) {
	k32 := string(bytes.Repeat([]byte{7}, 32))
	f.Add([]byte("(10:public-key(3:ecc(5:curve7:Ed25519)(5:flags5:eddsa)(1:q33:\x40" + k32 + ")))"))
	f.Add([]byte("(7:sig-val(5:eddsa(1:r31:" + k32[:31] + ")(1:s32:" + string(bytes.Repeat([]byte{2}, 32)) + ")))"))
	f.Add([]byte("(10:public-key(3:ecc(5:curve10:Curve25519)(1:q33:\x40" + k32 + ")))"))
	f.Add([]byte("()"))
	f.Add([]byte("(((("))
	f.Add([]byte("0:"))
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzcheck.Watch(t)
		if k, err := ed25519FromSexp(data); err == nil && len(k) != 32 {
			t.Fatalf("a key of %d bytes", len(k))
		}
		if s, err := ed25519SigFromSexp(data); err == nil && len(s) != 64 {
			t.Fatalf("a signature of %d bytes", len(s))
		}
		s, err := parseSexp(data)
		if err != nil {
			return
		}
		again, err := parseSexp(encodeSexp(s))
		if err != nil || !reflect.DeepEqual(again, s) {
			t.Fatalf("the canonical form %q reads back as %+v, %v", encodeSexp(s), again, err)
		}
	})
}
