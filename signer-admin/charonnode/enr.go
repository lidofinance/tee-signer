package charonnode

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
)

// ENRKey returns the compressed secp256k1 public key of an "enr:" record
// (EIP-778): base64url of the RLP list [signature, seq, k1, v1, ...]. It
// does not check the record's signature; Charon does that when it loads
// the lock.
func ENRKey(enr string) ([]byte, error) {
	if !strings.HasPrefix(enr, "enr:") {
		return nil, errors.New("charonnode: not an enr: record")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(enr, "enr:"))
	if err != nil {
		return nil, errors.New("charonnode: ENR is not base64url")
	}
	items, err := rlpList(raw)
	if err != nil {
		return nil, err
	}
	// items: signature, seq, then key/value pairs.
	if len(items) < 2 || len(items)%2 != 0 {
		return nil, errors.New("charonnode: ENR list has the wrong length")
	}
	for i := 2; i+1 < len(items); i += 2 {
		if bytes.Equal(items[i], []byte("secp256k1")) {
			if len(items[i+1]) != 33 {
				return nil, errors.New("charonnode: ENR secp256k1 key is not 33 bytes")
			}
			return items[i+1], nil
		}
	}
	return nil, errors.New("charonnode: ENR has no secp256k1 key")
}

// rlpList decodes one RLP list of byte strings (no nested lists).
func rlpList(b []byte) ([][]byte, error) {
	payload, rest, list, err := rlpItem(b)
	if err != nil {
		return nil, err
	}
	if !list || len(rest) != 0 {
		return nil, errors.New("charonnode: ENR is not one RLP list")
	}
	var out [][]byte
	for len(payload) > 0 {
		v, r, isList, err := rlpItem(payload)
		if err != nil {
			return nil, err
		}
		if isList {
			return nil, errors.New("charonnode: nested list in ENR")
		}
		out = append(out, v)
		payload = r
	}
	return out, nil
}

// rlpItem splits off one RLP item: its payload, the rest, and whether it is
// a list.
func rlpItem(b []byte) (payload, rest []byte, list bool, err error) {
	bad := errors.New("charonnode: bad RLP")
	if len(b) == 0 {
		return nil, nil, false, bad
	}
	p := b[0]
	length := func(n int) (int, error) {
		if n == 0 || n > 4 || len(b) < 1+n {
			return 0, bad
		}
		l := 0
		for _, c := range b[1 : 1+n] {
			l = l<<8 | int(c)
		}
		return l, nil
	}
	var start, size int
	switch {
	case p < 0x80:
		return b[:1], b[1:], false, nil
	case p <= 0xb7:
		start, size = 1, int(p-0x80)
	case p <= 0xbf:
		n := int(p - 0xb7)
		l, err := length(n)
		if err != nil {
			return nil, nil, false, err
		}
		start, size = 1+n, l
	case p <= 0xf7:
		start, size, list = 1, int(p-0xc0), true
	default:
		n := int(p - 0xf7)
		l, err := length(n)
		if err != nil {
			return nil, nil, false, err
		}
		start, size, list = 1+n, l, true
	}
	if len(b) < start+size {
		return nil, nil, false, bad
	}
	return b[start : start+size], b[start+size:], list, nil
}
