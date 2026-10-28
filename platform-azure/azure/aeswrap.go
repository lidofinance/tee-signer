package azure

import (
	"crypto/aes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

// kwpAIV is the high half of the alternative initial value of RFC 5649.
var kwpAIV = [4]byte{0xA6, 0x59, 0x59, 0xA6}

// aesUnwrapWithPadding is the AES Key Unwrap with Padding algorithm of
// RFC 5649, section 4.2, with kek as the AES key. The test vectors of the
// RFC are in aeswrap_test.go.
func aesUnwrapWithPadding(kek, c []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	if len(c)%8 != 0 || len(c) < 16 {
		return nil, errors.New("aes key unwrap: the wrapped key has a bad length")
	}
	n := len(c)/8 - 1 // 64-bit blocks of the padded key
	var a [8]byte
	r := make([]byte, 8*n)
	var buf [16]byte
	if n == 1 {
		block.Decrypt(buf[:], c)
		copy(a[:], buf[:8])
		copy(r, buf[8:])
	} else {
		// RFC 3394 unwrap, six rounds.
		copy(a[:], c[:8])
		copy(r, c[8:])
		for j := 5; j >= 0; j-- {
			for i := n; i >= 1; i-- {
				t := uint64(n*j + i)
				binary.BigEndian.PutUint64(buf[:8], binary.BigEndian.Uint64(a[:])^t)
				copy(buf[8:], r[(i-1)*8:i*8])
				block.Decrypt(buf[:], buf[:])
				copy(a[:], buf[:8])
				copy(r[(i-1)*8:i*8], buf[8:])
			}
		}
	}
	if subtle.ConstantTimeCompare(a[:4], kwpAIV[:]) != 1 {
		return nil, errors.New("aes key unwrap: integrity check failed")
	}
	mli := int(binary.BigEndian.Uint32(a[4:]))
	if mli <= 8*(n-1) || mli > 8*n {
		return nil, errors.New("aes key unwrap: bad length indicator")
	}
	for _, x := range r[mli:] {
		if x != 0 {
			return nil, errors.New("aes key unwrap: bad padding")
		}
	}
	return r[:mli], nil
}
