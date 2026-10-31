package statestore

import (
	"bytes"
	"testing"

	"github.com/lidofinance/tee-signer/devkit/fuzzcheck"
)

// A commit body is read from the host's storage
// after the open. Oracles: no panic, bounded allocation, and what decodes
// encodes back to the same bytes.

func FuzzDecodeBody(f *testing.F) {
	f.Add(encodeBody(&commitBody{prevVersion: 1, chain: 1}), uint64(2))
	f.Add(encodeBody(&commitBody{prevVersion: 4, chain: 2, segs: []*segment{{created: 3, count: 2, size: 9,
		chunks: []chunkRef{{sum: [32]byte{1}, size: 9}}}},
		ops: []entryOp{{key: "shares/aa", op: op{val: []byte{1, 2}}}, {key: "shares/bb", op: op{del: true}}}}), uint64(5))
	f.Fuzz(func(t *testing.T, b []byte, version uint64) {
		fuzzcheck.Watch(t)
		var body *commitBody
		var err error
		fuzzcheck.Bounded(t, len(b), func() { body, err = decodeBody(b, version) })
		if err != nil {
			return
		}
		if again := encodeBody(body); !bytes.Equal(again, b) {
			t.Fatalf("commit body does not encode back:\n%x\n%x", again, b)
		}
	})
}
