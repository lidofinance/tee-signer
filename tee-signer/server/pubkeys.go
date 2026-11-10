package server

import (
	"sync"

	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

// keysAnswer holds the PUBLIC_KEYS answer, status included, built once
// per key set. Every connection writes the same bytes
// (wire.WriteSharedFrame), so a peer that asks for the keys and stops
// reading holds no copy of the list. At 8192 keys a copy is 852 KB; 256
// stalled connections with one each held 221 MB of a 512 MiB enclave.
type keysAnswer struct {
	mu      sync.Mutex
	n       int
	payload []byte
}

// publicKeys is the PUBLIC_KEYS response payload. Nobody may change it.
// The core only adds keys, so the cached answer is current while the
// core's key count equals its count.
func (s *Server) publicKeys() []byte {
	a := &s.keysAnswer
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.payload == nil || s.Signer.KeyCount() != a.n {
		keys := s.Signer.Keys()
		a.n, a.payload = len(keys), wire.EncodeOK(wire.EncodeKeys(keys))
	}
	return a.payload
}
