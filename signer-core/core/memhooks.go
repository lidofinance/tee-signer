package core

import (
	"errors"
	"sync"
	"time"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

var errStoreFailed = errors.New("memhooks: store failed (FailRoots)")

// MemHooks keeps watermarks and repeat roots in memory and reads the system
// clock unless Clock is set. For tests and the software backend only:
// nothing survives the process, unless a test hands the same MemHooks to a
// second Signer to play a restart.
type MemHooks struct {
	mu         sync.Mutex
	marks      map[backend.Pubkey]backend.Watermark
	roots      map[backend.Pubkey][]byte
	Writes     int // watermark writes
	RootWrites int // repeat root writes
	FailRoots  bool
	Clock      func() (uint64, error)
}

var _ RepeatRootHooks = (*MemHooks)(nil)

func NewMemHooks() *MemHooks {
	return &MemHooks{marks: map[backend.Pubkey]backend.Watermark{}, roots: map[backend.Pubkey][]byte{}}
}

func (m *MemHooks) LoadWatermark(pk backend.Pubkey) (backend.Watermark, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	wm, ok := m.marks[pk]
	return wm, ok, nil
}

func (m *MemHooks) StoreWatermark(pk backend.Pubkey, wm backend.Watermark) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.marks[pk] = wm
	m.Writes++
	return nil
}

func (m *MemHooks) LoadRepeatRoots(pk backend.Pubkey) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.roots[pk]
	return append([]byte(nil), rec...), ok, nil
}

func (m *MemHooks) StoreRepeatRoots(pk backend.Pubkey, rec []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailRoots {
		return errStoreFailed
	}
	m.roots[pk] = append([]byte(nil), rec...)
	m.RootWrites++
	return nil
}

func (m *MemHooks) Now() (uint64, error) {
	if m.Clock != nil {
		return m.Clock()
	}
	return uint64(time.Now().Unix()), nil
}
