package software

import (
	"sync"
	"time"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// MemHooks keeps watermarks in memory and reads the system
// clock unless Clock is set. For tests and the software backend only:
// nothing survives the process, unless a test hands the same MemHooks to a
// second Signer to play a restart.
type MemHooks struct {
	mu     sync.Mutex
	marks  map[backend.Pubkey]backend.Watermark
	Writes int // watermark writes
	Clock  func() (uint64, error)
}

func NewMemHooks() *MemHooks {
	return &MemHooks{marks: map[backend.Pubkey]backend.Watermark{}}
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

func (m *MemHooks) Now() (uint64, error) {
	if m.Clock != nil {
		return m.Clock()
	}
	return uint64(time.Now().Unix()), nil
}
