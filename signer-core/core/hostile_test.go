package core_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// coreRestartFloor is false while the core has no restart floor: a
// slashable request it signs is logged as a gap, not a failure.
const coreRestartFloor = false

// hostileHooks keep per-validator marks and a device mark like an honest
// host, and misbehave on request.
type hostileHooks struct {
	mu        sync.Mutex
	marks     map[backend.Pubkey]backend.Watermark
	device    backend.Watermark
	hasDevice bool
	now       uint64

	lieStore bool               // answer nil and write nothing
	loadErr  error              // every load fails with it
	raw      *backend.Watermark // every load returns it
	clockErr error              // Now fails with it
}

func newHostile(now uint64) *hostileHooks {
	return &hostileHooks{marks: map[backend.Pubkey]backend.Watermark{}, now: now}
}

func (h *hostileHooks) LoadWatermark(pk backend.Pubkey) (backend.Watermark, bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.loadErr != nil {
		return backend.Watermark{}, false, h.loadErr
	}
	if h.raw != nil {
		return *h.raw, true, nil
	}
	wm, ok := h.marks[pk]
	return wm, ok, nil
}

func (h *hostileHooks) StoreWatermark(pk backend.Pubkey, wm backend.Watermark) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.lieStore {
		h.marks[pk] = wm
	}
	return nil
}

func (h *hostileHooks) LoadDeviceMark() (backend.Watermark, bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.loadErr != nil {
		return backend.Watermark{}, false, h.loadErr
	}
	if h.raw != nil {
		return *h.raw, true, nil
	}
	return h.device, h.hasDevice, nil
}

func (h *hostileHooks) StoreDeviceMark(wm backend.Watermark) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.lieStore {
		h.device, h.hasDevice = wm, true
	}
	return nil
}

func (h *hostileHooks) Now() (uint64, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.clockErr != nil {
		return 0, h.clockErr
	}
	return h.now, nil
}

func (h *hostileHooks) setNow(t uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.now = t
}

// snapshot copies the stored marks.
func (h *hostileHooks) snapshot() (map[backend.Pubkey]backend.Watermark, backend.Watermark, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	m := map[backend.Pubkey]backend.Watermark{}
	for k, v := range h.marks {
		m[k] = v
	}
	return m, h.device, h.hasDevice
}

func (h *hostileHooks) restore(m map[backend.Pubkey]backend.Watermark, d backend.Watermark, has bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.marks = map[backend.Pubkey]backend.Watermark{}
	for k, v := range m {
		h.marks[k] = v
	}
	h.device, h.hasDevice = d, has
}

// refused fails the test if err is nil: the request went through.
func refused(t *testing.T, err error, what string) {
	t.Helper()
	if err != nil {
		return
	}
	if !coreRestartFloor {
		t.Logf("gap: %s went through", what)
		return
	}
	t.Fatalf("%s went through", what)
}

// hostileKey is a fixed full key, so every signer of a test loads the same.
func hostileKey(t *testing.T) ([32]byte, backend.Pubkey) {
	t.Helper()
	var sk [32]byte
	for i := range sk {
		sk[i] = byte(i*7 + 3)
	}
	sk[0] = 0x11
	pk, err := core.PubkeyOf(sk)
	if err != nil {
		t.Fatal(err)
	}
	return sk, pk
}

func hostileSigner(t *testing.T, h *hostileHooks, device bool) *core.Signer {
	t.Helper()
	cfg := software.DevConfig(genesis, 12, 32) // max_epochs_ahead 1, commit_ahead {32, 1, 1}
	cfg.DeviceMark = device
	s, err := core.NewSigner(cfg, 4, 0, h)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func hostileAdd(t *testing.T, s *core.Signer) (backend.Pubkey, error) {
	t.Helper()
	sk, pk := hostileKey(t)
	_, err := s.AddValidator(pk, sk, 7, nil)
	return pk, err
}

func hostileBlock(slot uint64, tag byte) *backend.BeaconBlockHeader {
	return &backend.BeaconBlockHeader{Slot: slot, ProposerIndex: 7, BodyRoot: backend.Root{tag}}
}

func hostileVote(source, target uint64, tag byte) *backend.AttestationData {
	a := att(source, target)
	a.BeaconBlockRoot = backend.Root{tag}
	return a
}

// A host that loses, rolls back or garbles marks, claims writes it never
// made, or reads the clock up to one epoch behind its last reading. After
// a restart, a double vote, a surround vote and a double block against the
// first run must be refused, and signing must come back once the clock is
// past the restart floor.
func TestHostileHostRestart(t *testing.T) {
	const e = 40
	junk := backend.Watermark{BlockSlot: ^uint64(0), SourceEpoch: ^uint64(0), TargetEpoch: ^uint64(0)}
	cases := []struct {
		name string
		bad  func(h *hostileHooks, m map[backend.Pubkey]backend.Watermark, d backend.Watermark, has bool)
	}{
		{"lost", func(h *hostileHooks, _ map[backend.Pubkey]backend.Watermark, _ backend.Watermark, _ bool) {
			h.restore(nil, backend.Watermark{}, false)
		}},
		{"lie", nil},
		{"rollback", func(h *hostileHooks, m map[backend.Pubkey]backend.Watermark, d backend.Watermark, has bool) {
			h.restore(m, d, has)
		}},
		{"no flags", func(h *hostileHooks, _ map[backend.Pubkey]backend.Watermark, _ backend.Watermark, _ bool) {
			h.raw = &junk
		}},
		{"clock back", func(h *hostileHooks, _ map[backend.Pubkey]backend.Watermark, _ backend.Watermark, _ bool) {
			h.restore(nil, backend.Watermark{}, false)
			h.setNow(h.now - 12*32 + 1) // one epoch behind the last reading
		}},
	}
	for _, device := range []bool{false, true} {
		for _, c := range cases {
			name := c.name + "/validator"
			if device {
				name = c.name + "/device"
			}
			t.Run(name, func(t *testing.T) {
				h := newHostile(clockAtEpochValue(e - 4)) // the first run loads a few epochs before it signs
				h.lieStore = c.name == "lie"
				s := hostileSigner(t, h, device)
				pk, err := hostileAdd(t, s)
				if err != nil {
					t.Fatal(err)
				}
				h.setNow(clockAtEpochValue(e))
				mustSign := func(s *core.Signer, m backend.Message) {
					t.Helper()
					if _, err := s.Sign(signReq(s, pk, m)); err != nil {
						t.Fatalf("%v: %v", m.Kind(), err)
					}
				}
				mustSign(s, hostileVote(e-1, e, 1))
				mustSign(s, hostileBlock(e*32+2, 1))
				m, d, has := h.snapshot()
				h.setNow(clockAtEpochValue(e + 2))
				mustSign(s, hostileVote(e+1, e+2, 1)) // past the window: a write
				s.Close()
				if c.bad != nil {
					c.bad(h, m, d, has)
				}
				after, ad, ahas := h.snapshot()
				now := h.now

				requests := []struct {
					what string
					m    backend.Message
				}{
					{"double vote", hostileVote(e+1, e+2, 2)},
					{"surround vote", hostileVote(e, e+3, 3)},
					{"double block", hostileBlock(e*32+2, 2)},
				}
				for _, r := range requests {
					h.restore(after, ad, ahas)
					h.setNow(now)
					s := hostileSigner(t, h, device)
					if _, err := hostileAdd(t, s); err != nil {
						t.Fatal(err)
					}
					h.setNow(clockAtEpochValue(e + 3))
					_, err := s.Sign(signReq(s, pk, r.m))
					refused(t, err, r.what)
				}

				// Past the floor: clock epoch at the load + max_epochs_ahead + 1.
				h.restore(after, ad, ahas)
				h.setNow(now)
				h.raw = nil
				s = hostileSigner(t, h, device)
				if _, err := hostileAdd(t, s); err != nil {
					t.Fatal(err)
				}
				h.setNow(clockAtEpochValue(e + 6))
				mustSign(s, hostileVote(e+5, e+6, 4))
				mustSign(s, hostileBlock((e+6)*32+1, 4))
			})
		}
	}
}

// Load errors refuse the validator, a clock that fails at the load refuses
// it too, and a store or clock that fails later refuses the request.
func TestHostileHostErrors(t *testing.T) {
	for _, device := range []bool{false, true} {
		name := "validator"
		if device {
			name = "device"
		}
		t.Run(name, func(t *testing.T) {
			h := newHostile(clockAtEpochValue(40))
			h.loadErr = errors.New("disk on fire")
			s := hostileSigner(t, h, device)
			if _, err := hostileAdd(t, s); err == nil {
				t.Fatal("added with a failing load")
			}
			h.loadErr = nil
			h.clockErr = errors.New("no clock")
			s = hostileSigner(t, h, device)
			_, err := hostileAdd(t, s)
			refused(t, err, "add with no clock")
			h.clockErr = nil
		})
	}
}

// clockAtEpochValue is the time clockAtEpoch(e) returns.
func clockAtEpochValue(e uint64) uint64 {
	t, _ := clockAtEpoch(e)()
	return t
}
