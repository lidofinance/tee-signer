package server

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

// A panic in a request is a bug, never a way for a client to stop the
// runner (SHH-03): answer recovers it, logs it with its stack and closes
// that connection; the other connections go on.
//
// Recover policy: a panic in a request
// that changes state (SIGN, the imports, key generation, the handover
// messages, CONFIG_UPDATE, APPROVE_EXIT, any type but the four below) may
// have left that state half written. The runner then refuses every
// request but HEALTH, PUBLIC_KEYS, ATTEST and IDENTITY with NOT_READY
// until it restarts and reads its stored state again, as after ErrLost,
// and HEALTH reports ready false and request_panic. A panic in one of
// those four read-only requests only closes its connection.
//
// Every lock of the server is released by a deferred Unlock or before any
// call that can fail, so a recovered panic leaves no lock held. Some paths
// unlock without defer, though, and a panic there would leave the lock
// held for good: every later request would hang on it. checkAfterPanic
// takes each lock of the server once; if one stays held past
// panicProbeTimeout, the runner is wedged and OnWedged runs (main exits,
// and the supervisor starts the runner again from its stored state).

// panicProbeTimeout bounds the wait for the server's locks after a
// panic. A HANDOVER page holds the source's lock across mark log
// writes, so it is long. A variable so a test can shorten it.
var panicProbeTimeout = 5 * time.Minute

// answer runs one frame's request and returns the response payload. ok
// is false after a panic: the caller closes the connection.
func (s *Server) answer(ctx context.Context, f wire.Frame, cl *client) (payload []byte, ok bool) {
	defer func() {
		if r := recover(); r != nil {
			s.panics.Add(1)
			s.Log.Error("panic in a request, connection closed", "type", f.Type.String(),
				"panic", fmt.Sprint(r), "stack", string(debug.Stack()))
			if !readOnly(f.Type) {
				why := fmt.Sprintf("a %v request panicked (%v): this runner signs, imports and changes nothing until it restarts", f.Type, r)
				if s.panicked.CompareAndSwap(nil, &why) {
					s.Log.Error("state-changing request panicked: refusing every request but HEALTH, PUBLIC_KEYS, ATTEST and IDENTITY until a restart",
						"type", f.Type.String())
				}
			}
			go s.checkAfterPanic(panicProbeTimeout)
			payload, ok = nil, false
		}
	}()
	if s.panicHook != nil {
		s.panicHook(f)
	}
	body, err := s.dispatchFor(ctx, f, cl)
	if err != nil {
		return wire.EncodeError(err), true
	}
	return wire.EncodeOK(body), true
}

// readOnly reports whether a request of type t changes no state: a panic
// in it only closes its connection.
func readOnly(t wire.MsgType) bool {
	switch t {
	case wire.TypeHealth, wire.TypePublicKeys, wire.TypeAttest, wire.TypeIdentity:
		return true
	}
	return false
}

// panicRefusal is the refusal of a runner after a state-changing
// request panicked, nil before.
func (s *Server) panicRefusal() error {
	if why := s.panicked.Load(); why != nil {
		return backend.Refused(backend.StatusNotReady, "%s", *why)
	}
	return nil
}

// Panics is the number of requests that panicked since start.
func (s *Server) Panics() uint64 { return s.panics.Load() }

// checkAfterPanic takes and releases every lock of the server, and runs
// OnWedged when one is still held after wait.
func (s *Server) checkAfterPanic(wait time.Duration) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, l := range s.lockers() {
			l.Lock()
			l.Unlock() //nolint:staticcheck // an empty critical section: the probe
		}
		if s.Signer != nil {
			s.Signer.Keys() // takes the core's lock
		}
	}()
	select {
	case <-done:
		s.Log.Warn("after the panic every lock of the server is free")
	case <-time.After(wait):
		err := fmt.Errorf("a lock of the server is still held %v after a panic: the runner is wedged", wait)
		s.Log.Error("wedged", "err", err)
		if s.OnWedged != nil {
			s.OnWedged(err)
		}
	}
}

// lockers are the server's locks.
func (s *Server) lockers() []sync.Locker {
	ls := []sync.Locker{&s.sharesMu, &s.blockedMu, &s.admitMu, &s.originMu, &s.exits.mu, &s.attestLimit.mu}
	if u := s.Updates; u != nil {
		ls = append(ls, &u.writeMu, &u.mu, &u.srcMu)
	}
	if g := s.Image; g != nil {
		ls = append(ls, &g.mu)
	}
	for _, x := range []any{s.imp, s.handoverSrc} {
		if h, ok := x.(lockHolder); ok {
			ls = append(ls, h.lockers()...)
		}
	}
	return ls
}

// lockHolder is a part of the server with locks of its own: the handover
// source and target of key generation builds.
type lockHolder interface{ lockers() []sync.Locker }
