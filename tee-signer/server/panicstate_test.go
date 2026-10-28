//go:build (peer_azure || peer_aws || peer_gcp || peer_dev) && !debugimport

package server

import (
	"context"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
	"github.com/lidofinance/tee-signer/tee-signer/handover"
)

// ask sends one frame as the local admin, as a connection would (answer
// recovers a panic), and returns the decoded answer.
func (e *tgtEnv) ask(f wire.Frame) (body []byte, err error, ok bool) {
	payload, ok := e.srv.answer(context.Background(), f, localAdmin)
	if !ok {
		return nil, nil, false
	}
	body, err = wire.DecodeResponse(payload)
	return body, err, true
}

// registration is a builder registration of pk the setup allows.
func (e *tgtEnv) registration(pk backend.Pubkey) *backend.ValidatorRegistration {
	return &backend.ValidatorRegistration{FeeRecipient: e.setup.Locked.AllowedFeeRecipients[0], GasLimit: 36_000_000, Timestamp: e.now(), Pubkey: pk}
}

// panicOn makes the next request of type t panic.
func (e *tgtEnv) panicOn(t wire.MsgType) {
	fired := false
	e.srv.panicHook = func(f wire.Frame) {
		if f.Type == t && !fired {
			fired = true
			panic("test panic in " + f.Type.String())
		}
	}
}

// The recover policy: a recovered panic in
// a request that changes state may have left that state half written, so
// the runner refuses everything but HEALTH, PUBLIC_KEYS, ATTEST and
// IDENTITY until it restarts, as after ErrLost, and HEALTH says why. A
// panic in a read-only request only closes its connection.
func TestPanicInAStateChangingRequestRefusesUntilRestart(t *testing.T) {
	changing := []wire.MsgType{wire.TypeSign, wireadmin.TypeImportSealed, wireadmin.TypeConfigUpdate,
		wireadmin.TypeApproveExit, handover.TypeOrder, handover.Type, handover.TypeImport}
	for _, pt := range changing {
		t.Run(pt.String(), func(t *testing.T) {
			e := newTgtEnv(t, "dev", nil)
			sk, pk := newKey(t)
			if err := e.importSealed(pk, sk, 5, nil); err != nil {
				t.Fatal(err)
			}
			e.panicOn(pt)
			if _, _, ok := e.ask(wire.Frame{Type: pt}); ok {
				t.Fatal("the panicking request got an answer; want its connection closed")
			}
			for _, x := range changing {
				_, err, ok := e.ask(wire.Frame{Type: x})
				if !ok || backend.StatusOf(err) != backend.StatusNotReady || !strings.Contains(err.Error(), "panicked") {
					t.Errorf("%v after the panic: %v (answered %v), want NOT_READY naming the panic", x, err, ok)
				}
			}
			reg := e.registration(pk)
			if err := e.signMsg(pk, reg); err == nil {
				t.Error("a registration signed after the panic")
			}
			body, err, ok := e.ask(wire.Frame{Type: wire.TypeHealth})
			if !ok || err != nil {
				t.Fatalf("HEALTH after the panic: %v (answered %v)", err, ok)
			}
			h, err := wire.DecodeHealth(body)
			if err != nil {
				t.Fatal(err)
			}
			if h.Ready || !strings.Contains(h.RequestPanic, pt.String()) {
				t.Errorf("HEALTH after the panic: ready %v, request_panic %q", h.Ready, h.RequestPanic)
			}
			if _, err, ok := e.ask(wire.Frame{Type: wire.TypePublicKeys}); !ok || err != nil {
				t.Errorf("PUBLIC_KEYS after the panic: %v (answered %v)", err, ok)
			}
			// A restart clears it: the stored state is read again.
			e.restart()
			reg.Timestamp++
			if err := e.signMsg(pk, reg); err != nil {
				t.Errorf("a registration after the restart: %v", err)
			}
		})
	}
}

func TestPanicInAReadOnlyRequestOnlyClosesItsConnection(t *testing.T) {
	for _, pt := range []wire.MsgType{wire.TypeHealth, wire.TypePublicKeys, wire.TypeAttest, wire.TypeIdentity} {
		t.Run(pt.String(), func(t *testing.T) {
			e := newTgtEnv(t, "dev", nil)
			sk, pk := newKey(t)
			if err := e.importSealed(pk, sk, 5, nil); err != nil {
				t.Fatal(err)
			}
			e.panicOn(pt)
			if _, _, ok := e.ask(wire.Frame{Type: pt}); ok {
				t.Fatal("the panicking request got an answer; want its connection closed")
			}
			if err := e.signMsg(pk, e.registration(pk)); err != nil {
				t.Errorf("a registration after a read-only panic: %v", err)
			}
			body, err, _ := e.ask(wire.Frame{Type: wire.TypeHealth})
			h, herr := wire.DecodeHealth(body)
			if err != nil || herr != nil || !h.Ready || h.RequestPanic != "" {
				t.Errorf("HEALTH after a read-only panic: %+v %v %v", h, err, herr)
			}
		})
	}
}
