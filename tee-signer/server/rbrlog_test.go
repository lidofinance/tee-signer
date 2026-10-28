//go:build (peer_azure || peer_aws || peer_gcp || peer_dev) && !debugimport

package server

import (
	"errors"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	"github.com/lidofinance/tee-signer/slashing-log"
)

// RBRLOG-03: a runner whose mark log latched ErrLost (a clone took the log
// over) must sign nothing, also messages that write no record (builder
// registrations under its old fee recipient list). It stays up and HEALTH
// says why.
func TestRBRLOG03LostRunnerSignsNothing(t *testing.T) {
	a := newTgtEnv(t, "dev", nil)
	sk, pk := newKey(t)
	if err := a.importSealed(pk, sk, 5, nil); err != nil {
		t.Fatal(err)
	}
	reg := &backend.ValidatorRegistration{FeeRecipient: a.setup.Locked.AllowedFeeRecipients[0], GasLimit: 36_000_000, Timestamp: a.now(), Pubkey: pk}
	if err := a.signMsg(pk, reg); err != nil {
		t.Fatalf("registration before the takeover: %v", err)
	}

	// A clone of the same image and store claims the log.
	b := *a
	b.start()

	// A's next cover write conflicts and latches ErrLost.
	e := a.signer.EpochAt(a.now())
	if err := a.signer.CoverEpoch(e + 10); err == nil {
		t.Fatal("A's cover write went through after the clone's claim")
	}
	if !errors.Is(a.marks.Lost(), markstore.ErrLost) {
		t.Fatalf("A's mark log: lost %v, want ErrLost", a.marks.Lost())
	}

	reg.Timestamp++
	err := a.signMsg(pk, reg)
	if err == nil {
		t.Error("A signed a registration after it lost its mark log")
	}
	h, herr := a.srv.health()
	if herr != nil {
		t.Fatal(herr)
	}
	if h.Ready || !strings.Contains(h.MarkLogLost, "another runner instance") {
		t.Errorf("HEALTH after the loss: ready %v, mark_log_lost %q", h.Ready, h.MarkLogLost)
	}
	// Status, keys and attestation still answer.
	if _, err := a.srv.dispatch(ctx, wire.Frame{Type: wire.TypeHealth}); err != nil {
		t.Errorf("HEALTH refused: %v", err)
	}
}
