package admin_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-admin/remote/admin"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

// configRunner answers IDENTITY with the dev platform's document over its
// state, and CONFIG_UPDATE: an update it has not seen becomes the pending
// locked update (accepted), the same bytes again are known, and an update
// that starts with "bad" is refused.
type configRunner struct {
	mu    sync.Mutex
	state backend.SetupState
	seen  map[string]bool
	// forge makes IDENTITY bind other user data, as a relay that changed the
	// state would.
	forge bool
}

func (r *configRunner) start(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go r.serve(c)
		}
	}()
	return "tcp:" + ln.Addr().String()
}

func (r *configRunner) serve(c net.Conn) {
	defer c.Close()
	for {
		f, err := wire.ReadFrame(c)
		if err != nil {
			return
		}
		var answer []byte
		switch f.Type {
		case wire.TypeIdentity:
			nonce, err := wire.DecodeAttest(f.Payload)
			if err != nil {
				return
			}
			r.mu.Lock()
			id := &backend.Identity{State: r.state}
			forge := r.forge
			r.mu.Unlock()
			ud := backend.IdentityUserData(nonce, id)
			if forge {
				id.State.Locked.Version++
			}
			doc, _ := json.Marshal(map[string]any{"nonce": nonce, "user_data": ud})
			id.Attestation = &backend.Attestation{Platform: "dev", Format: "dev-json", UserData: ud, Document: doc}
			b, err := wire.EncodeIdentity(id)
			if err != nil {
				return
			}
			answer = wire.EncodeOK(b)
		case wireadmin.TypeConfigUpdate:
			raw, err := wireadmin.DecodeConfigUpdate(f.Payload)
			switch {
			case err != nil:
				answer = wire.EncodeError(backend.Refused(backend.StatusBadRequest, "%v", err))
			case bytes.HasPrefix(raw, []byte("bad")):
				answer = wire.EncodeError(backend.Refused(backend.StatusBadRequest, "config update: prev_hash is not the locked update in force"))
			default:
				r.mu.Lock()
				outcome := wireadmin.ConfigKnown
				if !r.seen[string(raw)] {
					r.seen[string(raw)] = true
					outcome = wireadmin.ConfigAccepted
					r.state.Locked.Pending = backend.PendingUpdate{Version: r.state.Locked.Version + 1, Hash: backend.Root{byte(len(raw))}, EffectiveAt: 1_800_000_000}
				}
				answer = wire.EncodeOK(wireadmin.EncodeConfigUpdateResponse(outcome, &r.state))
				r.mu.Unlock()
			}
		default:
			answer = wire.EncodeError(backend.Refused(backend.StatusUnsupported, "message type %v", f.Type))
		}
		if wire.WriteFrame(c, wire.Frame{Type: f.Type | wire.ResponseFlag, ID: f.ID, Payload: answer}) != nil {
			return
		}
	}
}

// ConfigUpdate sends the update and returns the runner's answer: accepted
// with the update pending, known when sent again, and a refusal with the
// runner's reason.
func TestConfigUpdate(t *testing.T) {
	r := &configRunner{seen: map[string]bool{}, state: backend.SetupState{SetupHash: backend.Root{1}, Locked: backend.ConfigGroup{Version: 2, Hash: backend.Root{2}}}}
	c, err := admin.New(r.start(t), remote.WithTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx := context.Background()
	update := []byte("U an update")

	outcome, st, err := c.ConfigUpdate(ctx, update)
	if err != nil || outcome != wireadmin.ConfigAccepted {
		t.Fatalf("first: outcome %d, %v", outcome, err)
	}
	if p := st.Locked.Pending; p.Version != 3 || p.EffectiveAt != 1_800_000_000 {
		t.Fatalf("state after the update: %+v", st.Locked)
	}
	outcome, st2, err := c.ConfigUpdate(ctx, update)
	if err != nil || outcome != wireadmin.ConfigKnown || *st2 != *st {
		t.Fatalf("again: outcome %d, state %+v, %v", outcome, st2, err)
	}

	_, _, err = c.ConfigUpdate(ctx, []byte("bad update"))
	var refused *backend.RefusedError
	if !errors.As(err, &refused) || refused.Code != backend.StatusBadRequest || !strings.Contains(refused.Detail, "prev_hash") {
		t.Fatalf("refusal: %v", err)
	}
	if _, _, err := c.ConfigUpdate(ctx, nil); err == nil {
		t.Fatal("an empty update was sent")
	}
	if _, _, err := c.ConfigUpdate(ctx, make([]byte, wireadmin.MaxConfigUpdate+1)); err == nil {
		t.Fatal("an update above the cap was sent")
	}
}
