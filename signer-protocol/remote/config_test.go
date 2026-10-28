package remote_test

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

// SetupState returns the state of a fresh, verified IDENTITY, and refuses
// one whose user data does not cover the state or that the verifier refuses.
func TestSetupState(t *testing.T) {
	want := backend.SetupState{SetupHash: backend.Root{7}, Locked: backend.ConfigGroup{Version: 1, Hash: backend.Root{8}},
		Open: backend.ConfigGroup{Hash: backend.Root{9}}, ApproverSetHash: backend.Root{10}}
	r := &configRunner{seen: map[string]bool{}, state: want}
	c, err := remote.New(r.start(t), remote.WithTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx := context.Background()

	if _, err := c.SetupState(ctx, nil); err == nil {
		t.Fatal("a state without a verifier")
	}
	got, err := c.SetupState(ctx, remote.DevVerifier)
	if err != nil || *got != want {
		t.Fatalf("state %+v, %v", got, err)
	}
	no := errors.New("not this runner")
	if _, err := c.SetupState(ctx, func(context.Context, []byte, *backend.Identity) error { return no }); !errors.Is(err, no) {
		t.Fatalf("a refused attestation: %v", err)
	}
	r.mu.Lock()
	r.forge = true
	r.mu.Unlock()
	if _, err := c.SetupState(ctx, remote.DevVerifier); err == nil || !strings.Contains(err.Error(), "user data") {
		t.Fatalf("a state the attestation does not cover: %v", err)
	}
}
