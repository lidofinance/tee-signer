package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	"github.com/lidofinance/tee-signer/trusted-time/clock"
)

// The key origin counts the loaded keys, after a restart too, and ATTEST
// binds it with keys_hash over the same keys. A runner without a setup
// reports none.
func TestKeyOrigin(t *testing.T) {
	store := &shareStore{m: map[string][]byte{}}
	setup, logID := [32]byte{0xa}, [32]byte{1}
	s := shareServer(t, store, setup, logID)
	s.State = constState(backend.SetupState{SetupHash: setup})
	if ko := s.SetupState().KeyOrigin; ko != (backend.KeyOrigin{}) {
		t.Fatalf("no key: %+v", ko)
	}
	for i := range 4 {
		sk, _ := software.NewSecret()
		pk, _ := core.PubkeyOf(sk)
		if _, err := s.addShare(pk, &sk, uint64(7+i), nil, "sealed"); err != nil {
			t.Fatal(err)
		}
		if ko := s.SetupState().KeyOrigin; ko != (backend.KeyOrigin{Imported: uint32(i + 1)}) {
			t.Fatalf("%d imports: %+v", i+1, ko)
		}
	}

	// A restart.
	listed, _ := ListShares(store)
	r := shareServer(t, store, setup, logID)
	r.State = constState(backend.SetupState{SetupHash: setup})
	r.Platform.Attester, r.Platform.Clock = fakeAttester{}, clock.System{}
	r.KeyReleaseHash, r.KeyLock = [32]byte{0x77}, backend.KeyLockLocked
	if n, err := r.LoadListedShares(listed); n != 4 || err != nil {
		t.Fatalf("loaded %d: %v", n, err)
	}
	want := backend.KeyOrigin{Imported: 4}
	if ko := r.SetupState().KeyOrigin; ko != want {
		t.Fatalf("after the restart: %+v, want %+v", ko, want)
	}

	nonce := bytes.Repeat([]byte{9}, 32)
	payload, _ := wire.EncodeAttest(nonce)
	body, err := r.dispatch(context.Background(), wire.Frame{Type: wire.TypeAttest, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	st, a, err := wire.DecodeAttestResponse(body)
	if err != nil {
		t.Fatal(err)
	}
	if st.KeyOrigin != want || st.KeyReleaseHash != r.KeyReleaseHash {
		t.Fatalf("ATTEST carries %+v and key_release_hash %x", st.KeyOrigin, st.KeyReleaseHash)
	}
	if !bytes.Equal(a.UserData, backend.AttestUserData(nonce, st, backend.KeysHash(r.Signer.Keys()))) {
		t.Fatal("the ATTEST user data does not bind the key origin with the loaded keys")
	}
	h, _ := r.health()
	if h.Setup.KeyOrigin != want || h.KeyLock != "locked" {
		t.Fatalf("HEALTH carries %+v, key_lock %q", h.Setup.KeyOrigin, h.KeyLock)
	}

	// The flag path: no setup, no key origin and no key_release_hash.
	flag := shareServer(t, store, [32]byte{}, [32]byte{})
	flag.State = constState(backend.SetupState{SetupHash: backend.Root{0xf}})
	flag.KeyReleaseHash = [32]byte{0x77}
	fsk, _ := software.NewSecret()
	fpk, _ := core.PubkeyOf(fsk)
	if _, err := flag.addShare(fpk, &fsk, 8, nil, "sealed"); err != nil {
		t.Fatal(err)
	}
	if st := flag.SetupState(); st != (backend.SetupState{SetupHash: backend.Root{0xf}}) {
		t.Fatalf("flag path: %+v", st)
	}
}

// Earlier builds wrote "generated" and "order" into the record of a share
// made in key generation inside the runner. Such a record does not load,
// and neither does one with another field it does not know or trailing
// data: a share never counts as imported because a reader dropped a field.
// A record as this build writes it loads.
func TestShareRecordRefusesUnknownFields(t *testing.T) {
	setup, logID := [32]byte{0xa}, [32]byte{1}
	order := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xd7}, 32))
	for name, c := range map[string]struct {
		extra string // JSON members after the record's own
		trail string // bytes after the object
		ok    bool
	}{
		"this build":             {ok: true},
		"this build, history":    {extra: `,"history":true`, ok: true},
		"generated with order":   {extra: `,"generated":true,"order":"` + order + `"`},
		"generated, no order":    {extra: `,"generated":true`},
		"generated false":        {extra: `,"generated":false`},
		"order on an import":     {extra: `,"order":"` + order + `"`},
		"another unknown field":  {extra: `,"origin":2`},
		"trailing object":        {trail: `{}`},
		"trailing garbage":       {trail: `x`},
		"trailing whitespace ok": {trail: " \n", ok: true},
	} {
		store := &shareStore{m: map[string][]byte{}}
		s := shareServer(t, store, setup, logID)
		s.State = constState(backend.SetupState{SetupHash: setup})
		sk, _ := software.NewSecret()
		pk, _ := core.PubkeyOf(sk)
		own, _ := json.Marshal(shareRecord{Pubkey: pk, Secret: sk[:], Index: 7})
		plain := fmt.Sprintf("%s%s}%s", own[:len(own)-1], c.extra, c.trail)
		blob, err := s.Platform.Sealer.Seal([]byte(plain), s.shareAAD(pk))
		if err != nil {
			t.Fatal(err)
		}
		store.Put(shareKey(pk), blob)
		listed, _ := ListShares(store)
		n, err := s.LoadListedShares(listed)
		switch {
		case c.ok && (n != 1 || err != nil):
			t.Errorf("%s: %d loaded, %v", name, n, err)
		case !c.ok && (n != 0 || err == nil || !strings.Contains(err.Error(), "bad record")):
			t.Errorf("%s: %d loaded, %v", name, n, err)
		}
		if _, err := parseShareRecord([]byte(plain)); (err == nil) != c.ok {
			t.Errorf("%s: parseShareRecord: %v", name, err)
		}
		if !c.ok && s.SetupState().KeyOrigin.Imported != 0 {
			t.Errorf("%s: the refused share counts", name)
		}
	}
}
