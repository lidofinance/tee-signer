package server

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	"github.com/lidofinance/tee-signer/trusted-time/clock"
)

// putGenerated stores a share as AddGeneratedShares does (the peer builds
// only): sealed, marked generated under order.
func putGenerated(t *testing.T, s *Server, order []byte) backend.Pubkey {
	t.Helper()
	sk, _ := software.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	blob, err := s.sealShare(pk, &sk, backend.IndexUnknown, true, order)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Platform.Store.Put(shareKey(pk), blob); err != nil {
		t.Fatal(err)
	}
	return pk
}

// The key origin counts the loaded keys by the origin in their sealed
// share records, after a restart too, and ATTEST binds it with keys_hash
// over the same keys. A runner without a setup reports none.
func TestKeyOrigin(t *testing.T) {
	store := &shareStore{m: map[string][]byte{}}
	setup, logID := [32]byte{0xa}, [32]byte{1}
	orderA, orderB := bytes.Repeat([]byte{0xa1}, 32), bytes.Repeat([]byte{0xb2}, 32)
	s := shareServer(t, store, setup, logID)
	s.State = constState(backend.SetupState{SetupHash: setup})
	if ko := s.SetupState().KeyOrigin; ko != (backend.KeyOrigin{}) {
		t.Fatalf("no key: %+v", ko)
	}
	sk, _ := software.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	if _, err := s.addShare(pk, &sk, 7, nil, "sealed"); err != nil {
		t.Fatal(err)
	}
	if ko := s.SetupState().KeyOrigin; ko != (backend.KeyOrigin{Imported: 1}) {
		t.Fatalf("one import: %+v", ko)
	}
	putGenerated(t, s, orderA)
	putGenerated(t, s, orderB)
	putGenerated(t, s, orderA)

	// A restart: the records say which keys were generated.
	listed, _ := ListShares(store)
	r := shareServer(t, store, setup, logID)
	r.State = constState(backend.SetupState{SetupHash: setup})
	r.Platform.Attester, r.Platform.Clock = fakeAttester{}, clock.System{}
	r.KeyReleaseHash, r.KeyLock = [32]byte{0x77}, backend.KeyLockLocked
	if n, err := r.LoadListedShares(listed); n != 4 || err != nil {
		t.Fatalf("loaded %d: %v", n, err)
	}
	want := backend.KeyOrigin{Generated: 3, Imported: 1, OrdersHash: backend.KeygenOrdersHash([][32]byte{[32]byte(orderA), [32]byte(orderB)})}
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

// A share record whose origin does not hold together does not load: an
// order on an imported share, or an order hash of another size.
func TestKeyOriginBadRecord(t *testing.T) {
	setup, logID := [32]byte{0xa}, [32]byte{1}
	for name, rec := range map[string]shareRecord{
		"order on an import": {Order: bytes.Repeat([]byte{1}, 32)},
		"short order":        {Generated: true, Order: []byte{1}},
	} {
		store := &shareStore{m: map[string][]byte{}}
		s := shareServer(t, store, setup, logID)
		sk, _ := software.NewSecret()
		pk, _ := core.PubkeyOf(sk)
		rec.Pubkey, rec.Secret, rec.Index = pk, sk[:], 7
		plain, _ := json.Marshal(rec)
		blob, err := s.Platform.Sealer.Seal(plain, s.shareAAD(pk))
		if err != nil {
			t.Fatal(err)
		}
		store.Put(shareKey(pk), blob)
		listed, _ := ListShares(store)
		if n, err := s.LoadListedShares(listed); n != 0 || err == nil || !strings.Contains(err.Error(), "bad record") {
			t.Errorf("%s: %d loaded, %v", name, n, err)
		}
	}
}
