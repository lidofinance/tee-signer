package server

import (
	"bytes"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
)

// withSealer gives s a sealer with the key byte b in every position, so two
// servers with the same b share a sealing key and with another b do not.
func withSealer(t *testing.T, s *Server, b byte) *Server {
	t.Helper()
	sealer, err := platform.NewGCMSealer(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	p := *s.Platform
	p.Sealer = sealer
	s.Platform = &p
	return s
}

// AWS-KMS-02 with a planted share: the key admin made the stored sealing
// blob before the key policy was locked, and the host put an object under
// shares/ so the platform takes the blob (platform-aws/nitro dataKey). The
// runner must not use that key: the junk share does not open under it.
func TestPlantedShareDoesNotProveTheSealingKey(t *testing.T) {
	store := &shareStore{m: map[string][]byte{}}
	setup, logID := [32]byte{0xa}, [32]byte{1}
	store.Put("shares/"+strings.Repeat("aa", 48), []byte("anything the admin wrote"))
	listed, _ := ListShares(store)

	s := withSealer(t, shareServer(t, store, setup, logID), 0x42)
	s.SealingKeyUnproven = true
	if err := s.ProveSealingKey(listed); err == nil || !strings.Contains(err.Error(), "opens 0 of 1") {
		t.Fatalf("a junk share proved the planted key: %v", err)
	}
	// A name that is no share key fails the same way.
	if err := s.ProveSealingKey([]string{"shares/aa01"}); err == nil {
		t.Fatal("shares/aa01 proved the planted key")
	}
	// Until the check passes, no share is sealed under the key.
	sk, _ := software.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	if _, err := s.addShare(pk, &sk, 7, nil, "test"); err == nil || !strings.Contains(err.Error(), "sealing key came from the store") {
		t.Fatalf("sealed a share under an unproven key: %v", err)
	}
	if l, _ := ListShares(store); len(l) != 1 {
		t.Fatalf("the refused import wrote a share: %v", l)
	}
}

// The runner's own shares prove its stored key; a share planted next to
// them under another key, or a blob swapped under them, stops the start.
// A list that is empty now (the host removed the shares after the platform
// listed them) proves nothing.
func TestOwnSharesProveTheSealingKey(t *testing.T) {
	store := &shareStore{m: map[string][]byte{}}
	setup, logID := [32]byte{0xa}, [32]byte{1}
	own := withSealer(t, shareServer(t, store, setup, logID), 0x01)
	for i := range 2 {
		sk, _ := software.NewSecret()
		pk, _ := core.PubkeyOf(sk)
		if _, err := own.addShare(pk, &sk, uint64(7+i), nil, "test"); err != nil {
			t.Fatal(err)
		}
	}
	listed, _ := ListShares(store)

	restart := withSealer(t, shareServer(t, store, setup, logID), 0x01)
	restart.SealingKeyUnproven = true
	if err := restart.ProveSealingKey(listed); err != nil || restart.SealingKeyUnproven {
		t.Fatalf("own shares: %v", err)
	}
	if n, err := restart.LoadListedShares(listed); n != 2 || err != nil {
		t.Fatalf("loaded %d: %v", n, err)
	}

	swapped := withSealer(t, shareServer(t, store, setup, logID), 0x42)
	if err := swapped.ProveSealingKey(listed); err == nil || !strings.Contains(err.Error(), "opens 0 of 2") {
		t.Fatalf("a swapped blob: %v", err)
	}

	planter := withSealer(t, shareServer(t, store, setup, logID), 0x42)
	sk, _ := software.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	if _, err := planter.addShare(pk, &sk, 9, nil, "test"); err != nil {
		t.Fatal(err)
	}
	all, _ := ListShares(store)
	if err := withSealer(t, shareServer(t, store, setup, logID), 0x01).ProveSealingKey(all); err == nil || !strings.Contains(err.Error(), "opens 2 of 3") {
		t.Fatalf("a share under another key next to the own ones: %v", err)
	}

	if err := withSealer(t, shareServer(t, store, setup, logID), 0x01).ProveSealingKey(nil); err == nil {
		t.Fatal("an empty list proved the key")
	}
}
