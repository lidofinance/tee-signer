package software

import (
	"context"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

func TestSoftwareBackend(t *testing.T) {
	ctx := context.Background()
	now := uint64(time.Now().Unix())
	cfg := core.DevConfig(now-100*384, 12, 32) // clock epoch 100
	b, err := New(cfg, 4, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	sk, _ := core.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	if _, err := b.ImportShare(ctx, backend.ImportShareRequest{Pubkey: pk, Secret: sk, Index: 7}); err != nil {
		t.Fatal(err)
	}
	keys, _ := b.PublicKeys(ctx)
	if len(keys) != 1 || keys[0].Pubkey != pk {
		t.Fatalf("%+v", keys)
	}
	a := &backend.AttestationData{Slot: 100 * 32, Source: backend.Checkpoint{Epoch: 99}, Target: backend.Checkpoint{Epoch: 100}}
	domain, _ := cfg.MessageDomain(a)
	if _, err := b.Sign(ctx, backend.SignRequest{Pubkey: pk, Message: a}); backend.StatusOf(err) != backend.StatusDomainMismatch {
		t.Fatalf("no domain: %v", err)
	}
	sig, err := b.Sign(ctx, backend.SignRequest{Pubkey: pk, Message: a, Domain: domain})
	if err != nil {
		t.Fatal(err)
	}
	root, _ := cfg.SigningRoot(a)
	if !core.Verify(pk, root, sig) {
		t.Fatal("bad signature")
	}
	// A validator client retry: same message, same signature.
	again, err := b.Sign(ctx, backend.SignRequest{Pubkey: pk, Message: a, Domain: domain})
	if err != nil || again != sig {
		t.Fatalf("exact repeat: %v", err)
	}
	double := *a
	double.BeaconBlockRoot = backend.Root{1}
	_, err = b.Sign(ctx, backend.SignRequest{Pubkey: pk, Message: &double, Domain: domain})
	if backend.StatusOf(err) != backend.StatusSlashTarget {
		t.Fatalf("double vote: %v", err)
	}
	h, _ := b.Health(ctx)
	if !h.Ready || h.Validators != 1 {
		t.Fatalf("%+v", h)
	}
}
