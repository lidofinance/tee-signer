package dev

import (
	"context"
	"errors"
	"testing"

	"github.com/lidofinance/tee-signer/platform"
)

// The dev platform keeps setups apart as the cloud platforms do: a runner
// with another setup over the same state directory unseals nothing the
// first sealed and opens none of its wrapped keys. The flag path (zero
// setup) keeps the fixed dev key.
func TestAnotherSetupOpensNothing(t *testing.T) {
	dir := t.TempDir()
	open := func(setup [32]byte) *platform.Platform {
		p, err := New(platform.Options{StateDir: dir, SetupHash: setup})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	a, b := open([32]byte{1}), open([32]byte{2})
	blob, err := a.Sealer.Seal([]byte("share"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Sealer.Unseal(blob, []byte("aad")); err == nil {
		t.Fatal("another setup unsealed the first setup's data")
	}
	if got, err := open([32]byte{1}).Sealer.Unseal(blob, []byte("aad")); err != nil || string(got) != "share" {
		t.Fatalf("the same setup after a restart: %q %v", got, err)
	}
	ctx := context.Background()
	_, kb, err := a.Keys.NewKey(ctx, []byte("mark key aad"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Keys.OpenKey(ctx, kb, []byte("mark key aad")); !errors.Is(err, platform.ErrNotAuthentic) {
		t.Fatalf("another setup opened a wrapped key: %v", err)
	}
	flag, _ := NewDevSealer().Seal([]byte("x"), nil)
	if _, err := open([32]byte{}).Sealer.Unseal(flag, nil); err != nil {
		t.Fatalf("the flag path lost the fixed dev key: %v", err)
	}
}
