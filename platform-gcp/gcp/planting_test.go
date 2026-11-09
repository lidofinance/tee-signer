package gcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/filestore"
)

// fakeKMS is the runner's KMS client against the Google fakes.
func fakeKMS(t *testing.T) *KMS {
	t.Helper()
	g := fakeGoogle(t)
	t.Cleanup(g.Close)
	return &KMS{L: NewLauncher(fakeLauncher(t, 1)), HTTP: g.Client(),
		Provider: "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/q",
		Key:      "projects/p/locations/l/keyRings/r/cryptoKeys/k", STSURL: g.URL, IAMURL: g.URL, KMSURL: g.URL}
}

// plant is a holder of cryptoKeyEncrypterDecrypter on the key: it wraps a
// data key it knows under the public sealing AAD and puts the blob in the
// store.
func plant(t *testing.T, k *KMS, store platform.Store, setup [32]byte) (known, blob []byte) {
	t.Helper()
	known = bytes.Repeat([]byte{0x42}, 32)
	blob, err := k.call(context.Background(), "encrypt", "plaintext", known, sealingAAD(setup))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(dekBlob, blob); err != nil {
		t.Fatal(err)
	}
	return known, blob
}

// A blob planted before the first start, on a store without shares: the
// runner does not use it and makes its own key. The blob is kept under
// another name, and the runner's own key stays across restarts once a
// share is sealed.
func TestPlantedDataKeyWithoutSharesIsSetAside(t *testing.T) {
	k := fakeKMS(t)
	ctx := context.Background()
	setup := [32]byte{7}
	store, _ := filestore.New(t.TempDir())
	known, planted := plant(t, k, store, setup)
	store.Put("wm/aa01", []byte("not a share"))

	dek, stored, err := k.dataKey(ctx, store, setup)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(dek, known) {
		t.Fatal("the runner took the planted data key")
	}
	if stored {
		t.Fatal("a key made at this start was reported as stored")
	}
	if b, err := store.Get(dekBlob); err != nil || bytes.Equal(b, planted) {
		t.Fatalf("the planted blob is still the sealing blob: %v", err)
	}
	sum := sha256.Sum256(planted)
	if kept, err := store.Get(fmt.Sprintf("%s.ignored-%x", dekBlob, sum[:8])); err != nil || !bytes.Equal(kept, planted) {
		t.Fatalf("the ignored blob was not kept: %v", err)
	}

	store.Put(sharePrefix+"aa01", []byte("sealed share"))
	again, stored, err := k.dataKey(ctx, store, setup)
	if err != nil || !bytes.Equal(again, dek) || !stored {
		t.Fatalf("restart with a share stored: stored %v, %v", stored, err)
	}
}

// A planted blob next to an object under shares/: the platform cannot tell
// the blob from its own, so it takes it but reports it as stored. The
// runner then needs every stored share to open under the key
// (platform.Platform.SealingKeyStored, tee-signer server.ProveSealingKey),
// and the planted share does not.
func TestPlantedDataKeyWithSharesIsReportedStored(t *testing.T) {
	k := fakeKMS(t)
	ctx := context.Background()
	setup := [32]byte{7}
	store, _ := filestore.New(t.TempDir())
	known, _ := plant(t, k, store, setup)
	store.Put(sharePrefix+"aa01", []byte("anything the planter wrote"))

	dek, stored, err := k.dataKey(ctx, store, setup)
	if err != nil || !bytes.Equal(dek, known) {
		t.Fatalf("planted blob with a share: %v", err)
	}
	if !stored {
		t.Fatal("a key from the stored blob was not reported as stored")
	}
	sealer, _ := platform.NewGCMSealer(dek)
	share, _ := store.Get(sharePrefix + "aa01")
	if _, err := sealer.Unseal(share, nil); err == nil {
		t.Fatal("the planted share opened")
	}
}

// A runner already in service (a stored blob it made and shares sealed
// under it) keeps its key after the upgrade: the key is reported as
// stored, and its shares open under it, so the runner's check passes.
func TestOwnDataKeyWithOwnSharesAfterUpgrade(t *testing.T) {
	k := fakeKMS(t)
	ctx := context.Background()
	setup := [32]byte{7}
	store, _ := filestore.New(t.TempDir())
	// What the earlier code stored: a blob of a key made in the VM.
	own := bytes.Repeat([]byte{0x01}, 32)
	blob, err := k.call(ctx, "encrypt", "plaintext", own, sealingAAD(setup))
	if err != nil {
		t.Fatal(err)
	}
	store.Put(dekBlob, blob)
	sealer, _ := platform.NewGCMSealer(own)
	aad := []byte("share aad")
	sealed, _ := sealer.Seal([]byte("share secret"), aad)
	store.Put(sharePrefix+"aa01", sealed)

	dek, stored, err := k.dataKey(ctx, store, setup)
	if err != nil || !bytes.Equal(dek, own) || !stored {
		t.Fatalf("restart after the upgrade: stored %v, %v", stored, err)
	}
	if b, _ := store.Get(dekBlob); !bytes.Equal(b, blob) {
		t.Fatal("the stored blob changed")
	}
	again, _ := platform.NewGCMSealer(dek)
	if p, err := again.Unseal(sealed, aad); err != nil || string(p) != "share secret" {
		t.Fatalf("the own share does not open: %v", err)
	}
}
