package charonnode

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/tee-signer/charonlock"
)

// TestCharonMadeNodeSignatures checks this package against locks Charon
// v1.11.0 made (CHARON_LOCKS, from scripts/charon-lock-test.sh): its node
// signatures verify with the ENR keys this package reads, and node0's key
// signs the lock hash the same way.
func TestCharonMadeNodeSignatures(t *testing.T) {
	env := os.Getenv("CHARON_LOCKS")
	if env == "" {
		t.Skip("CHARON_LOCKS not set (scripts/charon-lock-test.sh sets it)")
	}
	for _, p := range strings.Split(env, ",") {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		l, err := charonlock.Parse(b)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyNodeSignatures(l); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		k, err := LoadKey(filepath.Join(filepath.Dir(p), "charon-enr-private-key"))
		if err != nil {
			t.Fatal(err)
		}
		charonSig := append([]byte(nil), l.NodeSignatures[0]...)
		l.NodeSignatures[0] = nil
		idx, err := AddSignature(l, k)
		if err != nil || idx != 0 {
			t.Fatalf("%s: AddSignature: %d %v", p, idx, err)
		}
		if err := VerifyNodeSignatures(l); err != nil {
			t.Fatalf("%s: own signature: %v", p, err)
		}
		t.Logf("%s: %d node signatures by Charon verify; node0's own signature verifies (byte-equal to Charon's: %v)",
			p, len(l.NodeSignatures), bytes.Equal(charonSig, l.NodeSignatures[0]))
	}
}

func TestSignRecover(t *testing.T) {
	k, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	h := backend.Root{1, 2, 3}
	sig := Sign(k, h)
	if len(sig) != 65 || sig[64] > 1 {
		t.Fatalf("signature form: %x", sig)
	}
	got, err := Recover(sig, h)
	if err != nil || !bytes.Equal(got, k.PubKey().SerializeCompressed()) {
		t.Fatal("recovered another key")
	}
	h[0] ^= 1
	if got, _ := Recover(sig, h); bytes.Equal(got, k.PubKey().SerializeCompressed()) {
		t.Fatal("signature recovers the key for another hash")
	}
	if _, err := ENRKey("enr:!!"); err == nil {
		t.Fatal("bad ENR accepted")
	}
}
