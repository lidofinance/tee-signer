//go:build !peerselect

package azureid

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify"
	"github.com/lidofinance/tee-signer/attestation-verify/internal/testgen"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

const hostData = "73e0d1b6b2d0b0b3c0c8a0d7a8f2b1f3e4d5c6b7a8f9e0d1c2b3a4958677a6b5"

// identityWithToken builds an Azure runner's IDENTITY the way runner/platform
// does, with a synthetic MAA token under key kid "maa".
func identityWithToken(t *testing.T, nonce []byte) (*backend.Identity, attest.MAAOptions) {
	t.Helper()
	key := testgen.RSAKey(0)
	ks, err := attest.ParseJWKS(testgen.JWKS(t, "maa", key, true))
	if err != nil {
		t.Fatal(err)
	}
	id := &backend.Identity{
		State: backend.SetupState{SetupHash: backend.Root{9}}, ImportKEM: 0x647a, ImportKDF: 1, ImportAEAD: 2,
		ImportKey: []byte("hpke key"), TLSKeyHash: make([]byte, 32),
	}
	ud := backend.IdentityUserData(nonce, id)
	sum := sha256.Sum256(backend.MAARuntimeData(ud))
	now := time.Now()
	tok := testgen.SignJWT(t, key, "maa", map[string]any{
		"iss": "https://p.weu.attest.azure.net", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"x-ms-attestation-type": "sevsnpvm", "x-ms-compliance-status": attest.ComplianceACI,
		"x-ms-sevsnpvm-hostdata": hostData, "x-ms-sevsnpvm-is-debuggable": false, "x-ms-sevsnpvm-vmpl": 0,
		"x-ms-sevsnpvm-reportdata": hex.EncodeToString(sum[:]) + strings.Repeat("00", 32),
	}, nil)
	id.Attestation = &backend.Attestation{Platform: Platform, Format: Format, UserData: ud, Document: []byte(tok)}
	return id, attest.MAAOptions{
		Issuer: "https://p.weu.attest.azure.net", Keys: ks,
		ComplianceStatus: attest.ComplianceACI, HostData: []string{hostData},
	}
}

func TestVerify(t *testing.T) {
	nonce := []byte("client nonce")
	id, opts := identityWithToken(t, nonce)
	tok, err := Verify(nonce, id, opts)
	if err != nil {
		t.Fatal(err)
	}
	if tok.HostData != hostData {
		t.Fatalf("host data %q", tok.HostData)
	}

	t.Run("other nonce", func(t *testing.T) {
		if _, err := Verify([]byte("other"), id, opts); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("changed identity field", func(t *testing.T) {
		c := *id
		c.ImportKey = []byte("attacker key")
		if _, err := Verify(nonce, &c, opts); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("token over the raw user data", func(t *testing.T) {
		// The binding before the JSON runtime data fix: report data is the
		// hash of the raw user data.
		raw := sha256.Sum256(id.Attestation.UserData)
		now := time.Now()
		bad := testgen.SignJWT(t, testgen.RSAKey(0), "maa", map[string]any{
			"iss": opts.Issuer, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
			"x-ms-attestation-type": "sevsnpvm", "x-ms-compliance-status": attest.ComplianceACI,
			"x-ms-sevsnpvm-hostdata": hostData, "x-ms-sevsnpvm-is-debuggable": false, "x-ms-sevsnpvm-vmpl": 0,
			"x-ms-sevsnpvm-reportdata": hex.EncodeToString(raw[:]) + strings.Repeat("00", 32),
		}, nil)
		c := *id
		c.Attestation = &backend.Attestation{Platform: Platform, Format: Format, UserData: id.Attestation.UserData, Document: []byte(bad)}
		if _, err := Verify(nonce, &c, opts); !errors.Is(err, attest.ErrNonce) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("not an Azure document", func(t *testing.T) {
		c := *id
		c.Attestation = &backend.Attestation{Platform: "dev", Format: "dev-json", UserData: id.Attestation.UserData}
		if _, err := Verify(nonce, &c, opts); err == nil || !strings.Contains(err.Error(), "not an Azure MAA token") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("no attestation", func(t *testing.T) {
		if _, err := Verify(nonce, nil, opts); err == nil {
			t.Fatal("accepted nil")
		}
		if _, err := Verify(nonce, &backend.Identity{}, opts); err == nil {
			t.Fatal("accepted no attestation")
		}
	})
}
