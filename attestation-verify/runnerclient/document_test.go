//go:build !verifierselect

package runnerclient

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/internal/testgen"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// The document verifiers check a document against the user data the
// caller gives, with the same settings and checks as the identity
// verifiers: the right user data passes, any other is refused before or by
// the document's own check, and a document of another platform is refused.
func TestDocumentVerifiers(t *testing.T) {
	ud := sha256.Sum256([]byte("user data of another form"))
	other := sha256.Sum256([]byte("other user data"))
	nonce := []byte("document verifier nonce 0123456")

	nitro := newNitroEnv(t)
	nitroDoc := func(n, u []byte) *backend.Attestation {
		doc := nitro.ca.NitroDoc(t, testgen.NitroSpec{TS: time.Now(), Nonce: n, UserData: u})
		return &backend.Attestation{Platform: nitroPlatform, Format: nitroFormat, UserData: u, Document: doc}
	}
	maa := newMAAEnv(t, mainKeySet(t))
	maaDoc := func(_, u []byte) *backend.Attestation {
		return &backend.Attestation{Platform: "azure", Format: "azure-maa-jwt", UserData: u,
			Document: []byte(maa.token(tokenSpec{}, backend.MAARuntimeData(u)))}
	}
	gcpDoc := func(_, u []byte) *backend.Attestation {
		return &backend.Attestation{Platform: gcpPlatform, Format: gcpFormat, UserData: u, Document: []byte(maa.gcpToken(gcpSpec{}, u))}
	}
	devDoc := func(n, u []byte) *backend.Attestation {
		doc, _ := json.Marshal(map[string]any{"nonce": n, "user_data": u})
		return &backend.Attestation{Platform: "dev", Format: "dev-json", UserData: u, Document: doc}
	}
	cases := []struct {
		name string
		a    Attestation
		opts []Option
		doc  func(nonce, userData []byte) *backend.Attestation
	}{
		{"aws-nitro", nitroGood(), []Option{withNitroRoots(nitro.ca.Root)}, nitroDoc},
		{"azure-maa", Attestation{Verifier: VerifierAzureMAA, MAAHost: maa.host, CCEPolicySHA256: goodHostData},
			[]Option{WithHTTPClient(maa.srv.Client())}, maaDoc},
		{"gcp-cs", gcpGood(maa.issuer), []Option{WithHTTPClient(maa.srv.Client())}, gcpDoc},
		{"dev", Attestation{Verifier: VerifierDev}, nil, devDoc},
	}
	for _, c := range cases {
		v, err := c.a.NewDocumentVerifier(c.opts...)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if err := v(ctx, nonce, ud[:], c.doc(nonce, ud[:])); err != nil {
			t.Fatalf("%s: good document: %v", c.name, err)
		}
		// The caller expects other user data than the document binds.
		if err := v(ctx, nonce, other[:], c.doc(nonce, ud[:])); err == nil {
			t.Fatalf("%s: a document for other user data passed", c.name)
		}
		// The attestation claims the expected user data, the document
		// binds another.
		lie := c.doc(nonce, other[:])
		lie.UserData = ud[:]
		if err := v(ctx, nonce, ud[:], lie); err == nil {
			t.Fatalf("%s: a document that binds other user data passed", c.name)
		}
		if err := v(ctx, nonce, nil, c.doc(nonce, nil)); err == nil {
			t.Fatalf("%s: empty user data passed", c.name)
		}
		for _, o := range cases {
			if o.name != c.name {
				if err := v(ctx, nonce, ud[:], o.doc(nonce, ud[:])); err == nil {
					t.Fatalf("%s: a %s document passed", c.name, o.name)
				}
			}
		}
	}
	// Nitro and dev bind the nonce too.
	for _, c := range cases {
		if c.name != "aws-nitro" && c.name != "dev" {
			continue
		}
		v, _ := c.a.NewDocumentVerifier(c.opts...)
		if err := v(ctx, nonce, ud[:], c.doc(bytes.Repeat([]byte{1}, 32), ud[:])); err == nil {
			t.Fatalf("%s: a document for another nonce passed", c.name)
		}
	}
	// The settings are validated as for an identity verifier.
	bad := nitroGood()
	bad.NitroPCRs["0"] = "00"
	if _, err := bad.NewDocumentVerifier(); err == nil {
		t.Fatal("bad settings gave a document verifier")
	}
}
