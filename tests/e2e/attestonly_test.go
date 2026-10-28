package e2e

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
)

// testPKIAttest makes a client PKI (rolePKI) and returns the CA file, the
// signing leaf (with its admin twin for imports) and the attest-only leaf
// (clientAuth and backend.AttestOnlyClientOID).
func testPKIAttest(t *testing.T, dir, name string) (string, *tls.Config, *tls.Config) {
	t.Helper()
	r := rolePKI(t, dir, name, 24*time.Hour, 24*time.Hour)
	return r.caFile, r.signing, r.attestOnly
}

// TestE2EAttestOnlyCertificate: a release runner with mutual TLS serves an
// attest-only client certificate (the prover's) its identity, health, keys
// and attestations, at most backend.AttestOnlyPerMinute fresh ones a
// minute, and refuses it a signature and an import with FORBIDDEN. The
// same requests work with the admin certificate (attestations without a
// limit, the import) and the signing certificate (the signature).
func TestE2EAttestOnlyCertificate(t *testing.T) {
	c := newChain(t)
	caFile, fullCfg, attestCfg := testPKIAttest(t, t.TempDir(), "roles")
	addr := fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t))
	r := newRunnerArgs(t, "runner-roles", c, addr, "-tls-client-ca", caFile)
	r.start()

	full, err := newTLSClient(addr, fullCfg, remote.DevVerifier, remote.WithTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer full.Close()
	waitReady(t, full)
	sk, _ := core.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	if _, err := adminOf(full).ImportShareSealed(ctx, backend.ImportShareRequest{Pubkey: pk, Secret: sk, Index: 9}, pk, remote.DevVerifier); err != nil {
		t.Fatal(err)
	}

	// The attest-only client: the connection itself needs IDENTITY, which
	// it may ask for.
	prover, err := newTLSClient(addr, attestCfg, remote.DevVerifier, remote.WithTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer prover.Close()
	if _, err := prover.Health(ctx); err != nil {
		t.Fatalf("attest-only HEALTH: %v", err)
	}
	keys, err := prover.PublicKeys(ctx)
	if err != nil || len(keys) != 1 || keys[0].Pubkey != pk {
		t.Fatalf("attest-only PUBLIC_KEYS: %v %v", keys, err)
	}
	nonce := make([]byte, 32)
	rand.Read(nonce)
	st, a, err := prover.AttestState(ctx, nonce)
	if err != nil {
		t.Fatalf("attest-only ATTEST: %v", err)
	}
	if string(a.UserData) != string(backend.AttestUserData(nonce, st, backend.KeysHash(keys))) {
		t.Fatal("the ATTEST user data does not bind the state and the keys PUBLIC_KEYS gave")
	}
	t.Log("attest-only certificate: IDENTITY (on connect), HEALTH, PUBLIC_KEYS and ATTEST answered")

	// The limit: the connection's IDENTITY and that ATTEST were fresh
	// attestations 1 and 2 of this minute. New nonces answer up to the
	// limit, the next one is RATE_LIMITED, for IDENTITY too, and a repeat
	// of a nonce gets its answer again without counting.
	var last []byte
	var lastAtt *backend.Attestation
	for i := 3; i <= backend.AttestOnlyPerMinute; i++ {
		n := make([]byte, 32)
		rand.Read(n)
		_, la, err := prover.AttestState(ctx, n)
		if err != nil {
			t.Fatalf("fresh attestation %d of the minute: %v", i, err)
		}
		last, lastAtt = n, la
	}
	over := make([]byte, 32)
	rand.Read(over)
	_, _, err = prover.AttestState(ctx, over)
	if r := wantRefused(t, err, backend.StatusRateLimited); !strings.Contains(r.Detail, "in the last minute") {
		t.Fatalf("fresh attestation %d: %v", backend.AttestOnlyPerMinute+1, r)
	}
	t.Logf("attestation %d of the minute refused: %v", backend.AttestOnlyPerMinute+1, err)
	_, again, err := prover.AttestState(ctx, last)
	if err != nil || !bytes.Equal(again.Document, lastAtt.Document) || !bytes.Equal(again.UserData, lastAtt.UserData) {
		t.Fatalf("a repeat of the last nonce: %v, or another answer", err)
	}
	_, err = prover.Identity(ctx, over)
	wantRefused(t, err, backend.StatusRateLimited)
	// A signing certificate may not ask for ATTEST; the admin certificate
	// may, without a limit.
	n0 := make([]byte, 32)
	rand.Read(n0)
	_, _, err = full.AttestState(ctx, n0)
	wantRefused(t, err, backend.StatusForbidden)
	for i := 0; i < backend.AttestOnlyPerMinute+2; i++ {
		n := make([]byte, 32)
		rand.Read(n)
		if _, _, err := adminOf(full).AttestState(ctx, n); err != nil {
			t.Fatalf("admin certificate, attestation %d: %v", i+1, err)
		}
	}
	t.Logf("attest-only certificate: %d fresh attestations a minute, a repeat answered again; a signing certificate gets no ATTEST, the admin certificate has no limit",
		backend.AttestOnlyPerMinute)

	_, err = prover.Sign(ctx, c.req(pk, att(1, 2, 0x71)))
	if r := wantRefused(t, err, backend.StatusForbidden); !strings.Contains(r.Detail, "attest-only") {
		t.Fatalf("attest-only SIGN: %v", r)
	}
	_, err = adminOf(prover).ImportSealed(ctx, &backend.SealedImportRequest{Pubkey: pk, SharePubkey: pk, Index: 10, Sealed: make([]byte, 64)})
	wantRefused(t, err, backend.StatusForbidden)
	t.Log("attest-only certificate: SIGN and IMPORT_SHARE_SEALED refused with FORBIDDEN")

	e := c.stableEpoch(t)
	c.waitEpoch(t, e+3)
	req := c.req(pk, att(e+2, e+3, 0x71))

	sig, err := full.Sign(ctx, req)
	if err != nil {
		t.Fatalf("full certificate SIGN: %v", err)
	}
	root, _ := c.cfg.SigningRoot(att(e+2, e+3, 0x71))
	if !core.Verify(pk, root, sig) {
		t.Fatal("signature of the full client does not verify")
	}
	t.Log("full certificate: the same SIGN is signed")
}
