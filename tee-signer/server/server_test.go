package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	"github.com/lidofinance/tee-signer/tee-signer/attls"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// fakeAttester answers like the nitro platform does: a document of its
// own that carries whatever user data it was asked to bind.
type fakeAttester struct{}

func (fakeAttester) Attest(_ context.Context, nonce, userData []byte) (*backend.Attestation, error) {
	return &backend.Attestation{Platform: "nitro", Format: "aws-nitro-cose-sign1", UserData: userData, Document: []byte("doc")}, nil
}

func identityOf(t *testing.T, s *Server, nonce []byte) *backend.Identity {
	t.Helper()
	payload, err := wire.EncodeAttest(nonce)
	if err != nil {
		t.Fatal(err)
	}
	body, err := s.dispatch(context.Background(), wire.Frame{Type: wire.TypeIdentity, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	id, err := wire.DecodeIdentity(body)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// constState is a Server.State that always reports s.
func constState(s backend.SetupState) func() backend.SetupState {
	return func() backend.SetupState { return s }
}

// A runner with TLS names its TLS key in the identity, and the attested
// user data covers that name. Without it the identity has no key hash, and
// no client built by attest/runnerclient can bind the channel.
func TestIdentityCarriesTheTLSKeyHash(t *testing.T) {
	hash := sha256.Sum256([]byte("the runner's TLS key"))
	nonce := bytes.Repeat([]byte{7}, 32)
	plat := &platform.Platform{Name: "nitro", Attester: fakeAttester{}}
	st := constState(backend.SetupState{SetupHash: backend.Root{1}})

	withTLS := identityOf(t, &Server{State: st, TLSKeyHash: hash[:], Platform: plat, Log: quiet}, nonce)
	if !bytes.Equal(withTLS.TLSKeyHash, hash[:]) {
		t.Fatalf("identity names TLS key %x, want %x", withTLS.TLSKeyHash, hash)
	}
	if !bytes.Equal(withTLS.Attestation.UserData, backend.IdentityUserData(nonce, withTLS)) {
		t.Fatal("the attested user data does not cover the identity with its TLS key hash")
	}

	without := identityOf(t, &Server{State: st, Platform: plat, Log: quiet}, nonce)
	if len(without.TLSKeyHash) != 0 {
		t.Fatalf("identity without TLS names a key: %x", without.TLSKeyHash)
	}
	if bytes.Equal(without.Attestation.UserData, withTLS.Attestation.UserData) {
		t.Fatal("the user data does not change with the TLS key hash")
	}
}

// IDENTITY carries the setup state the server reports at that moment,
// and the attested user data covers it: a pending update or another
// approver set gives another hash.
func TestIdentityCarriesTheSetupState(t *testing.T) {
	nonce := bytes.Repeat([]byte{7}, 32)
	plat := &platform.Platform{Name: "nitro", Attester: fakeAttester{}}
	want := backend.SetupState{SetupHash: backend.Root{0xaa}, Locked: backend.ConfigGroup{Version: 3, Hash: backend.Root{3}},
		Open:            backend.ConfigGroup{Version: 1, Hash: backend.Root{4}, Pending: backend.PendingUpdate{Version: 2, Hash: backend.Root{5}, EffectiveAt: 1_800_000_000}},
		ApproverSetHash: backend.Root{6}}
	now := want
	s := &Server{State: func() backend.SetupState { return now }, Platform: plat, Log: quiet}
	id := identityOf(t, s, nonce)
	if id.State != want {
		t.Fatalf("identity state %+v, want %+v", id.State, want)
	}
	if !bytes.Equal(id.Attestation.UserData, backend.IdentityUserData(nonce, id)) {
		t.Fatal("the attested user data does not cover the identity")
	}
	now.Open.Pending = backend.PendingUpdate{}
	again := identityOf(t, s, nonce)
	if again.State != now || bytes.Equal(again.Attestation.UserData, id.Attestation.UserData) {
		t.Fatal("the identity does not follow the state, or its user data does not change with it")
	}
}

// A request of another version gets UNSUPPORTED, for IDENTITY and for
// ATTEST: the client gets a clear refusal, not a body it would misread.
func TestIdentityRequestVersionRefused(t *testing.T) {
	s := &Server{State: constState(backend.SetupState{SetupHash: backend.Root{1}}), Log: quiet,
		Platform: &platform.Platform{Name: "nitro", Attester: fakeAttester{}}}
	nonce := bytes.Repeat([]byte{7}, 32)
	v0 := append(append([]byte{0, 32}, nonce...), 0)
	v2 := append(append([]byte{0, 32}, nonce...), 2)
	for _, typ := range []wire.MsgType{wire.TypeIdentity, wire.TypeAttest} {
		for name, p := range map[string][]byte{"version 0": v0, "version 2": v2} {
			_, err := s.dispatch(context.Background(), wire.Frame{Type: typ, Payload: p})
			var r *backend.RefusedError
			if !errors.As(err, &r) || r.Code != backend.StatusUnsupported || !strings.Contains(r.Detail, "version") {
				t.Fatalf("%v, %s: %v, want UNSUPPORTED naming the version", typ, name, err)
			}
		}
	}
}

// ATTEST v2 answers with the setup state, and its document binds
// AttestUserData over the nonce, that state and the loaded keys.
func TestAttestCarriesTheSetupState(t *testing.T) {
	want := backend.SetupState{SetupHash: backend.Root{0xbb}, Locked: backend.ConfigGroup{Hash: backend.Root{1}},
		Open: backend.ConfigGroup{Hash: backend.Root{2}}, ApproverSetHash: backend.Root{3}}
	s := shareServer(t, &shareStore{m: map[string][]byte{}}, [32]byte{}, [32]byte{})
	s.State, s.Platform.Attester = constState(want), fakeAttester{}
	nonce := []byte("attest nonce")
	p, _ := wire.EncodeAttest(nonce)
	body, err := s.dispatch(context.Background(), wire.Frame{Type: wire.TypeAttest, Payload: p})
	if err != nil {
		t.Fatal(err)
	}
	st, a, err := wire.DecodeAttestResponse(body)
	if err != nil || *st != want {
		t.Fatalf("state %+v %v, want %+v", st, err, want)
	}
	if !bytes.Equal(a.UserData, backend.AttestUserData(nonce, &want, backend.KeysHash(nil))) {
		t.Fatal("the ATTEST user data does not cover the nonce, the state and the keys")
	}
}

// A TLS connection that never finishes its handshake (a parent instance
// that connects to the vsock port and says nothing) does not hold a
// goroutine for good.
func TestHandshakeTimeout(t *testing.T) {
	old := handshakeTimeout
	handshakeTimeout = 200 * time.Millisecond
	t.Cleanup(func() { handshakeTimeout = old })

	cfg, _, err := attls.ServerConfig(selfSignedCA(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	peer, srvSide := net.Pipe()
	defer peer.Close()
	s := &Server{Log: quiet, Platform: &platform.Platform{Name: "nitro"}}
	done := make(chan struct{})
	go func() {
		s.handleConn(context.Background(), tls.Server(srvSide, cfg))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleConn still waits for a handshake that never comes")
	}
}

// selfSignedCA returns the PEM of a CA certificate, for ServerConfig.
func selfSignedCA(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
