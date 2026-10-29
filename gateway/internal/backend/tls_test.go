package backend

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
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/herumi/bls-eth-go-binary/bls"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	proto "github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/buildflavor"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

// These tests run the gateway's connections (runnerclient over a node)
// against a fake signer: a TLS 1.3 server with a self-signed key that
// demands a client certificate from the test CA and answers IDENTITY,
// PUBLIC_KEYS and SIGN with the wire protocol. Its attestation document
// is the dev platform's unsigned one.

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "gateway test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	return &testCA{cert: cert, key: key, pool: pool}
}

// clientFiles writes a client certificate of the CA and its key.
func (ca *testCA) clientFiles(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "gateway"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	dir := t.TempDir()
	certPath, keyPath = filepath.Join(dir, "client.pem"), filepath.Join(dir, "client-key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}

	return certPath, keyPath
}

// tlsRunner is the fake signer. It holds one share and signs the root
// the test sets.
type tlsRunner struct {
	ln    net.Listener
	spki  []byte
	key   proto.ValidatorKey
	share *bls.SecretKey
	root  phase0.Root
	// badDoc makes its attestation document carry another nonce.
	badDoc bool
	// allowed, if set, is the one client certificate (DER) a new
	// connection may present.
	allowed atomic.Pointer[[]byte]
	// hsDelay delays each new connection, as a slow attestation does.
	hsDelay atomic.Int64

	mu     sync.Mutex
	frames map[wire.MsgType]int
	conns  []net.Conn
}

// chainMark is the runner certificate's chain mark (RunnerChainOID) for
// genesis fork version gfv.
func chainMark(t *testing.T, gfv proto.Version) []pkix.Extension {
	t.Helper()
	v, err := asn1.Marshal(gfv[:])
	if err != nil {
		t.Fatal(err)
	}

	return []pkix.Extension{{Id: proto.RunnerChainOID, Value: v}}
}

// startTLSRunner starts a fake signer with share i of k, which signs
// testRoot. badDoc makes its attestation document carry another nonce.
func startTLSRunner(t *testing.T, ca *testCA, k *testKey, i int, badDoc bool, exts []pkix.Extension) *tlsRunner {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(99), Subject: pkix.Name{CommonName: buildflavor.DefaultCertName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ExtraExtensions: exts}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	h := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	r := &tlsRunner{spki: h[:], share: &k.shares[i], root: testRoot, badDoc: badDoc, frames: map[wire.MsgType]int{},
		key: proto.ValidatorKey{Pubkey: proto.Pubkey(k.pk), SharePubkey: proto.Pubkey(pubOf(&k.shares[i])), Index: proto.IndexUnknown}}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}},
		ClientAuth:   tls.RequireAndVerifyClientCert, ClientCAs: ca.pool,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if a := r.allowed.Load(); a != nil && !bytes.Equal(raw[0], *a) {
				return errors.New("client certificate not accepted")
			}

			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	r.ln = ln
	t.Cleanup(func() { ln.Close(); r.dropConns() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			r.mu.Lock()
			r.conns = append(r.conns, c)
			r.mu.Unlock()
			go func() {
				time.Sleep(time.Duration(r.hsDelay.Load()))
				r.serve(c)
			}()
		}
	}()

	return r
}

// allow makes the runner take only the client certificate der on new
// connections. Connections already open stay.
func (r *tlsRunner) allow(der []byte) { r.allowed.Store(&der) }

func (r *tlsRunner) setHandshakeDelay(d time.Duration) { r.hsDelay.Store(int64(d)) }

func (r *tlsRunner) addr() string { return "tcp:" + r.ln.Addr().String() }

func (r *tlsRunner) seen(t wire.MsgType) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.frames[t]
}

// dropConns closes every connection, as a restart does.
func (r *tlsRunner) dropConns() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.conns {
		c.Close()
	}
	r.conns = nil
}

func (r *tlsRunner) serve(c net.Conn) {
	defer c.Close()
	for {
		fr, err := wire.ReadFrame(c)
		if err != nil {
			return
		}
		r.mu.Lock()
		r.frames[fr.Type]++
		r.mu.Unlock()
		var body []byte
		switch fr.Type {
		case wire.TypeIdentity:
			nonce, err := wire.DecodeAttest(fr.Payload)
			if err != nil {
				return
			}
			id := &proto.Identity{State: proto.SetupState{SetupHash: proto.Root{1}}, ImportKEM: 0x10, ImportKDF: 1, ImportAEAD: 1,
				ImportKey: []byte("hpke"), TLSKeyHash: r.spki}
			ud := proto.IdentityUserData(nonce, id)
			docNonce := nonce
			if r.badDoc {
				docNonce = make([]byte, len(nonce))
			}
			doc, _ := json.Marshal(map[string]any{"nonce": docNonce, "user_data": ud})
			id.Attestation = &proto.Attestation{Platform: "dev", Format: "dev-json", UserData: ud, Document: doc}
			if body, err = wire.EncodeIdentity(id); err != nil {
				return
			}
		case wire.TypePublicKeys:
			body = wire.EncodeKeys([]proto.ValidatorKey{r.key})
		case wire.TypeSign:
			if _, err := wire.DecodeSign(fr.Payload); err != nil {
				return
			}
			sig := signRoot(r.share, r.root)
			body = sig[:]
		default:
			return
		}
		if err := wire.WriteFrame(c, wire.Frame{Type: fr.Type | wire.ResponseFlag, ID: fr.ID, Payload: wire.EncodeOK(body)}); err != nil {
			return
		}
	}
}

func devConnection(t *testing.T, ca *testCA, r *tlsRunner) runnerclient.Connection {
	t.Helper()
	cert, key := ca.clientFiles(t)

	return runnerclient.Connection{Address: r.addr(), ClientCert: cert, ClientKey: key,
		Attestation: runnerclient.Attestation{Verifier: runnerclient.VerifierDev}}
}

func testNode(t *testing.T, conn runnerclient.Connection) *node {
	t.Helper()
	n, err := newNode(conn, poolConfig{size: 1}, runnerclient.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })

	return n
}

func ctxShort(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)

	return ctx
}

// Every new connection is attested before a request goes on it: the
// signer's restart (its connections dropped) costs a new IDENTITY and its
// check.
func TestNodeAttestsEveryNewConnection(t *testing.T) {
	ca := newTestCA(t)
	k := splitKey(t, 2, 3)
	r := startTLSRunner(t, ca, k, 0, false, nil)
	n := testNode(t, devConnection(t, ca, r))
	keys, err := n.PublicKeys(ctxShort(t))
	if err != nil || len(keys) != 1 || keys[0].Pubkey != proto.Pubkey(k.pk) {
		t.Fatalf("public keys %v %v", keys, err)
	}
	if got := r.seen(wire.TypeIdentity); got != 1 {
		t.Fatalf("%d IDENTITY requests for the first connection", got)
	}
	req := proto.SignRequest{Pubkey: proto.Pubkey(k.pk), Message: &proto.AttestationData{Slot: 1}}
	if _, err := n.Sign(ctxShort(t), req); err != nil {
		t.Fatal(err)
	}
	if got := r.seen(wire.TypeIdentity); got != 1 {
		t.Fatalf("%d IDENTITY requests on one connection", got)
	}
	r.dropConns()
	sig, err := n.Sign(ctxShort(t), req)
	if err != nil {
		t.Fatalf("sign after the signer dropped the connection: %v", err)
	}
	if err := VerifyBLS(pubOf(&k.shares[0]), testRoot, phase0.BLSSignature(sig)); err != nil {
		t.Fatal(err)
	}
	if got := r.seen(wire.TypeIdentity); got != 2 {
		t.Fatalf("%d IDENTITY requests after a new connection, want 2", got)
	}
}

// refusedBeforeRequests checks that err names why and that no request
// but IDENTITY reached the signer.
func refusedBeforeRequests(t *testing.T, r *tlsRunner, err error, why string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), why) {
		t.Fatalf("want an error with %q, got %v", why, err)
	}
	if n := r.seen(wire.TypePublicKeys) + r.seen(wire.TypeSign); n != 0 {
		t.Fatalf("%d requests reached a refused signer", n)
	}
}

func TestNodeRefusesWrongTLSKeyPin(t *testing.T) {
	ca := newTestCA(t)
	r := startTLSRunner(t, ca, splitKey(t, 2, 3), 0, false, nil)
	conn := devConnection(t, ca, r)
	conn.TLSKeyPin = hex.EncodeToString(make([]byte, 32))
	_, err := testNode(t, conn).PublicKeys(ctxShort(t))
	refusedBeforeRequests(t, r, err, "pinned")
	if r.seen(wire.TypeIdentity) != 0 {
		t.Fatal("IDENTITY sent to a signer with another TLS key")
	}

	// The right pin works.
	conn.TLSKeyPin = hex.EncodeToString(r.spki)
	if _, err := testNode(t, conn).PublicKeys(ctxShort(t)); err != nil {
		t.Fatal(err)
	}
}

// A signer whose certificate says it signs for mainnet is refused unless
// the settings say mainnet; one of a test network is refused when they do.
func TestNodeRefusesWrongChainMark(t *testing.T) {
	ca := newTestCA(t)
	k := splitKey(t, 2, 3)
	mainnet := startTLSRunner(t, ca, k, 0, false, chainMark(t, proto.Version{0, 0, 0, 0}))
	_, err := testNode(t, devConnection(t, ca, mainnet)).PublicKeys(ctxShort(t))
	refusedBeforeRequests(t, mainnet, err, "mainnet")

	testnet := startTLSRunner(t, ca, k, 0, false, chainMark(t, proto.Version{0x10, 0, 0, 0}))
	if _, err := testNode(t, devConnection(t, ca, testnet)).PublicKeys(ctxShort(t)); err != nil {
		t.Fatalf("test network signer, settings without mainnet: %v", err)
	}
	conn := devConnection(t, ca, testnet)
	conn.Attestation.Mainnet = true
	n, err := newNode(conn, poolConfig{size: 1}, runnerclient.WithTimeout(3*time.Second))
	if err != nil {
		// The settings themselves may refuse mainnet with this verifier.
		t.Logf("mainnet settings with the dev verifier: %v", err)

		return
	}
	defer n.Close()
	other := startTLSRunner(t, ca, k, 0, false, chainMark(t, proto.Version{0x10, 0, 0, 0}))
	conn.Address = other.addr()
	n2, err := newNode(conn, poolConfig{size: 1}, runnerclient.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer n2.Close()
	_, err = n2.PublicKeys(ctxShort(t))
	refusedBeforeRequests(t, other, err, "mainnet")
}

func TestNodeRefusesAttestationWithoutTheNonce(t *testing.T) {
	ca := newTestCA(t)
	r := startTLSRunner(t, ca, splitKey(t, 2, 3), 0, true, nil)
	_, err := testNode(t, devConnection(t, ca, r)).PublicKeys(ctxShort(t))
	refusedBeforeRequests(t, r, err, "attestation")
}

// Through Signers: a signer that fails its check is a failed signer, and
// the other two still sign.
func TestSignersWithOneSignerRefused(t *testing.T) {
	ca := newTestCA(t)
	k := splitKey(t, 2, 3)
	var nodes []runner
	var runners []*tlsRunner
	for i := range 3 {
		var exts []pkix.Extension
		if i == 0 {
			exts = chainMark(t, proto.Version{0, 0, 0, 0})
		}
		r := startTLSRunner(t, ca, k, i, false, exts)
		runners = append(runners, r)
		nodes = append(nodes, testNode(t, devConnection(t, ca, r)))
	}
	s := newSigners([]string{"signer-1", "signer-2", "signer-3"}, nodes, 0, 3*time.Second,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, err := s.Refresh(ctxShort(t)); err != nil {
		t.Fatal(err)
	}
	if g, ok := s.keys.lookup(k.pk); !ok || len(g.shares) != 2 || g.threshold != 2 {
		t.Fatalf("group %+v", g)
	}
	sig, err := s.Sign(ctxShort(t), k.pk, attestationJob())
	if err != nil {
		t.Fatal(err)
	}
	if sig != phase0.BLSSignature(signRoot(&k.sk, testRoot)) {
		t.Fatal("combined signature")
	}
	if n := runners[0].seen(wire.TypePublicKeys) + runners[0].seen(wire.TypeSign); n != 0 {
		t.Fatalf("%d requests reached the refused signer", n)
	}
}
