// Package fakerunner is a cloud runner for the tests of cloud-import,
// proof-check and signer-admin. It serves mutual TLS 1.3 on 127.0.0.1 with
// a client CA of its own, and answers IDENTITY with the dev platform's
// document and a setup state the test sets, HEALTH, PUBLIC_KEYS and
// IMPORT_SHARE_SEALED. It opens each sealed share with a real HPKE key, so a
// share sealed to its identity imports. A runner made with StartSetup has a
// setup and takes CONFIG_UPDATE (config.go). It counts the requests it gets
// by type and signs nothing. Only tests use it.
package fakerunner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/flavor"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/sealedimport"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

// Runner is one fake runner.
type Runner struct {
	ln       net.Listener
	caCert   *x509.Certificate
	caKey    *ecdsa.PrivateKey
	tlsKey   []byte // sha256 of its TLS key, as its identity names it
	importer *sealedimport.Key

	mu     sync.Mutex
	state  cloud.SetupState
	keys   []cloud.ValidatorKey
	frames map[wire.MsgType]int
	// afterImport, if set, gives the state of the identities after each
	// import (SetAfterImport).
	afterImport *cloud.SetupState
	// config, if set (StartSetup), holds the setup and the config groups;
	// the state comes from it.
	config *configModel
	// flavor is the build flavour it plays: its certificate's name and its
	// HEALTH version (StartSetupAs).
	flavor flavor.Flavor
}

// SetAfterImport makes the runner report s from the first share it
// imports on, as a runner whose config changed while the shares go in.
func (r *Runner) SetAfterImport(s cloud.SetupState) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.afterImport = &s
}

// Start starts a runner whose identity carries state. It stops at the end
// of the test.
func Start(t testing.TB, state cloud.SetupState) *Runner {
	t.Helper()
	return start(t, state, flavor.Default)
}

// start starts a runner of build flavour f.
func start(t testing.TB, state cloud.SetupState, f flavor.Flavor) *Runner {
	t.Helper()
	r := &Runner{state: state, frames: map[wire.MsgType]int{}, flavor: f}
	certName := flavor.DefaultCertName
	if f == flavor.Testnet {
		certName = flavor.TestnetCertName
	}
	var err error
	if r.caKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fakerunner client CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &r.caKey.PublicKey, r.caKey)
	if err != nil {
		t.Fatal(err)
	}
	if r.caCert, err = x509.ParseCertificate(der); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(r.caCert)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99), Subject: pkix.Name{CommonName: certName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	r.tlsKey = h[:]
	if r.importer, err = sealedimport.Generate(); err != nil {
		t.Fatal(err)
	}
	r.ln, err = tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}},
		ClientAuth:   tls.RequireAndVerifyClientCert, ClientCAs: pool,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.ln.Close() })
	go func() {
		for {
			c, err := r.ln.Accept()
			if err != nil {
				return
			}
			go r.serve(c)
		}
	}()
	return r
}

// Addr is the runner's address, tcp:127.0.0.1:PORT.
func (r *Runner) Addr() string { return "tcp:" + r.ln.Addr().String() }

// SetState changes the setup state of the next identities.
func (r *Runner) SetState(s cloud.SetupState) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.state = s
}

// Seen is the number of requests of type t so far.
func (r *Runner) Seen(t wire.MsgType) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.frames[t]
}

// Keys are the keys of the shares it imported.
func (r *Runner) Keys() []cloud.ValidatorKey {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]cloud.ValidatorKey(nil), r.keys...)
}

// ClientFiles writes a client certificate of the runner's CA and its key
// into dir as client.pem and client-key.pem, and returns their paths.
func (r *Runner) ClientFiles(t testing.TB, dir string) (cert, key string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "client"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, r.caCert, &k.PublicKey, r.caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	cert, key = filepath.Join(dir, "client.pem"), filepath.Join(dir, "client-key.pem")
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func (r *Runner) serve(c net.Conn) {
	defer c.Close()
	for {
		f, err := wire.ReadFrame(c)
		if err != nil {
			return
		}
		r.mu.Lock()
		r.frames[f.Type]++
		r.mu.Unlock()
		var answer []byte
		switch f.Type {
		case wire.TypeIdentity:
			nonce, err := wire.DecodeAttest(f.Payload)
			if err != nil {
				return
			}
			body, err := r.identity(nonce)
			if err != nil {
				return
			}
			answer = wire.EncodeOK(body)
		case wire.TypeHealth:
			h := &cloud.Health{Platform: "dev", Ready: true, ClockUnix: uint64(time.Now().Unix())}
			if r.flavor == flavor.Testnet {
				h.Version = "0.1.0" + flavor.VersionSuffix
			}
			r.mu.Lock()
			if r.config != nil {
				s := r.config.state(unixNow())
				h.Setup, h.ConfigHash = &s, s.SetupHash
				h.ClockSource, h.ClockTrusted = "fake", true
			}
			r.mu.Unlock()
			body, _ := wire.EncodeHealth(h)
			answer = wire.EncodeOK(body)
		case wire.TypePublicKeys:
			answer = wire.EncodeOK(wire.EncodeKeys(r.Keys()))
		case wireadmin.TypeImportSealed:
			answer = r.importSealed(f.Payload)
		case wireadmin.TypeConfigUpdate:
			answer = r.configUpdate(f.Payload)
		default:
			return
		}
		if err := wire.WriteFrame(c, wire.Frame{Type: f.Type | wire.ResponseFlag, ID: f.ID, Payload: answer}); err != nil {
			return
		}
	}
}

// identity is the IDENTITY answer: the state, the HPKE import key, the TLS
// key hash and the dev platform's document over them.
func (r *Runner) identity(nonce []byte) ([]byte, error) {
	r.mu.Lock()
	state := r.state
	if r.config != nil {
		state = r.config.state(unixNow())
	}
	r.mu.Unlock()
	id := &cloud.Identity{State: state, TLSKeyHash: r.tlsKey}
	r.importer.Fill(id)
	ud := cloud.IdentityUserData(nonce, id)
	doc, err := json.Marshal(map[string]any{"nonce": nonce, "user_data": ud})
	if err != nil {
		return nil, err
	}
	id.Attestation = &cloud.Attestation{Platform: "dev", Format: "dev-json", UserData: ud, Document: doc}
	return wire.EncodeIdentity(id)
}

// importSealed opens the share and keeps its key. It does not check the
// share against its public key.
func (r *Runner) importSealed(p []byte) []byte {
	req, err := wireadmin.DecodeImportSealed(p)
	if err != nil {
		return wire.EncodeError(cloud.Refused(cloud.StatusDecode, "%v", err))
	}
	secret, err := r.importer.Open(&req)
	clear(secret[:])
	if err != nil {
		return wire.EncodeError(cloud.Refused(cloud.StatusBadKey, "%v", err))
	}
	k := cloud.ValidatorKey{Pubkey: req.Pubkey, SharePubkey: req.SharePubkey, Index: req.Index}
	r.mu.Lock()
	r.keys = append(r.keys, k)
	if r.afterImport != nil {
		r.state = *r.afterImport
	}
	r.mu.Unlock()
	return wire.EncodeOK(wire.AppendKey(nil, k))
}
