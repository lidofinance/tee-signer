package runnerclient

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient/verify"
	"github.com/lidofinance/tee-signer/governance/runnerchain"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

// runnerChainOID is the extension of the runner's TLS certificate that
// names its chain: the genesis fork version, an OCTET STRING of 4 bytes.
var runnerChainOID = asn1.ObjectIdentifier{1, 2, 840, 113556, 1, 8000, 2554,
	49247, 57036, 45844, 17649, 38356, 1811430, 10320378, 3}

// The chain marks of the tests: mainnet, hoodi, and a fork version no
// row of the chain table names (prod, since the table fails closed).
var (
	mainnetMark = backend.Version{0, 0, 0, 0}
	hoodiMark   = backend.Version{0x10, 0, 0x09, 0x10}
	unknownMark = backend.Version{0xde, 0xad, 0xbe, 0xef}
)

func chainExt(t *testing.T, gfv backend.Version) []pkix.Extension {
	t.Helper()
	v, err := asn1.Marshal(gfv[:])
	if err != nil {
		t.Fatal(err)
	}
	return []pkix.Extension{{Id: runnerChainOID, Value: v}}
}

// maaRunner is a fake runner with a good MAA token and the extensions exts
// (a chain mark, or none) in its certificate. The client of mainnetConn
// reaches it.
func maaRunner(t *testing.T, ca *testCA, env *maaEnv, exts []pkix.Extension) *fakeRunner {
	t.Helper()
	f := startFakeRunnerExt(t, ca, env.attest(tokenSpec{}), runnerchain.MainnetCertName, "0.1.0", exts)
	f.setState(backend.SetupState{SetupHash: fakeConfigHash, KeyReleaseHash: backend.Root{0x4b, 0x52}})
	return f
}

// mainnetConn is a client that may reach a mainnet runner: azure-maa with
// the runner's setup and key rule hashes pinned, mainnet set.
func mainnetConn(t *testing.T, ca *testCA, f *fakeRunner, env *maaEnv) Connection {
	t.Helper()
	c := maaConn(t, ca, f, env)
	c.Attestation.Mainnet = true
	c.Attestation.KeyReleaseSHA256 = pinOf(backend.Root{0x4b, 0x52})
	return c
}

// The client's mainnet setting fails open: the identity names no chain,
// so a client that leaves mainnet out reaches a mainnet runner without
// the mainnet rules (key_release_sha256 for azure-maa and aws-nitro).
// The runner's certificate names its chain; a client refuses a runner
// whose chain is mainnet unless its settings say mainnet, and a runner of
// another chain if they do. A runner whose certificate names no chain is
// checked by the setting alone.
func TestMainnetRunnerNeedsMainnetSetting(t *testing.T) {
	ca := newTestCA(t)
	env := newMAAEnv(t, mainKeySet(t))
	opts := []Option{verify.WithHTTPClient(env.srv.Client())}

	mainnet := maaRunner(t, ca, env, chainExt(t, mainnetMark))
	c := mainnetConn(t, ca, mainnet, env)
	c.Attestation.Mainnet = false
	wantErr(t, health(t, c, opts...), "mainnet")
	if n := mainnet.seen(wire.TypeIdentity) + mainnet.seen(wire.TypeHealth); n != 0 {
		t.Errorf("the client sent %d requests to a refused runner", n)
	}
	if err := health(t, mainnetConn(t, ca, mainnet, env), opts...); err != nil {
		t.Fatalf("mainnet runner, client set to mainnet: %v", err)
	}

	hoodi := maaRunner(t, ca, env, chainExt(t, hoodiMark))
	c = mainnetConn(t, ca, hoodi, env)
	c.Attestation.Mainnet = false
	if err := health(t, c, opts...); err != nil {
		t.Fatalf("test network runner, client without mainnet: %v", err)
	}
	wantErr(t, health(t, mainnetConn(t, ca, hoodi, env), opts...), "mainnet")

	// Fail closed: a chain without a row in the chain table is prod, so the
	// client takes its runner only with the mainnet rules.
	unknown := maaRunner(t, ca, env, chainExt(t, unknownMark))
	c = mainnetConn(t, ca, unknown, env)
	c.Attestation.Mainnet = false
	wantErr(t, health(t, c, opts...), "set mainnet")
	if err := health(t, mainnetConn(t, ca, unknown, env), opts...); err != nil {
		t.Fatalf("unknown chain runner, client set to mainnet: %v", err)
	}

	old := maaRunner(t, ca, env, nil)
	for _, m := range []bool{false, true} {
		c := mainnetConn(t, ca, old, env)
		c.Attestation.Mainnet = m
		if err := health(t, c, opts...); err != nil {
			t.Fatalf("runner without a chain mark, client mainnet %v: %v", m, err)
		}
	}
}

// The dev verifier accepts an unsigned document, so it proves nothing
// about the runner it talks to. It never reaches a mainnet runner: the
// settings refuse dev with mainnet, and the handshake refuses a runner
// whose certificate names a prod chain when the verifier is dev, whatever
// mainnet says. So one wrong flag cannot seal a share to a fake runner
// that claims the mainnet chain. A non-prod chain mark, or none, stays
// open to the dev verifier.
func TestDevVerifierNeverReachesMainnet(t *testing.T) {
	ca := newTestCA(t)
	const want = "the dev verifier proves nothing"

	// The settings: share-import -verifier dev -setup-sha256 PIN -mainnet.
	for _, a := range []Attestation{
		{Verifier: VerifierDev, Mainnet: true},
		{Verifier: VerifierDev, Mainnet: true, SetupSHA256: pinOf(testSetupHash)},
	} {
		wantErr(t, a.Validate(), want)
		_, err := a.NewVerifier()
		wantErr(t, err, want)
		cert, key := ca.issue(t, t.TempDir(), "client", time.Time{})
		c := Connection{Address: "tcp:127.0.0.1:7100", ClientCert: cert, ClientKey: key, Attestation: a}
		wantErr(t, c.Validate(), want)
		_, err = c.New()
		wantErr(t, err, want)
	}

	// The handshake: a prod chain mark, mainnet or a chain without a row.
	for name, mark := range map[string]backend.Version{"mainnet": mainnetMark, "unknown": unknownMark} {
		f := startFakeRunnerExt(t, ca, devAttest, runnerchain.MainnetCertName, "0.1.0", chainExt(t, mark))
		wantErr(t, health(t, devConn(t, ca, f)), want)
		if n := f.seen(wire.TypeIdentity) + f.seen(wire.TypeHealth); n != 0 {
			t.Errorf("%s: the client sent %d requests to a refused runner", name, n)
		}
	}

	hoodi := startFakeRunnerExt(t, ca, devAttest, runnerchain.MainnetCertName, "0.1.0", chainExt(t, hoodiMark))
	if err := health(t, devConn(t, ca, hoodi)); err != nil {
		t.Fatalf("test network runner, dev verifier: %v", err)
	}
	old := startFakeRunner(t, ca, devAttest)
	if err := health(t, devConn(t, ca, old)); err != nil {
		t.Fatalf("runner without a chain mark, dev verifier: %v", err)
	}
}

// The test's OID is the one of package backend, which the runner writes.
func TestRunnerChainOID(t *testing.T) {
	if !runnerChainOID.Equal(backend.RunnerChainOID) {
		t.Fatalf("test OID %v, backend %v", runnerChainOID, backend.RunnerChainOID)
	}
}
