package runnerclient

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient/verify"
	"github.com/lidofinance/tee-signer/governance/runnerchain"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

// runnerChainOID is the extension of the runner's TLS certificate that
// names its chain: the genesis fork version and the genesis validators
// root, an OCTET STRING of 36 bytes (4 from older runners).
var runnerChainOID = asn1.ObjectIdentifier{1, 2, 840, 113556, 1, 8000, 2554,
	49247, 57036, 45844, 17649, 38356, 1811430, 10320378, 3}

// The genesis values of the tests: mainnet, hoodi, the devnet row's fork
// version, a fork version no row of the chain table names, and a root
// that is no public network's.
var (
	mainnetFork = backend.Version{0, 0, 0, 0}
	hoodiFork   = backend.Version{0x10, 0, 0x09, 0x10}
	devnetFork  = backend.Version{0x10, 0, 0, 0x38}
	unknownFork = backend.Version{0xde, 0xad, 0xbe, 0xef}
	hoodiRoot   = mustRoot("212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f")
	mainnetRoot = mustRoot("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95")
	devnetRoot  = backend.Root{0xd0}
)

func mustRoot(s string) (r backend.Root) {
	if n, err := hex.Decode(r[:], []byte(s)); err != nil || n != len(r) {
		panic(s)
	}
	return r
}

func chainExt(t *testing.T, gfv backend.Version, gvr ...backend.Root) []pkix.Extension {
	t.Helper()
	raw := gfv[:]
	for _, r := range gvr {
		raw = append(raw, r[:]...)
	}
	v, err := asn1.Marshal(raw)
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

	mainnet := maaRunner(t, ca, env, chainExt(t, mainnetFork, mainnetRoot))
	c := mainnetConn(t, ca, mainnet, env)
	c.Attestation.Mainnet = false
	wantErr(t, health(t, c, opts...), "mainnet")
	if n := mainnet.seen(wire.TypeIdentity) + mainnet.seen(wire.TypeHealth); n != 0 {
		t.Errorf("the client sent %d requests to a refused runner", n)
	}
	if err := health(t, mainnetConn(t, ca, mainnet, env), opts...); err != nil {
		t.Fatalf("mainnet runner, client set to mainnet: %v", err)
	}

	hoodi := maaRunner(t, ca, env, chainExt(t, hoodiFork, hoodiRoot))
	c = mainnetConn(t, ca, hoodi, env)
	c.Attestation.Mainnet = false
	if err := health(t, c, opts...); err != nil {
		t.Fatalf("test network runner, client without mainnet: %v", err)
	}
	wantErr(t, health(t, mainnetConn(t, ca, hoodi, env), opts...), "mainnet")

	// Fail closed: a chain without a row in the chain table is prod, so the
	// client takes its runner only with the mainnet rules. So is a test
	// network's fork version with mainnet's root: it signs mainnet
	// messages.
	for name, ext := range map[string][]pkix.Extension{
		"unknown chain":             chainExt(t, unknownFork, hoodiRoot),
		"hoodi fork, mainnet root":  chainExt(t, hoodiFork, mainnetRoot),
		"devnet fork, mainnet root": chainExt(t, devnetFork, mainnetRoot),
	} {
		r := maaRunner(t, ca, env, ext)
		c := mainnetConn(t, ca, r, env)
		c.Attestation.Mainnet = false
		if err := health(t, c, opts...); err == nil || !strings.Contains(err.Error(), "set mainnet") {
			t.Errorf("%s, client without mainnet: %v, want refused", name, err)
		}
		if err := health(t, mainnetConn(t, ca, r, env), opts...); err != nil {
			t.Errorf("%s, client set to mainnet: %v", name, err)
		}
	}

	// A runner without a mark, or with the fork version alone (built before
	// the root was in the mark): the setting alone decides.
	for name, ext := range map[string][]pkix.Extension{
		"no chain mark":         nil,
		"hoodi fork, no root":   chainExt(t, hoodiFork),
		"mainnet fork, no root": chainExt(t, mainnetFork),
	} {
		r := maaRunner(t, ca, env, ext)
		for _, m := range []bool{false, true} {
			c := mainnetConn(t, ca, r, env)
			c.Attestation.Mainnet = m
			if err := health(t, c, opts...); err != nil {
				t.Errorf("runner with %s, client mainnet %v: %v", name, m, err)
			}
		}
	}
}

// The dev verifier accepts an unsigned document, so it proves nothing
// about the runner it talks to. It never reaches a mainnet runner: the
// settings refuse dev with mainnet, and the handshake refuses a runner
// whose certificate names a prod chain when the verifier is dev, whatever
// mainnet says. So one wrong flag cannot seal a share to a fake runner
// that claims the mainnet chain. A non-prod chain mark, or none, stays
// open to the dev verifier, and so does a mark of the fork version alone,
// which counts as none.
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

	// The handshake: a prod chain mark, mainnet, a chain without a row, a
	// test network's fork version with mainnet's root, or an old mark with
	// the fork version alone.
	for name, ext := range map[string][]pkix.Extension{
		"mainnet":                  chainExt(t, mainnetFork, mainnetRoot),
		"unknown":                  chainExt(t, unknownFork, devnetRoot),
		"hoodi fork, mainnet root": chainExt(t, hoodiFork, mainnetRoot),
		"mainnet fork, no root":    chainExt(t, mainnetFork),
		"hoodi fork, no root":      chainExt(t, hoodiFork),
	} {
		f := startFakeRunnerExt(t, ca, devAttest, runnerchain.MainnetCertName, "0.1.0", ext)
		wantErr(t, health(t, devConn(t, ca, f)), want)
		if n := f.seen(wire.TypeIdentity) + f.seen(wire.TypeHealth); n != 0 {
			t.Errorf("%s: the client sent %d requests to a refused runner", name, n)
		}
	}

	for name, ext := range map[string][]pkix.Extension{
		"test network":  chainExt(t, hoodiFork, hoodiRoot),
		"devnet":        chainExt(t, devnetFork, devnetRoot),
		"no chain mark": nil,
	} {
		f := startFakeRunnerExt(t, ca, devAttest, runnerchain.MainnetCertName, "0.1.0", ext)
		if err := health(t, devConn(t, ca, f)); err != nil {
			t.Errorf("runner with %s, dev verifier: %v", name, err)
		}
	}
}

// The test's OID is the one of package backend, which the runner writes.
func TestRunnerChainOID(t *testing.T) {
	if !runnerChainOID.Equal(backend.RunnerChainOID) {
		t.Fatalf("test OID %v, backend %v", runnerChainOID, backend.RunnerChainOID)
	}
}
