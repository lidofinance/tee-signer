//go:build !peerselect

package runnerclient

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/lidofinance/tee-signer/governance/flavor"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

// runnerChainOID is the extension of the runner's TLS certificate that
// names its chain: the genesis fork version, an OCTET STRING of 4 bytes.
var runnerChainOID = asn1.ObjectIdentifier{1, 2, 840, 113556, 1, 8000, 2554,
	49247, 57036, 45844, 17649, 38356, 1811430, 10320378, 3}

func chainExt(t *testing.T, gfv backend.Version) []pkix.Extension {
	t.Helper()
	v, err := asn1.Marshal(gfv[:])
	if err != nil {
		t.Fatal(err)
	}
	return []pkix.Extension{{Id: runnerChainOID, Value: v}}
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
	mainnet := startFakeRunnerExt(t, ca, devAttest, flavor.DefaultCertName, "0.1.0", chainExt(t, backend.Version{0, 0, 0, 0}))
	wantErr(t, health(t, devConn(t, ca, mainnet)), "mainnet")
	if n := mainnet.seen(wire.TypeIdentity) + mainnet.seen(wire.TypeHealth); n != 0 {
		t.Errorf("the client sent %d requests to a refused runner", n)
	}
	c := devConn(t, ca, mainnet)
	c.Attestation.Mainnet = true
	if err := health(t, c); err != nil {
		t.Fatalf("mainnet runner, client set to mainnet: %v", err)
	}

	hoodi := startFakeRunnerExt(t, ca, devAttest, flavor.DefaultCertName, "0.1.0", chainExt(t, backend.Version{0x10, 0, 0, 0x00}))
	if err := health(t, devConn(t, ca, hoodi)); err != nil {
		t.Fatalf("test network runner, client without mainnet: %v", err)
	}
	c = devConn(t, ca, hoodi)
	c.Attestation.Mainnet = true
	wantErr(t, health(t, c), "mainnet")

	old := startFakeRunner(t, ca, devAttest)
	for _, m := range []bool{false, true} {
		c := devConn(t, ca, old)
		c.Attestation.Mainnet = m
		if err := health(t, c); err != nil {
			t.Fatalf("runner without a chain mark, client mainnet %v: %v", m, err)
		}
	}
}

// The test's OID is the one of package backend, which the runner writes.
func TestRunnerChainOID(t *testing.T) {
	if !runnerChainOID.Equal(backend.RunnerChainOID) {
		t.Fatalf("test OID %v, backend %v", runnerChainOID, backend.RunnerChainOID)
	}
}
