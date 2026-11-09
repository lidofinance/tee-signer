package main

// No build tag: the catalog, the Nitro port map and the UDP relay allowlist
// need no cgo, so make test-modules runs this test.

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/lidofinance/tee-signer/platform-aws/udprelay"
	"github.com/lidofinance/tee-signer/platform/setup"
	"github.com/lidofinance/tee-signer/trusted-time/ntscatalog"
)

// The Nitro port map and the parent's UDP relay allowlist follow the
// catalog: the same port per host, every NTS-KE host, every NTP net.
func TestNTSNitroRoutingMatchesTheCatalog(t *testing.T) {
	dialed := ntscatalog.Builtin.Dialed()
	if len(setup.NitroNTSKE) != len(dialed) {
		t.Fatalf("port map has %d NTS-KE routes, the catalog dials %d servers", len(setup.NitroNTSKE), len(dialed))
	}
	var nets []netip.Prefix
	for i, e := range dialed {
		r := setup.NitroNTSKE[i]
		if r.Host != e.Host || r.Port != e.NitroPort || r.HostPort != 4460 {
			t.Errorf("route %s:%d to port %d, catalog %s %s:%d", r.Host, r.Port, r.HostPort, e.ID, e.Host, e.NitroPort)
		}
		if !slices.Contains(udprelay.DefaultNames, e.Host) {
			t.Errorf("udprelay does not allow %s (%s)", e.Host, e.ID)
		}
		for _, n := range e.NTPNets {
			nets = append(nets, netip.MustParsePrefix(n))
		}
	}
	if len(udprelay.DefaultNames) != len(dialed) {
		t.Errorf("udprelay allows %v, the catalog dials %d servers", udprelay.DefaultNames, len(dialed))
	}
	if !slices.Equal(udprelay.DefaultNets, nets) {
		t.Errorf("udprelay nets %v, catalog %v", udprelay.DefaultNets, nets)
	}
}
