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

// The Nitro port map and the parent's UDP relay allowlist cover every host a
// runner of this image may dial (ntscatalog Endpoints): each on its own
// catalog port, clear of the fixed ports, with every NTP host name and net
// its NTS-KE can name. The default set and any confirmed choice are among
// them.
func TestNTSNitroRoutingMatchesTheCatalog(t *testing.T) {
	eps := ntscatalog.Builtin.Endpoints()
	if len(setup.NitroNTSKE) != len(eps) {
		t.Fatalf("port map has %d NTS-KE routes, the catalog has %d endpoints", len(setup.NitroNTSKE), len(eps))
	}
	routed := map[string]uint32{}
	for i, e := range eps {
		r := setup.NitroNTSKE[i]
		if r.Host != e.Host || r.Port != e.NitroPort || r.HostPort != 4460 {
			t.Errorf("route %s:%d to port %d, catalog %s %s:%d", r.Host, r.Port, r.HostPort, e.ID, e.Host, e.NitroPort)
		}
		if r.Port <= setup.PortMarkBucket || r.Port >= 9000 {
			t.Errorf("%s: port %d clashes with the fixed ports or leaves 8005 to 8999", r.Host, r.Port)
		}
		routed[r.Host] = r.Port
	}
	if want := ntscatalog.NTPHosts(eps); !slices.Equal(udprelay.DefaultNames, want) {
		t.Errorf("udprelay allows %v, the catalog's NTP hosts are %v", udprelay.DefaultNames, want)
	}
	// The plain NTP hosts of Netnod and FER, which answer plain NTP only
	// on those names.
	for _, h := range []string{"ntp.se", "ntp.hr"} {
		if !slices.Contains(udprelay.DefaultNames, h) {
			t.Errorf("udprelay does not allow the plain NTP host %s", h)
		}
	}
	var nets []netip.Prefix
	for _, n := range ntscatalog.NTPNets(eps) {
		nets = append(nets, netip.MustParsePrefix(n))
	}
	if !slices.Equal(udprelay.DefaultNets, nets) {
		t.Errorf("udprelay nets %v, catalog %v", udprelay.DefaultNets, nets)
	}
	chosen, err := ntscatalog.Builtin.WithConfirmed([]string{"time.nl@any.time.nl", "obspm"})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range chosen {
		if p, ok := routed[e.Host]; !ok || p != e.NitroPort {
			t.Errorf("%s (%s) is not routed on %d", e.Host, e.ID, e.NitroPort)
		}
	}
}
