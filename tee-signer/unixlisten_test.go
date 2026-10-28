package main

import (
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol/transport"
)

// A unix listener is refused off the dev platform in release and key
// generation builds, and kept on dev; a debug build keeps it everywhere.
func TestUnixListenerOffDev(t *testing.T) {
	unix := []transport.Addr{{Network: "unix", Address: "/tmp/r.sock"}}
	for _, p := range []string{"dev", "gcp", "azure", "nitro"} {
		err := checkFlags(p, unix, true, "none", "")
		refused := err != nil && strings.Contains(err.Error(), "unix listener")
		if want := p != "dev" && !unixOffDevAllowed(); refused != want {
			t.Errorf("platform %s: %v, refused want %v", p, err, want)
		}
	}
}
