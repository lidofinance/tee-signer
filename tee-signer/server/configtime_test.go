package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setuptext"
	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// Every sample setup and open update of governance/setuptext names
// time_servers the runner takes, so the samples stay usable setups.
func TestSampleTimeServersPassTheCatalog(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "governance", "setuptext", "testdata", "*.conf"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no samples: %v", err)
	}
	checked := 0
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var o *setupwire.Open
		name := filepath.Base(p)
		switch {
		case strings.HasPrefix(name, "setup-"):
			s, err := setuptext.ParseSetup(name, raw)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			o = &s.Open
		case strings.HasPrefix(name, "update-"):
			u, err := setuptext.ParseUpdate(name, raw)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			o = u.Body.Open
		}
		if o == nil {
			continue // a locked update
		}
		if err := CheckTimeServers(o.TimeServers); err != nil {
			t.Errorf("%s: time_servers %v: %v", name, o.TimeServers, err)
		}
		checked++
	}
	if checked < 7 {
		t.Fatalf("checked %d samples, want the 6 setups and the open update", checked)
	}
}
