package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// draft and show check time_servers against this build's NTS catalog: a
// list the catalog refuses gets a warning, an unchanged list nothing.
func TestCheckTimeServersNote(t *testing.T) {
	active := &setupwire.Open{}
	for _, c := range []struct {
		list []string
		want string
	}{
		{[]string{"nosuch.example"}, "warning: time_servers: the NTS catalog of this signer-admin build refuses"},
		{[]string{"ptb"}, "warning: time_servers"},
		{[]string{"fer"}, "time_servers: the NTS catalog of this signer-admin build takes the list"},
	} {
		var out bytes.Buffer
		checkTimeServersNote(&out, active, &setupwire.Open{TimeServers: c.list})
		if !strings.Contains(out.String(), c.want) {
			t.Errorf("%v: %q, want %q", c.list, out.String(), c.want)
		}
	}
	var out bytes.Buffer
	checkTimeServersNote(&out, &setupwire.Open{TimeServers: []string{"x"}}, &setupwire.Open{TimeServers: []string{"x"}})
	if out.Len() != 0 {
		t.Errorf("unchanged list: %q", out.String())
	}
}
