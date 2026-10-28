package transport

import "testing"

func TestParseAndString(t *testing.T) {
	for _, tc := range []struct{ in, out string }{
		{"tcp:127.0.0.1:7100", "tcp:127.0.0.1:7100"},
		{"unix:/run/signer/runner.sock", "unix:/run/signer/runner.sock"},
		{"vsock:16:7100", "vsock:16:7100"},
		{"vsock:any:7100", "vsock:any:7100"},
	} {
		a, err := Parse(tc.in)
		if err != nil {
			t.Fatalf("%s: %v", tc.in, err)
		}
		if a.String() != tc.out {
			t.Fatalf("%s parses to %s", tc.in, a)
		}
	}
	for _, bad := range []string{"", "tcp", "tcp:", "tcp:nohostport", "vsock:1", "vsock:x:1", "vsock:1:x", "udp:1.2.3.4:5"} {
		if _, err := Parse(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}
