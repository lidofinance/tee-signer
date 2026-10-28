package nitro

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform-aws/udprelay"
)

// NetDial sends TCP to the proxy route of the host:port and UDP through the
// relay, and refuses what has neither.
func TestNetDial(t *testing.T) {
	// A TCP "vsock-proxy": the route's address, answering "kept".
	tl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tl.Close()
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("kept"))
			c.Close()
		}
	}()
	// A UDP server and the relay in front of it.
	u, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	go func() {
		b := make([]byte, 100)
		for {
			n, from, err := u.ReadFromUDP(b)
			if err != nil {
				return
			}
			_, _ = u.WriteToUDP(append([]byte("re:"), b[:n]...), from)
		}
	}()
	uport := uint16(u.LocalAddr().(*net.UDPAddr).Port)
	rl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := &udprelay.Server{Allow: &udprelay.Allowlist{Nets: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Ports: []uint16{uport}}}
	go func() { _ = srv.Serve(ctx, rl) }()

	o := platform.Options{Params: map[string]string{
		"proxy":     "time.example:4460=tcp:" + tl.Addr().String(),
		"ntp_relay": "tcp:" + rl.Addr().String(),
	}}
	routes, relay, err := netOptions(o)
	if err != nil {
		t.Fatal(err)
	}
	dial := NetDial(routes, relay)
	dctx, dcancel := context.WithTimeout(ctx, 5*time.Second)
	defer dcancel()

	c, err := dial(dctx, "tcp", "time.example:4460")
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 10)
	n, _ := c.Read(b)
	c.Close()
	if string(b[:n]) != "kept" {
		t.Fatalf("tcp route: %q", b[:n])
	}
	if _, err := dial(dctx, "tcp", "time.example:443"); err == nil || !strings.Contains(err.Error(), "no vsock-proxy route") {
		t.Fatalf("tcp without a route: %v", err)
	}

	uc, err := dial(dctx, "udp", "127.0.0.1:"+strconv.Itoa(int(uport)))
	if err != nil {
		t.Fatal(err)
	}
	_ = uc.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = uc.Write([]byte("ntp"))
	n, err = uc.Read(b)
	uc.Close()
	if err != nil || string(b[:n]) != "re:ntp" {
		t.Fatalf("udp through the relay: %q %v", b[:n], err)
	}
	if c, err := dial(dctx, "udp", "127.0.0.1:123"); err == nil || !strings.Contains(err.Error(), "refused") {
		if c != nil {
			c.Close()
		}
		t.Fatalf("udp to a port off the allowlist: %v", err)
	}
	if _, err := NetDial(routes, nil)(dctx, "udp", "127.0.0.1:123"); err == nil || !strings.Contains(err.Error(), "ntp_relay") {
		t.Fatalf("udp without a relay: %v", err)
	}
	if _, err := dial(dctx, "unix", "/tmp/x"); err == nil {
		t.Fatal("unix dialed")
	}

	if _, _, err := netOptions(platform.Options{Params: map[string]string{"ntp_relay": "vsock:3"}}); err == nil {
		t.Fatal("bad ntp_relay accepted")
	}
	if _, r, err := netOptions(platform.Options{}); err != nil || r != nil {
		t.Fatalf("no options: %v %v", r, err)
	}
}
