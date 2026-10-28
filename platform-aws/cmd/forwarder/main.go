// Command forwarder is the network entry of an AWS signer, for the parent
// EC2 instance: it accepts TCP connections and copies each one to the
// enclave's vsock port. Nothing else. It does not terminate TLS and holds
// no certificate, key or CA: the runner's mutual TLS ends inside the
// enclave, and the parent is not trusted (DESIGN-INVARIANTS.md, rule 12).
// Any other TCP forwarder does the same job, for example
//
//	socat TCP-LISTEN:7100,fork,reuseaddr VSOCK-CONNECT:16:7100
//
// UNTESTED on EC2: the copy logic is tested over TCP, and vsock never
// carried a byte here.
//
//	forwarder -listen tcp:0.0.0.0:7100 -to vsock:16:7100
//
// Build it with -tags platform_aws: only that build has vsock
// (scripts/build-runner.sh does).
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/lidofinance/tee-signer/platform-aws/forward"
	"github.com/lidofinance/tee-signer/signer-protocol/transport"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "forwarder:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		listen   = flag.String("listen", "tcp:0.0.0.0:7100", "address the Dirk fork connects to (tcp:HOST:PORT)")
		to       = flag.String("to", "", "the enclave's address (vsock:CID:PORT, the runner's -listen port), required")
		maxConns = flag.Int("max-conns", 256, "connections open at once; more are closed")
	)
	flag.Parse()
	if *to == "" {
		return fmt.Errorf("-to is required, for example -to vsock:16:7100")
	}
	from, err := transport.Parse(*listen)
	if err != nil {
		return err
	}
	if from.Network != "tcp" {
		return fmt.Errorf("-listen %q: the forwarder listens on tcp", *listen)
	}
	target, err := transport.Parse(*to)
	if err != nil {
		return err
	}
	if target.Network == "vsock" && target.CID == transport.AnyCID {
		return fmt.Errorf("-to %q: give the enclave's CID, not any", *to)
	}
	if target.Network == "vsock" && !transport.HasVsock() {
		return fmt.Errorf("this binary has no vsock: build it with -tags platform_aws (scripts/build-runner.sh does)")
	}
	l, err := transport.Listen(from)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	f := &forward.Forwarder{
		Dial:     func(ctx context.Context) (net.Conn, error) { return transport.Dial(ctx, target) },
		MaxConns: *maxConns,
		Log:      log,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Info("forwarding bytes, no TLS here", "listen", from.String(), "to", target.String(), "max_conns", *maxConns)
	return f.Serve(ctx, l)
}
