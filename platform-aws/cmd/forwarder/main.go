// Command forwarder is the network entry of an AWS signer, for the parent
// EC2 instance: it accepts TCP connections and copies each one to the
// enclave's vsock port. Nothing else. It does not terminate TLS and holds
// no certificate, key or CA: the runner's mutual TLS ends inside the
// enclave, and the parent is not trusted.
// Any other TCP forwarder does the same job, for example
//
//	socat TCP-LISTEN:7100,fork,reuseaddr VSOCK-CONNECT:16:7100
//
// UNTESTED on EC2: the copy logic is tested over TCP, and vsock never
// carried a byte here.
//
//	forwarder -listen tcp:0.0.0.0:7100 -to vsock:16:7100
//
// -metrics-listen 127.0.0.1:PORT serves Prometheus metrics
// (platform-aws/README.md, "Metrics").
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
	"time"

	"github.com/lidofinance/tee-signer/platform-aws/cmd/internal/metrics"
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
		listen   = flag.String("listen", "tcp:0.0.0.0:7100", "address the signing client connects to (tcp:HOST:PORT)")
		to       = flag.String("to", "", "the enclave's address (vsock:CID:PORT, the runner's -listen port), required")
		maxConns = flag.Int("max-conns", 256, "connections open at once; more are closed")
		perSrc   = flag.Int("max-conns-per-source", 16, "connections from one source IP address within their first 15 s, the TLS handshake window (the enclave cannot tell outside peers apart); more are closed; a connection past the window counts against -max-conns only; -1 = no bound")
		mAddr    = flag.String("metrics-listen", "", "HOST:PORT for Prometheus metrics at /metrics, plain HTTP without authentication; empty = off")
		mRemote  = flag.Bool("metrics-allow-remote", false, "allow a -metrics-listen address that is not loopback")
	)
	flag.Parse()
	if *to == "" {
		return fmt.Errorf("-to is required, for example -to vsock:16:7100")
	}
	if *mAddr != "" {
		if err := metrics.CheckAddr(*mAddr, *mRemote); err != nil {
			return err
		}
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
		Dial:              func(ctx context.Context) (net.Conn, error) { return transport.Dial(ctx, target) },
		MaxConns:          *maxConns,
		MaxConnsPerSource: *perSrc,
		Log:               log,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if *mAddr != "" {
		start := time.Now()
		if err := metrics.Start(ctx, *mAddr, *mRemote, func(w *metrics.Writer) { writeMetrics(w, f.Stats(), start) }, log); err != nil {
			return err
		}
	}
	log.Info("forwarding bytes, no TLS here", "listen", from.String(), "to", target.String(), "max_conns", *maxConns, "max_conns_per_source", *perSrc)
	return f.Serve(ctx, l)
}

func writeMetrics(w *metrics.Writer, s forward.Stats, start time.Time) {
	w.Gauge("signer_forwarder_start_time_seconds", "Start time of the forwarder, Unix seconds.", float64(start.Unix()))
	w.Counter("signer_forwarder_connections_accepted_total", "Connections accepted, refused ones included.", float64(s.Accepted))
	w.Gauge("signer_forwarder_connections_open", "Connections being forwarded now.", float64(s.Open))
	const refused = "signer_forwarder_connections_refused_total"
	w.Counter(refused, "Connections closed at accept, by the bound reached.", float64(s.RefusedMaxConns), "reason", "max_conns")
	w.Counter(refused, "", float64(s.RefusedPerSource), "reason", "max_conns_per_source")
	w.Counter("signer_forwarder_dial_failures_total", "Dials to the enclave that failed; the client was closed.", float64(s.DialFailures))
}
