// Command udprelay runs on the Nitro parent instance. It carries the NTS
// clock's NTP datagrams between the enclave (vsock) and the NTP servers
// (UDP), for destinations on an allowlist only (package udprelay).
//
//	udprelay -listen vsock:any:7102
//
// The defaults allow the runner's four NTS operators: the NTS-KE host names,
// ports 123 and 4123, and Netnod's NTP server block 194.58.200.0/21. The
// relay cannot forge time: NTS authenticates every answer. It can delay or
// drop datagrams, as any network on the path can.
//
// Build it with -tags platform_aws: only that build has vsock
// (scripts/build-runner.sh does).
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/lidofinance/tee-signer/platform-aws/udprelay"
	"github.com/lidofinance/tee-signer/signer-protocol/transport"
)

func main() {
	listen := flag.String("listen", "vsock:any:7102", "address the enclave dials (vsock:any:PORT on the parent; tcp:HOST:PORT for tests)")
	names := flag.String("allow-names", strings.Join(udprelay.DefaultNames, ","), "comma-separated host names a destination may name")
	var defNets []string
	for _, p := range udprelay.DefaultNets {
		defNets = append(defNets, p.String())
	}
	nets := flag.String("allow-nets", strings.Join(defNets, ","), "comma-separated address blocks a destination address may lie in")
	ports := flag.String("allow-ports", "123,4123", "comma-separated UDP ports a destination may name")
	maxSessions := flag.Int("max-sessions", 16, "sessions at once")
	rate := flag.Float64("rate", 10, "datagrams out per second, all destinations")
	burst := flag.Float64("burst", 20, "datagrams out at once, all destinations")
	destRate := flag.Float64("dest-rate", 0.5, "datagrams out per second to one address")
	destBurst := flag.Float64("dest-burst", 4, "datagrams out at once to one address")
	statsEvery := flag.Duration("stats-every", 10*time.Minute, "period of the counters log line; 0 = never")
	debug := flag.Bool("debug", false, "log every session")
	flag.Parse()

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	fail := func(err error) {
		fmt.Fprintln(os.Stderr, "udprelay:", err)
		os.Exit(2)
	}
	allow := &udprelay.Allowlist{Names: udprelay.ParseNames(*names)}
	var err error
	if allow.Nets, err = udprelay.ParseNets(*nets); err != nil {
		fail(err)
	}
	if allow.Ports, err = udprelay.ParsePorts(*ports); err != nil {
		fail(err)
	}
	if len(allow.Ports) == 0 || (len(allow.Names) == 0 && len(allow.Nets) == 0) {
		fail(fmt.Errorf("the allowlist needs ports and names or address blocks"))
	}
	a, err := transport.Parse(*listen)
	if err != nil {
		fail(err)
	}
	if a.Network == "vsock" && !transport.HasVsock() {
		fail(fmt.Errorf("this binary has no vsock: build it with -tags platform_aws (scripts/build-runner.sh does)"))
	}
	l, err := transport.Listen(a)
	if err != nil {
		fmt.Fprintln(os.Stderr, "udprelay:", err)
		os.Exit(1)
	}
	srv := &udprelay.Server{Allow: allow, Log: log, MaxSessions: *maxSessions, Rate: *rate, Burst: *burst,
		DestRate: *destRate, DestBurst: *destBurst}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Info("udprelay listening", "addr", a.String(), "names", allow.Names, "nets", *nets, "ports", allow.Ports,
		"rate", *rate, "dest_rate", *destRate)
	if *statsEvery > 0 {
		go func() {
			t := time.NewTicker(*statsEvery)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					snap := srv.Counter.Snapshot()
					var args []any
					for _, k := range slices.Sorted(maps.Keys(snap)) {
						args = append(args, k, snap[k])
					}
					log.Info("udprelay: counters", args...)
				}
			}
		}()
	}
	if err := srv.Serve(ctx, l); err != nil {
		fmt.Fprintln(os.Stderr, "udprelay:", err)
		os.Exit(1)
	}
}
