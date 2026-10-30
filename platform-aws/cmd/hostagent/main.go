// Command hostagent runs on the Nitro parent instance: it stores the
// enclave's sealed blobs and hands it the instance role credentials.
// UNTESTED on EC2; the protocol is tested over a unix socket.
//
//	hostagent -listen vsock:any:7101 -dir /var/lib/signer-runner -creds imds
//
// When the runner fails, it sends its error line before it exits; the agent
// writes it with the time to -exit-file (default DIR/last-exit.txt) and to
// its own log.
//
// -setup names the signer's binary setup. The agent checks it with the runner's decoder at start, logs its
// setup_hash and hands it to the enclave (SETUP) at every start. The enclave
// image is the same for every operator; the setup is what makes it this
// signer. With -proxy-routes the agent only prints the vsock-proxy routes of
// the setup, one "PORT HOST HOSTPORT" line each, for cloud/aws/parent-run.sh,
// and exits:
//
//	hostagent -setup setup.bin -proxy-routes
//
// Build it with -tags platform_aws: only that build has vsock
// (scripts/build-runner.sh does).
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/lidofinance/tee-signer/platform-aws/hostagent"
	"github.com/lidofinance/tee-signer/platform/filestore"
	"github.com/lidofinance/tee-signer/platform/setup"
	"github.com/lidofinance/tee-signer/signer-protocol/transport"
)

func main() {
	listen := flag.String("listen", "vsock:any:7101", "address the enclave dials (vsock:any:PORT on the parent)")
	dir := flag.String("dir", "hostagent-state", "directory for sealed blobs")
	creds := flag.String("creds", "imds", "imds (instance role via IMDSv2) or none")
	exitFile := flag.String("exit-file", "", "file for the runner's fatal error line (EXIT), replaced on each report; default DIR/last-exit.txt")
	setupFile := flag.String("setup", "", "the signer's binary setup, handed to the enclave at every start (SETUP)")
	routes := flag.Bool("proxy-routes", false, "print the vsock-proxy routes of -setup (PORT HOST HOSTPORT) and exit")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	var st *setup.Setup
	if *setupFile != "" {
		raw, err := setup.File{Path: *setupFile}.Read(context.Background())
		if err == nil {
			st, err = setup.Load(raw, "nitro")
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "hostagent:", err)
			os.Exit(1)
		}
	}
	if *routes {
		if st == nil {
			fmt.Fprintln(os.Stderr, "hostagent: -proxy-routes needs -setup")
			os.Exit(2)
		}
		lines, err := setup.NitroProxyLines(st)
		if err != nil {
			fmt.Fprintln(os.Stderr, "hostagent:", err)
			os.Exit(1)
		}
		fmt.Print(lines)
		return
	}

	store, err := filestore.New(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *exitFile == "" {
		*exitFile = filepath.Join(*dir, "last-exit.txt")
	}
	srv := &hostagent.Server{Store: store, Log: log, Exit: hostagent.ExitFile(*exitFile, log)}
	if st != nil {
		srv.Setup = func() ([]byte, error) { return st.Raw, nil }
		log.Info("setup", "file", *setupFile, "setup_sha256", st.HashHex(), "signer", st.SignerID())
	} else {
		log.Warn("no -setup: an enclave image that reads its setup from this agent refuses to start")
	}
	switch *creds {
	case "imds":
		srv.Creds = hostagent.IMDSCredentials
	case "none":
	default:
		fmt.Fprintln(os.Stderr, "unknown -creds", *creds)
		os.Exit(2)
	}
	a, err := transport.Parse(*listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if a.Network == "vsock" && !transport.HasVsock() {
		fmt.Fprintln(os.Stderr, "hostagent: this binary has no vsock: build it with -tags platform_aws (scripts/build-runner.sh does)")
		os.Exit(2)
	}
	l, err := transport.Listen(a)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Info("hostagent listening", "addr", a.String(), "dir", *dir, "creds", *creds)
	if err := srv.Serve(ctx, l); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
