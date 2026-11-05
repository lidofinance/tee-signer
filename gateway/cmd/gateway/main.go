// Command gateway serves the Web3Signer eth2 signing API and signs through
// the TEE signers: each request goes to every signer over mutual TLS, and
// the gateway combines a threshold of their partial signatures.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lidofinance/tee-signer/gateway/internal/backend"
	"github.com/lidofinance/tee-signer/gateway/internal/certreload"
	"github.com/lidofinance/tee-signer/gateway/internal/config"
	"github.com/lidofinance/tee-signer/gateway/internal/metrics"
	"github.com/lidofinance/tee-signer/gateway/internal/policy"
	"github.com/lidofinance/tee-signer/gateway/internal/server"
	"github.com/lidofinance/tee-signer/gateway/internal/servertls"
	"github.com/lidofinance/tee-signer/web3signer-api/eth2"
	"github.com/lidofinance/tee-signer/web3signer-api/signing"
)

func main() {
	cfgPath := flag.String("config", "gateway.yml", "path to the YAML config")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(*cfgPath, log); err != nil {
		log.Error("gateway stopped", "err", err.Error())
		os.Exit(1)
	}
}

func run(cfgPath string, log *slog.Logger) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	genesisFork, err := cfg.GenesisForkVersion()
	if err != nil {
		return err
	}
	hasher, err := eth2.NewHasher(cfg.Chain.Preset)
	if err != nil {
		return err
	}
	gvr, sched, err := cfg.Schedule()
	if err != nil {
		return err
	}
	pin := &signing.Pin{GenesisValidatorsRoot: gvr}
	for _, f := range sched {
		pin.Forks = append(pin.Forks, signing.ForkEpoch{Epoch: f.Epoch, Version: f.Version})
	}
	chain := signing.Chain{Hasher: hasher, SlotsPerEpoch: hasher.SlotsPerEpoch(), GenesisForkVersion: genesisFork, Pin: pin,
		GloasForkEpoch: cfg.GloasEpoch()}
	if cfg.Chain.SlotsPerEpoch != 0 {
		chain.SlotsPerEpoch = cfg.Chain.SlotsPerEpoch
	}
	log.Info("chain", "preset", hasher.Preset(), "slots_per_epoch", chain.SlotsPerEpoch, "genesis_fork_version", cfg.Chain.GenesisForkVersion,
		"genesis_validators_root", cfg.Chain.GenesisValidatorsRoot, "forks", len(pin.Forks)-1,
		"last_fork_version", fmt.Sprintf("%#x", pin.Forks[len(pin.Forks)-1].Version))
	pol, err := policy.New(cfg.Policy.FeeRecipientAllowlist)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The listener's TLS files are read before the signers are reached, so
	// a bad file stops the start at once.
	var serverTLS *servertls.Server
	if cfg.TLSOn() {
		if serverTLS, err = servertls.New(cfg.ServerTLS(), log); err != nil {
			return err
		}
		leaf := serverTLS.Leaf()
		log.Info("server TLS", "cert", cfg.TLS.Cert, "serial", leaf.SerialNumber.String(),
			"not_after", leaf.NotAfter.UTC().Format(time.RFC3339), "min_version", cfg.TLS.MinVersion,
			"client_ca", cfg.TLS.ClientCA, "client_fingerprints", len(cfg.TLS.ClientFingerprints),
			"reload_interval", cfg.TLS.ReloadInterval.String())
		go serverTLS.Run(ctx, cfg.TLS.ReloadInterval)
	}
	warnAccess(log, "access", cfg.Access, "listen", cfg.Listen, "can request signatures")
	if cfg.Metrics != "" {
		warnAccess(log, "metrics_access", cfg.MetricsAccess, "metrics", cfg.Metrics, "can read the metrics")
	}

	certs, err := certreload.New(cfg.Signers.ClientCert, cfg.Signers.ClientKey, log)
	if err != nil {
		return err
	}
	cur := certs.Current()
	log.Info("client certificate", "cert", cfg.Signers.ClientCert, "serial", cur.Serial(),
		"not_after", cur.NotAfter().UTC().Format(time.RFC3339), "reload_interval", cfg.Signers.CertReloadInterval.String())
	go certs.Run(ctx, cfg.Signers.CertReloadInterval)
	m := metrics.New()
	m.Certs(certs)
	if serverTLS != nil {
		m.ServerCert(serverTLS)
	}

	bcfg := backend.Config{
		Connections: cfg.Signers.Connections, Timeout: cfg.Signers.Timeout, DialTimeout: cfg.Signers.DialTimeout,
		MaxShareIndex: cfg.Signers.MaxShareIndex, Certs: certs, Metrics: m,
	}
	for i, n := range cfg.Signers.Nodes {
		bcfg.Signers = append(bcfg.Signers, backend.SignerConfig{Name: n.Name, Connection: cfg.Connection(i)})
		log.Info("signer", "signer", n.Name, "address", n.Address, "verifier", n.Attestation.Verifier, "mainnet", n.Attestation.Mainnet)
	}
	signers, err := backend.New(bcfg, log)
	if err != nil {
		return err
	}
	defer signers.Close()
	errCh := make(chan error, 2)
	if cfg.Metrics != "" {
		// Its own listener, so the signing API and the metrics can sit on
		// different interfaces. It starts before the first key load, so a
		// start that waits for the signers shows in the metrics.
		ln, err := net.Listen("tcp", cfg.Metrics)
		if err != nil {
			return fmt.Errorf("metrics: %w", err)
		}
		mux := http.NewServeMux()
		mux.Handle("GET /metrics", m.Registry)
		msrv := httpServer(ctx, cfg.MetricsAccess, serverTLS, mux, cfg.Signers.Timeout, log)
		go func() { errCh <- fmt.Errorf("metrics: %w", serve(msrv, ln)) }()
		defer msrv.Close()
		log.Info("metrics", "addr", cfg.Metrics, "path", "/metrics", "access", cfg.MetricsAccess)
	}
	// The signers may still be starting; retry the first key load for a minute.
	for attempt := 1; ; attempt++ {
		n, err := signers.Refresh(ctx)
		if err == nil {
			log.Info("keys loaded", "count", n)
			break
		}
		if attempt == 30 || ctx.Err() != nil {
			return err
		}
		log.Warn("key load failed, retrying", "attempt", attempt, "err", err.Error())
		time.Sleep(2 * time.Second)
	}

	handler := server.New(signers, pol, chain, log, cfg.Signers.Timeout).WithMetrics(m)
	if *cfg.Coalesce.Enabled {
		handler = handler.WithCoalescing(cfg.CoalesceKeep())
	}
	log.Info("coalesce", "enabled", *cfg.Coalesce.Enabled, "cache_slots", *cfg.Coalesce.CacheSlots,
		"seconds_per_slot", cfg.Chain.SecondsPerSlot)
	srv := httpServer(ctx, cfg.Access, serverTLS, handler.Handler(), cfg.Signers.Timeout, log)
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	go func() { errCh <- serve(srv, ln) }()
	log.Info("listening", "addr", cfg.Listen, "access", cfg.Access)

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	return nil
}

// httpServer is the HTTP server of one listener: TLS from st for access
// mtls and unsafe_open_tls, with the client check for mtls only, and
// plain HTTP for local and unsafe_plain_http. Failed handshakes (a client
// without an accepted certificate) go to the log as warnings. An mtls
// listener retires its connections when the client CA changes, until ctx
// ends.
//
// The write timeout covers the slowest request: its read, a key list load
// for a key the list lacks, then the signing, each up to signTimeout
// (signers.timeout).
func httpServer(ctx context.Context, access string, st *servertls.Server, h http.Handler, signTimeout time.Duration,
	log *slog.Logger) *http.Server {
	srv := &http.Server{Handler: h, ReadHeaderTimeout: readHeaderTimeout, ReadTimeout: readTimeout,
		WriteTimeout: readTimeout + 2*signTimeout, IdleTimeout: idleTimeout, MaxHeaderBytes: maxHeaderBytes,
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn)}
	if config.UsesTLS(access) {
		srv.TLSConfig = st.Config(access == config.AccessMTLS)
	}
	if access == config.AccessMTLS {
		go func(changed <-chan struct{}) {
			var t *time.Timer
			for {
				select {
				case <-ctx.Done():
					return
				case <-changed:
					if t != nil {
						t.Stop()
					}
					t = retire(srv, retireWindow)
					log.Info("client CA changed: open connections close after their current request")
				}
			}
		}(st.ClientsChanged())
	}

	return srv
}

// retire turns keep-alives off for window: idle connections close, and
// each active one closes after its current response (Connection: close).
// New connections are served throughout, with the client check in force.
// The window outlasts a sign request (signers.timeout).
func retire(srv *http.Server, window time.Duration) *time.Timer {
	srv.SetKeepAlivesEnabled(false)

	return time.AfterFunc(window, func() { srv.SetKeepAlivesEnabled(true) })
}

// The timeouts and header limit of both listeners, and how long keep-alives
// stay off after a client CA change. A sign request is a few KiB of
// headers and body, so 30 s to read it and 64 KiB of headers leave a wide
// margin.
const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	idleTimeout       = 120 * time.Second
	maxHeaderBytes    = 64 << 10
	retireWindow      = 30 * time.Second
)

// serve serves srv on ln, over TLS when srv has a TLS config.
func serve(srv *http.Server, ln net.Listener) error {
	if srv.TLSConfig != nil {
		return srv.ServeTLS(ln, "", "")
	}

	return srv.Serve(ln)
}

// warnAccess logs a warning at start for the unsafe access values of a
// listener.
func warnAccess(log *slog.Logger, field, access, addrField, addr, what string) {
	switch access {
	case config.AccessUnsafeOpenTLS:
		log.Warn(field+": unsafe_open_tls, no client certificate is checked: any client that reaches "+addrField+" "+what,
			addrField, addr)
	case config.AccessUnsafePlainHTTP:
		log.Warn(field+": unsafe_plain_http, plain HTTP without authentication: any host that reaches "+addrField+" "+what,
			addrField, addr)
	}
}
