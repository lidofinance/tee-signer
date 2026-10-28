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
		msrv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		go func() { errCh <- fmt.Errorf("metrics: %w", msrv.Serve(ln)) }()
		defer msrv.Close()
		log.Info("metrics", "addr", cfg.Metrics, "path", "/metrics")
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
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { errCh <- srv.ListenAndServe() }()
	log.Info("listening", "addr", cfg.Listen)

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
