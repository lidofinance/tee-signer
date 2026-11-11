// Command runner is the enclave side of the pluggable signer backend. It
// links the C signer core, holds the shares, and serves the wire protocol
// (signer-protocol/wire) on TCP, unix sockets or vsock. TCP and vsock listeners
// serve mutual TLS (-tls-client-ca).
//
//	runner -platform dev -config chain.json -state-dir ./state -listen tcp:127.0.0.1:7100
//	runner -platform azure -setup platform -state-dir /var/lib/signer -listen tcp:127.0.0.1:7100 ...
//
// See README.md for the flags that matter: the restart rule, the clock,
// the mark log, TLS and the platform options. With -setup the operator's
// values come from the signer's setup instead of flags (start.go).
//
// The platforms are build-time plugins, one runner binary per cloud
// (platforms.go): a binary holds the platforms of the tags it was built
// with, and refuses to start with none.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/setup"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-protocol/sealedimport"
	"github.com/lidofinance/tee-signer/signer-protocol/transport"
	"github.com/lidofinance/tee-signer/slashing-log"
	"github.com/lidofinance/tee-signer/tee-signer/attls"
	"github.com/lidofinance/tee-signer/tee-signer/server"
	"github.com/lidofinance/tee-signer/tee-signer/state"
)

type kvFlag map[string]string

func (k kvFlag) String() string { return fmt.Sprint(map[string]string(k)) }
func (k kvFlag) Set(s string) error {
	key, val, ok := strings.Cut(s, "=")
	if !ok {
		return fmt.Errorf("want key=value, got %q", s)
	}
	k[key] = val
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "runner:", err)
		os.Exit(1)
	}
}

// checkFlags enforces the rules that keep a cloud image safe, before the
// platform starts: no plaintext import outside dev (debug builds only have
// it, see debugimport.go), mutual TLS on every network listener of the
// cloud platforms (tcp on gcp and azure, vsock and tcp on nitro), no plain
// vsock in release builds, and an explicit mark log choice.
//
// On Nitro the parent instance forwards traffic into the enclave over vsock
// and is not trusted, so a vsock listener is a network listener like a TCP
// one. A unix socket has no TLS, so its client is a local admin
// (server/roles.go): a release build refuses one on every platform but
// dev. Debug builds, which no cloud image is, keep it for the e2e tests
// with fake hardware (unixOffDevAllowed).
//
// haveCA: the client CA comes from -tls-client-ca or from the setup.
func checkFlags(platformName string, listens []transport.Addr, haveCA bool, markSpec string) error {
	cloud := platformName != "dev"
	if err := checkPlainImport(platformName); err != nil {
		return err
	}
	for _, a := range listens {
		if cloud && a.Network == "unix" && !unixOffDevAllowed() {
			return fmt.Errorf("platform %s: unix listener %v refused; a client without TLS has the admin role, so off the dev platform every listener is tcp or vsock with mutual TLS", platformName, a)
		}
	}
	if !haveCA {
		for _, a := range listens {
			switch {
			case (platformName == "gcp" || platformName == "azure") && a.Network == "tcp":
				return fmt.Errorf("platform %s listens on the network (%v): set -tls-client-ca for mutual TLS", platformName, a)
			case platformName == "nitro" && (a.Network == "tcp" || a.Network == "vsock"):
				return fmt.Errorf("platform nitro listens on the network (%v): set -tls-client-ca for mutual TLS inside the enclave, the parent instance that forwards the traffic is not trusted", a)
			case a.Network == "vsock" && !plainVsockAllowed(platformName):
				return fmt.Errorf("vsock listener %v without -tls-client-ca: this build serves vsock with mutual TLS only, the host side of vsock is not trusted", a)
			}
		}
	}
	// The mark log is the clone protection: a second instance's write
	// conflicts. Off dev the choice is explicit; the setup path always has
	// the setup's store.
	if cloud && markSpec == "" {
		return fmt.Errorf("platform %s: set -mark-store (the locked mark log, or none to run without clone protection)", platformName)
	}
	return nil
}

// checkClock is the clock rule of checkFlags. It runs once the platform is
// built, because only then is the clock known. Off the dev platform the
// clock must be one the host cannot move (the NTS clock of -nts-clock in
// the images): the restart floor, the import floor, the certificate dates
// and the mark log age check all read it. A cloud platform on the system
// clock is refused. Debug builds, which no cloud image is, keep it for the
// e2e tests with fake hardware (untrustedClockAllowed).
func checkClock(platformName string, c platform.Clock) error {
	if platformName == "dev" || c.Trusted() || untrustedClockAllowed() {
		return nil
	}
	return fmt.Errorf("platform %s: clock %s is not trusted (the host can set it); run the NTS clock (-nts-clock)", platformName, c.Source())
}

func run() (err error) {
	if len(platforms) == 0 {
		return errNoPlatform
	}
	params := kvFlag{}
	var (
		listen        = flag.String("listen", "tcp:127.0.0.1:7100", "comma-separated addresses: tcp:HOST:PORT, unix:PATH, vsock:CID|any:PORT (vsock in the AWS build only)")
		platformName  = flag.String("platform", defaultPlatform(), "platform of this build: "+strings.Join(builtPlatforms(), ", "))
		setupSrc      = flag.String("setup", "", "where the signer's setup comes from: platform (the platform's channel: the host agent on nitro, SIGNER_SETUP on azure and dev, the metadata attribute signer-setup on gcp) or file:PATH (dev); empty: the values come from flags (-config, -tls-client-ca, -platform-opt, ...), on dev or in a debug build only")
		configPath    = flag.String("config", "", "chain and policy config (JSON, see core.Config); not with -setup")
		stateDir      = flag.String("state-dir", "state", "directory for sealed shares and watermarks (dev, or a host volume)")
		floor         = flag.Bool("restart-floor", true, restartFloorUsage)
		floorMargin   = flag.Int64("floor-margin", -1, "epochs added to the clock epoch for the floor, at least max_epochs_ahead + 1; -1 = max_epochs_ahead + 1")
		persist       = flag.Bool("persist-watermarks", false, "persist commit-ahead watermarks (safe only on rollback-proof storage)")
		clockCheck    = flag.Bool("clock-check", false, "print clock readings and exit")
		maxValidators = flag.Uint("max-validators", 1024, "capacity of the signer")
		sealedImport  = flag.Bool("sealed-import", true, "accept IMPORT_SHARE_SEALED (shares encrypted to this boot's attested key)")
		tlsCA         = flag.String("tls-client-ca", "", "PEM file of the CA certificate(s) that issue client certificates; enables mutual TLS on tcp and vsock listeners")
		markSpec      = flag.String("mark-store", "", "mark log (one device mark in a locked append-only log): none, file:DIR (tests), s3:bucket=B,region=R[,endpoint=URL] (AWS build), gcs:bucket=B[,endpoint=URL] (GCP build), azblob:account=A,container=C[,endpoint=URL][,subscription=S,resource_group=G] (Azure build; the lock check needs the last two); required off the dev platform")
		markSigner    = flag.String("mark-signer", "", "this signer's log ID in the mark store")
		markCreate    = flag.Bool("mark-create", false, "start a mark log that has no valid record even if shares are stored or objects lie under record names (after losing the log, or a key release that no longer opens it)")
		markRaiseSlot = flag.Int("mark-raise-slot", -1, "slot of each epoch at which the mark is raised for the next epoch; -1 = three quarters into the epoch (24 of 32)")
		stateSpec     = flag.String("state-store", "", "durable copy of the sealed state (shares, wrapped sealing key) in an object store, same syntax as -mark-store; restored at start on azure, gcp and dev (docs/durable-state.md)")
		stateCreate   = flag.Bool("state-create", false, "start a state copy of which no commit opens under this key release with every object it needs (after a new key, with the shares imported again)")
		stateRefresh  = flag.Duration("state-refresh", 24*time.Hour, "write the whole state into the state copy again when the oldest object its newest commit needs is this old, so a locked store's retention never ends on one; with a setup, at most half of slashing_log_min_lock_days less two hours; 0 = never without a setup")
		logJSON       = flag.Bool("log-json", false, "JSON logs")
		maxConns      = flag.Int("max-conns", server.DefaultMaxConns, "connections open at once over every listener, TLS handshakes included; more are closed at once")
		maxHandshakes = flag.Int("max-handshakes", 0, "TLS handshakes at once; more are closed at once; 0 = the -max-conns value")
		maxInflight   = flag.Int("max-inflight-mib", server.DefaultMaxInflight>>20, "MiB that frames may hold together past their first 64 KiB each; a frame that would go over closes its connection")
		idleTimeout   = flag.Duration("idle-timeout", server.DefaultIdleTimeout, "close a connection that sends no frame for this long after its last answer; 0 = never (clients that do not redial a closed connection fail a request on it)")
	)
	flag.Var(params, "platform-opt", "platform option key=value (repeatable)")
	flag.Parse()
	if err := checkRestartFloor(*floor); err != nil {
		return err
	}

	var log *slog.Logger
	if *logJSON {
		log = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	} else {
		log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}

	var addrs []transport.Addr
	for _, a := range strings.Split(*listen, ",") {
		addr, err := transport.Parse(strings.TrimSpace(a))
		if err != nil {
			return err
		}
		addrs = append(addrs, addr)
	}
	newPlatform, err := lookupPlatform(*platformName)
	if err != nil {
		return err
	}
	signerID := *markSigner

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// The setup (or the flags), then the platform: start.go.
	given := map[string]string{}
	flag.Visit(func(f *flag.Flag) { given[f.Name] = f.Value.String() })
	boot, plat, copyStore, err := startPlatform(ctx, &startArgs{
		platformName: *platformName, setupSrc: *setupSrc, given: given, params: params,
		listens: addrs, stateDir: *stateDir, clockCheck: *clockCheck,
		tlsCA: *tlsCA, markSpec: *markSpec, stateSpec: *stateSpec, signerID: signerID,
		stateCreate: *stateCreate, maxValidators: uint32(*maxValidators),
	}, newPlatform, log)
	if err != nil {
		return err
	}
	signerID = boot.signerID
	if plat.Close != nil {
		defer plat.Close()
	}
	if plat.ReportExit != nil {
		defer func() { reportExit(plat.ReportExit, recover(), err) }()
	}
	if copyStore != nil && copyStore.store == nil {
		return fmt.Errorf("platform %s keeps its state elsewhere and takes no -state-store (on Nitro the store is on the parent and survives a restart)", *platformName)
	}
	// The key rule the platform read before its key release, and the
	// mainnet rule once more, before anything sealed is opened.
	rule, err := keyRule(boot.setup != nil, boot.prod, boot.noLockAccepted, plat, log)
	if err != nil {
		return err
	}

	// Platform hooks of the build (hooks.go): none in this tree.
	for _, h := range platformHooks {
		if err := h(ctx, &platformHookArgs{plat: plat, setup: boot.setup, stateCopy: copyStore != nil, clockCheck: *clockCheck, log: log}); err != nil {
			return err
		}
	}

	if *maxHandshakes == 0 {
		*maxHandshakes = *maxConns // the budget follows the cap the operator set, not the constant
	}
	if *maxConns <= 0 || *maxHandshakes <= 0 || *maxInflight <= 0 || *idleTimeout < 0 {
		return errors.New("-max-conns, -max-handshakes and -max-inflight-mib must be positive, -idle-timeout zero or positive")
	}
	if !*clockCheck {
		if err := checkClock(*platformName, plat.Clock); err != nil {
			return err
		}
	}
	if *clockCheck {
		t, err := plat.Clock.Now()
		if err != nil {
			return err
		}
		fmt.Printf("clock_source=%s trusted=%v clock=%s system=%s skew=%v\n", plat.Clock.Source(), plat.Clock.Trusted(),
			t.UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339), time.Since(t).Round(time.Second))
		return nil
	}

	// The chain config: from the setup, or the flag path's -config. The
	// config hash in the log is setup_hash on the setup path, which covers
	// the chain config and everything else in the setup, and the hash of
	// the -config file on the flag path (flagState).
	cfg, cfgHash := boot.cfg, [32]byte{}
	if boot.setup != nil {
		cfgHash = boot.setup.SHA256
	} else {
		if *configPath == "" {
			return errors.New("-config is required (or -setup)")
		}
		var raw []byte
		if cfg, raw, err = core.LoadConfig(*configPath); err != nil {
			return err
		}
		cfgHash = sha256.Sum256(raw)
	}
	margin := state.DefaultFloorMargin(cfg)
	if *floorMargin >= 0 {
		margin = uint64(*floorMargin)
	}
	markOn := boot.markSpec != "" && boot.markSpec != "none"
	cfg.DeviceMark = markOn
	mode := state.Mode{Floor: *floor, Persist: *persist, FloorMargin: margin, MarkLog: markOn}
	hooks, err := state.New(cfg, mode, plat.Clock, plat.Store, plat.Sealer, log)
	if err != nil {
		return err
	}

	// claimed: the mark log's log_id and the shares listed before its claim
	// (the setup path loads only those).
	var claimed markClaim
	if markOn {
		// Mark log: claim it before any share loads. The state copy, if
		// any, was restored in the platform.
		if claimed, err = setupMarkLog(ctx, plat, hooks, *platformName, boot.markSpec, signerID, *markCreate, boot.setup, log); err != nil {
			return err
		}
	} else if *platformName != "dev" {
		log.Warn("no mark log (-mark-store none): two instances of this image can sign conflicting messages")
	}

	// Config updates (setupstate.go): the core starts with the config in
	// force by the log's state and the clock, not the setup's first values.
	var updates *server.Updates
	if boot.setup != nil && claimed.log != nil {
		if updates, err = newConfigUpdates(boot.setup, claimed.log, plat.Clock, *platformName, log); err != nil {
			return err
		}
		if cfg, err = updates.StartConfig(cfg); err != nil {
			return fmt.Errorf("config in force: %w", err)
		}
	}

	signer, err := core.NewSigner(cfg, boot.maxValidators, 64, hooks)
	if err != nil {
		return err
	}
	defer signer.Close()
	// The restart floor counts epochs on the signer's clock, which follows
	// the slot time changes in force.
	hooks.UseClock(signer.EpochAt)

	srv := &server.Server{Signer: signer, Hooks: hooks, Platform: plat, State: flagState(cfgHash), Log: log,
		Limits: server.Limits{MaxConns: *maxConns, MaxHandshakes: *maxHandshakes, MaxInflight: int64(*maxInflight) << 20, IdleTimeout: *idleTimeout}}
	// A request that panicked and left a lock held: every later request
	// would hang on it. Exit, so the supervisor starts the runner again
	// from its stored state.
	srv.OnWedged = func(err error) {
		if plat.ReportExit != nil {
			plat.ReportExit("runner: " + err.Error())
		}
		fmt.Fprintln(os.Stderr, "runner:", err)
		os.Exit(1)
	}
	if boot.setup != nil {
		// Shares are sealed under setup_hash and the log's log_id. IDENTITY,
		// ATTEST and HEALTH carry setup_hash and the config state in force.
		srv.SetupHash, srv.LogID = boot.setup.SHA256, claimed.logID
		if updates != nil {
			updates.Attach(signer)
			srv.Updates, srv.State = updates, updates.SetupState
			go updates.Run(ctx, configSyncEvery)
			go claimed.log.RefreshLoop(ctx, markRefreshEvery)
		}
		srv.KeyReleaseHash, srv.KeyLock, srv.KeyLockWhy = rule.Hash, rule.Lock, rule.Why
		// The revoked client certificates in force (server/revoked.go).
		srv.Revoked = &attls.Revoked{}
		srv.Revoked.Set(boot.setup.Wire.Open.RevokedClientCerts)
		srv.RefreshRevokedClientCerts()
	}
	applyPlainImport(srv)
	if *sealedImport {
		if srv.ImportKey, err = sealedimport.Generate(); err != nil {
			return err
		}
	}
	// One TLS configuration, and so one key made at this start, for every
	// tcp and vsock listener. The client certificate's validity dates are
	// checked against the platform's clock, which on the cloud images is the
	// NTS clock (-nts-clock), not the host-set system clock.
	caPEM := boot.caPEM
	if boot.setup == nil && *tlsCA != "" {
		if caPEM, err = os.ReadFile(*tlsCA); err != nil {
			return err
		}
	}
	var tlsCfg *tls.Config
	if caPEM != nil {
		if tlsCfg, srv.TLSKeyHash, err = attls.ServerConfig(caPEM, plat.Clock.Now, chainMark(cfg), attls.WithRevoked(srv.Revoked)); err != nil {
			return err
		}
		srv.ClientCAs = tlsCfg.ClientCAs
	}
	// A sealing key from a stored blob seals nothing until every stored
	// share opens under it (AWS-KMS-02, server.ProveSealingKey).
	srv.SealingKeyUnproven = plat.SealingKeyStored
	var n int
	imageState := "not_applicable"
	if boot.setup != nil {
		// The image check and the image rule of the key rule lock, before
		// any share is unsealed (imagecheck.go, keyruleimages.go). Either
		// leaves the shares sealed on refusal; the runner stays up.
		var load bool
		if srv.Image, load, err = startImageCheck(ctx, plat, boot.prod, rule, updates, log); err != nil {
			return err
		}
		h, _ := srv.Image.Status(updates)
		imageState = h.State
		if load {
			if srv.SealingKeyUnproven {
				if err := srv.ProveSealingKey(claimed.shares); err != nil {
					return err
				}
			}
			n, err = srv.LoadListedShares(claimed.shares)
		}
	} else if srv.SealingKeyUnproven {
		var keys []string
		if keys, err = server.ListShares(plat.Store); err != nil {
			return err
		}
		if err = srv.ProveSealingKey(keys); err != nil {
			return err
		}
		n, err = srv.LoadListedShares(keys)
	} else {
		n, err = srv.LoadShares()
	}
	if err != nil {
		log.Error("some stored shares did not load", "err", err)
	}
	if markOn {
		go raiseMarks(ctx, signer, plat.Clock, *markRaiseSlot, log)
	}
	if copyStore != nil {
		var lockDays uint32
		if boot.setup != nil {
			lockDays = boot.setup.Wire.SlashingLogMinLockDays
		}
		if age := refreshAge(*stateRefresh, lockDays); age > 0 {
			go copyStore.refresh(ctx, age, srv.SetStateCopyFailed)
		}
	}
	log.Info("runner started", "platform", plat.Name, "version", server.Version, "config_sha256", fmt.Sprintf("%x", cfgHash),
		"setup", boot.setup != nil,
		"restart_mode", mode.String(), "floor_margin", margin,
		"clock", plat.Clock.Source(), "clock_trusted", plat.Clock.Trusted(),
		"record", hooks.MarkLogStatus(), "state_copy", copyStore.status(), "shares_loaded", n, "plaintext_import", plainImportStatus(), "sealed_import", *sealedImport,
		"tls_key_sha256", fmt.Sprintf("%x", srv.TLSKeyHash), "revoked_client_certs", srv.Revoked.Len(), "image_check", imageState,
		"max_conns", *maxConns, "max_handshakes", *maxHandshakes, "max_inflight_mib", *maxInflight, "idle_timeout", idleTimeout.String())
	if !plat.Clock.Trusted() && mode.Floor && !mode.Persist {
		log.Warn("restart floor relies on a clock the host controls; a host that moves it can get double votes signed")
	}

	var listeners []net.Listener
	for _, addr := range addrs {
		l, tlsOn, err := attls.Listen(addr, tlsCfg, transport.Listen)
		if err != nil {
			return fmt.Errorf("listen %v: %w", addr, err)
		}
		if tlsOn {
			log.Info("listening", "addr", addr.String(), "tls", "mutual, TLS 1.3")
		} else {
			log.Info("listening", "addr", addr.String())
		}
		listeners = append(listeners, l)
	}
	errc := make(chan error, len(listeners))
	for _, l := range listeners {
		go func(l net.Listener) { errc <- srv.Serve(ctx, l) }(l)
	}
	var errs []error
	for range listeners {
		if err := <-errc; err != nil {
			errs = append(errs, err)
			stop()
		}
	}
	log.Info("runner stopped")
	return errors.Join(errs...)
}

// reportExit hands the line main prints for err to the platform's host,
// on a platform whose console nobody sees. A panic of the main goroutine is
// sent as its runtime error text only (another panic value could hold
// anything), then goes on.
func reportExit(report func(string), panicked any, err error) {
	if panicked != nil {
		msg := "runner: panic"
		if re, ok := panicked.(runtime.Error); ok {
			msg += ": " + re.Error()
		}
		report(msg)
		panic(panicked)
	}
	if err != nil {
		report("runner: " + err.Error())
	}
}

// setupMarkLog opens the mark store, claims the log and hands the newest
// mark to the hooks. The records' keys come from the platform's key release
// (platform.Keys), not from the state directory, so a runner that lost its
// state reads its log again.
// Any error stops the start: a runner that cannot read its log does not
// sign (a start on the clock floor alone would let a clone with no store
// sign too).
//
// With a setup (st) the log is the setup's (markstore.SetupOf: names and
// records carry setup_hash, record times come from the platform's clock),
// and outside dev the store's lock is checked first against the setup's
// slashing_log_min_lock_days, and again by the claim once it has read the
// log (markstore.Options.LockDays). The shares are listed once, before the claim; the
// setup path loads only that list.
func setupMarkLog(ctx context.Context, plat *platform.Platform, hooks *state.Hooks, platformName, spec, signerID string,
	create bool, st *setup.Setup, log *slog.Logger) (markClaim, error) {
	if signerID == "" {
		return markClaim{}, errors.New("-mark-store needs -mark-signer")
	}
	env := markLogEnv(plat, platformName, st)
	if plat.Keys == nil {
		return markClaim{}, fmt.Errorf("platform %s has no key release for the mark log", platformName)
	}
	l, err := markstore.Open(spec, env)
	if err != nil {
		return markClaim{}, err
	}
	opts := markstore.Options{AllowCreate: create, HintStore: plat.Store, HintSealer: plat.Sealer, Log: log}
	if st != nil {
		if opts.Setup, err = markstore.SetupOf(st.Wire, st.SHA256); err != nil {
			return markClaim{}, err
		}
		opts.Clock = plat.Clock.Now
		if platformName != "dev" {
			lctx, lcancel := context.WithTimeout(ctx, 60*time.Second)
			err := markstore.CheckLock(lctx, l, st.Wire.SlashingLogMinLockDays)
			lcancel()
			if err != nil {
				return markClaim{}, err
			}
			opts.LockDays = st.Wire.SlashingLogMinLockDays
		}
		if err := checkStoreProject(ctx, l, st.Wire.Platform.SealingKeyRelease.ProjectNumber, "mark log"); err != nil {
			return markClaim{}, err
		}
	}
	m, err := markstore.New(l, signerID, plat.Keys, opts)
	if err != nil {
		return markClaim{}, err
	}
	stored, err := server.ListShares(plat.Store)
	if err != nil {
		return markClaim{}, err
	}
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	mark, found, err := m.Claim(cctx, len(stored) > 0)
	if err != nil {
		return markClaim{}, err
	}
	hooks.UseMarkLog(m, mark, found)
	log.Info("mark log ready", "store", l.String(), "signer", signerID,
		"mark_key", fmt.Sprintf("%x", m.PublicKey()), "had_mark", found, "shares_stored", len(stored),
		"log_id", fmt.Sprintf("%x", m.LogID()))
	return markClaim{log: m, logID: m.LogID(), shares: stored}, nil
}

// markLogEnv is the env the mark log's store opens with: storeEnv with the
// setup's retention (retainDays).
func markLogEnv(plat *platform.Platform, platformName string, st *setup.Setup) markstore.Env {
	return storeEnv(plat, platformName, retainDays(platformName, st))
}

// storeEnv is the env of a store the runner opens by spec (the mark log,
// the state copy): the platform's HTTP client, credentials and tokens, and
// retain as RetainDays. Dev falls back to the AWS credentials of the
// environment.
func storeEnv(plat *platform.Platform, platformName string, retain uint32) markstore.Env {
	env := markstore.Env{HTTP: plat.HTTPClient, AWSCreds: plat.RecordCredentials, RetainDays: retain}
	if plat.StorageToken != nil {
		c := markstore.NewTokenCache(plat.StorageToken, markstore.TokenRefreshAfter, markstore.TokenMaxAge)
		env.Token, env.TokenRefused = c.Token, c.Invalidate
	}
	if plat.ManagementToken != nil {
		c := markstore.NewTokenCache(plat.ManagementToken, markstore.TokenRefreshAfter, markstore.TokenMaxAge)
		env.ARMToken, env.ARMTokenRefused = c.Token, c.Invalidate
	}
	if platformName == "dev" && env.AWSCreds == nil {
		env.AWSCreds = envCredentials()
	}
	return env
}

// retainDays is the retention each object the runner writes to the mark
// log's store must carry by itself (markstore.Env.RetainDays): the setup's
// slashing_log_min_lock_days wherever the store's lock is checked (a setup,
// not the dev platform), else 0. On S3 the bucket's default retention can be
// lowered after the check; an object's own compliance retention cannot.
func retainDays(platformName string, st *setup.Setup) uint32 {
	if st == nil || platformName == "dev" {
		return 0
	}
	return st.Wire.SlashingLogMinLockDays
}

// markClaim is what the mark log's claim leaves for the server: the log
// (its config state goes into IDENTITY), its log_id and the shares listed
// before the claim.
type markClaim struct {
	log    *markstore.MarkLog
	logID  [32]byte
	shares []string
}

// raiseMarks raises the device mark for epoch E+1 at slot raiseSlot of
// epoch E, so the log write happens with most of an epoch to spare instead
// of at the first vote of E+1. If the store is down the core keeps signing
// inside the committed mark and refuses what lies above it.
//
// The slot and epoch come from the signer's clock, which follows the slot
// time changes in force; the check runs every second, at least four times a
// slot of any slot time from 4 s up.
func raiseMarks(ctx context.Context, s *core.Signer, clk platform.Clock, raiseSlot int, log *slog.Logger) {
	spe, genesis := s.Config().SlotsPerEpoch, s.Config().GenesisTime
	if raiseSlot < 0 || uint64(raiseSlot) >= spe {
		raiseSlot = int(spe * 3 / 4)
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var raised uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		now, err := clk.Now()
		if err != nil || uint64(now.Unix()) <= genesis {
			continue
		}
		slot := s.SlotAt(uint64(now.Unix()))
		epoch, inEpoch := slot/spe, slot%spe
		if inEpoch < uint64(raiseSlot) || raised > epoch {
			continue
		}
		if err := s.CoverEpoch(epoch + 1); err != nil {
			log.Warn("mark not raised for the next epoch; the first vote of that epoch will try again", "epoch", epoch+1, "err", err)
			continue
		}
		raised = epoch + 1
	}
}

// chainMark names the runner's chain in its TLS certificate by both
// genesis values (attls.WithChain).
func chainMark(cfg core.Config) attls.Option {
	return attls.WithChain(cfg.GenesisForkVersion, cfg.GenesisValidatorsRoot)
}
