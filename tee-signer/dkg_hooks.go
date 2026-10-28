//go:build (peer_azure || peer_aws || peer_gcp || peer_dev) && !debugimport

// Key generation is a build-time plugin (runner/keygen, docs/dkg.md): a
// runner built with peer_* tags has this file in place of nodebugimport.go,
// so a runner built without them is byte for byte the one without key
// generation. The peer_* tags pick the attestation verifiers it can check
// its DKG peers with (attest/runnerclient, tag peerselect); a policy that
// names another verifier stops the start, an order that does is refused.
//
// A runner with a setup takes no policy file: approver-signed DKG orders
// come over the wire (DKG_ORDER, runner/keygen/orders.go), each with the
// setup_hash, image, operator key and attestation settings of every
// participant. The flag path keeps -dkg-policy.

package main

import (
	"flag"
	"fmt"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"os"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	"github.com/lidofinance/tee-signer/platform/setup"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
	"github.com/lidofinance/tee-signer/tee-signer/keygen"
	"github.com/lidofinance/tee-signer/tee-signer/server"
)

var dkgPolicyPath = flag.String("dkg-policy", "", "key generation policy (JSON, docs/dkg.md); enables the DKG_* messages. Every runner of a cluster loads the same file. Without -setup only")

// A runner with a setup takes DKG orders, not a policy file. The flag
// exists in this build only, so its refusal is added here (start.go
// setupRefuses).
func init() {
	setupRefuses["dkg-policy"] = "a runner with a setup takes approver-signed DKG orders over the wire (DKG_ORDER), not a policy file (setup-phase.md, section 10)"
}

// The policy checked at start, before the platform comes up.
var (
	dkgPolicy     *keygen.Policy
	dkgPolicyHash [32]byte
)

// checkPlainImport is the release build's (no plaintext import), plus the
// policy check: the file parses, names only verifiers built in and suits
// this platform.
func checkPlainImport(platformName string) error {
	if *dkgPolicyPath == "" {
		return nil
	}
	raw, err := os.ReadFile(*dkgPolicyPath)
	if err != nil {
		return fmt.Errorf("-dkg-policy: %w", err)
	}
	dkgPolicy, dkgPolicyHash, err = keygen.ParsePolicy(raw, platformName)
	if err != nil {
		return fmt.Errorf("-dkg-policy %s: %w", *dkgPolicyPath, err)
	}
	return nil
}

// plainVsockAllowed is false in a release build: vsock is served with
// mutual TLS only, because the host side of vsock is not trusted.
func plainVsockAllowed(string) bool { return false }

// unixOffDevAllowed is false in a key generation build, as in a release
// build.
func unixOffDevAllowed() bool { return false }

// applyPlainImport loads the operator key and, with a policy, turns key
// generation on.
func applyPlainImport(srv *server.Server) {
	if err := checkDKGPolicy(srv.Platform.Name, srv.Signer.Config().GenesisForkVersion, dkgPolicy); err != nil {
		fmt.Fprintln(os.Stderr, "runner: -dkg-policy:", err)
		os.Exit(1)
	}
	if err := setupDKG(srv); err != nil {
		fmt.Fprintln(os.Stderr, "runner: key generation:", err)
		os.Exit(1)
	}
}

// checkDKGPolicy checks the threshold of a -dkg-policy file p (nil: none)
// on this runner. The policy file names no chain, so the rule takes the
// runner's platform and genesis fork version: no single-node GCP signer,
// and 2t - n >= 2 on mainnet (setupwire.CheckThresholdOn).
func checkDKGPolicy(platformName string, genesisForkVersion backend.Version, p *keygen.Policy) error {
	if p == nil {
		return nil
	}
	pl, err := setupwire.ParsePlatform(platformName)
	if err != nil {
		return err
	}
	return setupwire.CheckThresholdOn(pl, genesisForkVersion, p.Threshold, len(p.Participants))
}

func plainImportStatus() string { return "not built in" }

func setupDKG(srv *server.Server) error {
	plat := srv.Platform
	log := srv.Log
	ops, err := keygen.LoadOperatorKeys(plat.Sealer, plat.Store, plat.Attester)
	if err != nil {
		return err
	}
	srv.SetOperatorKeys(ops)
	log.Info("operator key", "ed25519", ops.PublicHex(), "peers_built_in", builtPeers())
	var opts []runnerclient.Option
	if plat.HTTPClient != nil {
		opts = append(opts, runnerclient.WithHTTPClient(plat.HTTPClient))
	}
	if srv.Updates != nil {
		return setupOrders(srv, ops, opts)
	}
	if dkgPolicy == nil {
		return nil
	}
	verifiers := make([]remote.VerifyFunc, len(dkgPolicy.Participants))
	for i := range dkgPolicy.Participants {
		if verifiers[i], err = dkgPolicy.Participants[i].Attestation.NewDKGHelloVerifier(opts...); err != nil {
			return fmt.Errorf("policy participant %d: %w", i+1, err)
		}
	}
	m, err := keygen.New(dkgPolicy, dkgPolicyHash, keygen.Env{
		Platform:    plat.Name,
		Sealer:      plat.Sealer,
		Store:       plat.Store,
		Attester:    plat.Attester,
		State:       srv.SetupState(),
		TLSKeyHash:  func() []byte { return srv.TLSKeyHash },
		OperatorKey: ops.Public(),
		Verifiers:   verifiers,
		Chain:       srv.Signer.Config(),
		AddShares:   srv.AddGeneratedShares,
		WithShare:   srv.WithShare,
		Sign:        srv.Signer.Sign,
		Keys:        srv.Signer.Keys,
		Now: func() time.Time {
			if t, err := plat.Clock.Now(); err == nil {
				return t
			}
			return time.Now()
		},
		Log: log,
	})
	if err != nil {
		return err
	}
	srv.SetDKG(m)
	log.Info("key generation on", "participants", len(dkgPolicy.Participants), "threshold", dkgPolicy.Threshold,
		"policy_sha256", fmt.Sprintf("%x", dkgPolicyHash))
	return nil
}

// setupOrders turns key generation under DKG orders on, for a runner with a
// setup. IDENTITY's order slot shows the order that waits longest.
func setupOrders(srv *server.Server, ops *keygen.OperatorKeys, opts []runnerclient.Option) error {
	plat, u := srv.Platform, srv.Updates
	// A Nitro enclave reaches only its setup's routes: an order with a peer
	// whose key set host is not among them is refused (keygen.Orders).
	endpoints, limited := setup.PeerEgress(u.SetupWire())
	o, err := keygen.NewOrders(keygen.OrdersEnv{
		Env: keygen.Env{
			Platform:    plat.Name,
			Sealer:      plat.Sealer,
			Store:       plat.Store,
			Attester:    plat.Attester,
			StateNow:    srv.SetupState,
			TLSKeyHash:  func() []byte { return srv.TLSKeyHash },
			OperatorKey: ops.Public(),
			ChainNow:    srv.ConfigInForce,
			AddShares:   srv.AddGeneratedShares,
			WithShare:   srv.WithShare,
			Sign:        srv.SignSetupMessage,
			Keys:        srv.Signer.Keys,
			Now: func() time.Time {
				if t, err := plat.Clock.Now(); err == nil {
					return t
				}
				return time.Now()
			},
			Log: srv.Log,
		},
		Setup:           u.SetupWire(),
		SetupHash:       srv.SetupHash,
		Locked:          u.LockedInForce,
		TrustedNow:      u.TrustedTime,
		VerifierOptions: opts,
		LimitedEgress:   limited,
		PeerEndpoints:   endpoints,
	})
	if err != nil {
		return err
	}
	// The slot shows a pending handover order (in the mark log's state)
	// before a DKG order that waits.
	setupState := srv.State
	srv.State = func() backend.SetupState {
		s := setupState()
		if slot := o.PendingSlot(); slot.Kind != 0 && s.Order.Kind == 0 {
			s.Order = slot
		}
		return s
	}
	srv.SetDKGOrders(o)
	srv.Log.Info("key generation under DKG orders on", "setup_sha256", fmt.Sprintf("%x", srv.SetupHash),
		"limited_egress", limited, "keygen_peer_attestation_hosts", strings.Join(endpoints, ","))
	// HANDOVER as a source checks the target's attestation, and
	// IMPORT_HANDOVER the source's origin proof, with the same verifiers and
	// egress rule as DKG peers (docs/protocol.md, "Handover"). The source
	// side goes first: it tells its own pending order in the slot from an
	// import.
	if err := srv.EnableHandoverSource(server.HandoverSourceOptions{VerifierOptions: opts, LimitedEgress: limited, PeerEndpoints: endpoints}); err != nil {
		return err
	}
	srv.Log.Info("handover source on: HANDOVER_ORDER and HANDOVER hand the shares to the target an approvers' order names")
	if err := srv.EnableHandoverImport(server.HandoverImportOptions{VerifierOptions: opts, LimitedEgress: limited, PeerEndpoints: endpoints}); err != nil {
		return err
	}
	srv.Log.Info("handover import on: IMPORT_HANDOVER takes the shares a HANDOVER source sealed to this runner")
	return nil
}

// builtPeers lists the peer verifiers of this build.
func builtPeers() string {
	var out []string
	for _, v := range []string{runnerclient.VerifierAzureMAA, runnerclient.VerifierAWSNitro, runnerclient.VerifierGCPCS, runnerclient.VerifierDev} {
		if runnerclient.Available(v) {
			out = append(out, v)
		}
	}
	return strings.Join(out, ",")
}
