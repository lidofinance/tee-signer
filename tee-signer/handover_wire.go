//go:build !debugimport

// Release build: the handover sides of the server (signer-protocol
// docs/protocol.md, "Handover"). A runner with a setup and the mark log
// hands its shares to the next image under an approvers' order and takes
// them as that image. A debug build has neither (handover_wire_debug.go).

package main

import (
	"fmt"
	"strings"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	"github.com/lidofinance/tee-signer/platform/setup"
	"github.com/lidofinance/tee-signer/tee-signer/server"
)

// enableHandover turns HANDOVER_ORDER, HANDOVER and IMPORT_HANDOVER on for a
// runner with a setup and the mark log. The verifier of the other image
// is this build's own platform verifier (attestation-verify/runnerclient,
// tag verifierselect); on a runner that reaches only its setup's hosts (a
// Nitro enclave), the hosts that verifier fetches key sets from must be
// among them (setup.AttestationEgress).
func enableHandover(srv *server.Server) error {
	if srv.Updates == nil {
		return nil
	}
	plat, u := srv.Platform, srv.Updates
	var opts []runnerclient.Option
	if plat.HTTPClient != nil {
		opts = append(opts, runnerclient.WithHTTPClient(plat.HTTPClient))
	}
	endpoints, limited := setup.AttestationEgress(u.SetupWire())
	// The source side goes first: it tells its own pending order in the
	// slot from an import.
	if err := srv.EnableHandoverSource(server.HandoverSourceOptions{VerifierOptions: opts, LimitedEgress: limited, PeerEndpoints: endpoints}); err != nil {
		return fmt.Errorf("handover source: %w", err)
	}
	if err := srv.EnableHandoverImport(server.HandoverImportOptions{VerifierOptions: opts, LimitedEgress: limited, PeerEndpoints: endpoints}); err != nil {
		return fmt.Errorf("handover import: %w", err)
	}
	srv.Log.Info("handover on: HANDOVER_ORDER and HANDOVER hand the shares to the target an approvers' order names, IMPORT_HANDOVER takes a source's shares",
		"limited_egress", limited, "peer_attestation_hosts", strings.Join(endpoints, ","))
	return nil
}
