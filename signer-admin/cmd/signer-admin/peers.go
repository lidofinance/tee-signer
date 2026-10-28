package main

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	"github.com/lidofinance/tee-signer/governance/dkgorder"
	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// Peer endpoints (research/setup-phase.md, "Found while building", the
// peer endpoints note): a Nitro enclave reaches only the routes of its
// setup, so the hosts that its DKG peer verifiers fetch key sets from (an
// Azure peer's MAA host, Google's Confidential Space hosts) must be in its
// setup's keygen_peer_attestation_hosts, or the runner refuses every order with that peer.
// The list is fixed for the signer's life, so setup warns from the cluster
// file and dkg-draft from the order's participants.

// limitedEgress is the runner's rule (setup.PeerEgress): a nitro signer
// reaches only its keygen_peer_attestation_hosts, a dev signer too when it lists any.
func limitedEgress(s *setupwire.Setup) bool {
	switch s.Platform.Platform {
	case setupwire.PlatformNitro:
		return true
	case setupwire.PlatformDev:
		return len(s.Platform.KeygenPeerAttestationHosts) > 0
	}
	return false
}

// peerHosts is a peer and the hosts its verifier fetches key sets from.
type peerHosts struct {
	name     string
	verifier string
	hosts    []string
}

// setupPeer is what a cluster file says of a peer: an Azure signer's
// tokens come from its key release's MAA host; a GCP signer's from
// Google's issuer, which dkg-draft names when cloud.json sets none.
func setupPeer(s *setupwire.Setup) peerHosts {
	var a runnerclient.Attestation
	switch s.Platform.Platform {
	case setupwire.PlatformAzure:
		a = runnerclient.Attestation{Verifier: runnerclient.VerifierAzureMAA, MAAHost: s.Platform.SealingKeyRelease.MAAEndpoint}
	case setupwire.PlatformGCP:
		a = runnerclient.Attestation{Verifier: runnerclient.VerifierGCPCS}
	default:
		return peerHosts{name: s.SignerName}
	}
	return peerHosts{name: s.SignerName, verifier: a.Verifier, hosts: a.Endpoints()}
}

// orderPeer is a participant of an order and the hosts of its verifier.
func orderPeer(p *dkgorder.Participant) peerHosts {
	a := runnerclient.OrderAttestation(p)
	return peerHosts{name: p.Name, verifier: a.Verifier, hosts: a.Endpoints()}
}

// missingPeerEndpoints lists, for the signer of setup s at position self,
// the keygen_peer_attestation_hosts lines its setup lacks for the other peers, each with
// the peers that need it; none when its egress is not limited.
func missingPeerEndpoints(s *setupwire.Setup, peers []peerHosts, self int) []string {
	if !limitedEgress(s) {
		return nil
	}
	need := map[string][]string{}
	for i, p := range peers {
		if i == self {
			continue
		}
		for _, h := range p.hosts {
			if !slices.Contains(s.Platform.KeygenPeerAttestationHosts, h) {
				need[h] = append(need[h], p.name+", "+p.verifier)
			}
		}
	}
	var out []string
	for h, who := range need {
		out = append(out, fmt.Sprintf("keygen_peer_attestation_hosts = %s   # %s", h, strings.Join(who, "; ")))
	}
	slices.Sort(out)
	return out
}

// warnPeerEndpoints writes a warning for a signer with missing lines.
func warnPeerEndpoints(out io.Writer, s *setupwire.Setup, missing []string, what string) {
	if len(missing) == 0 {
		return
	}
	fprintf(out, "warning: signer %s (%s) reaches only the hosts of its keygen_peer_attestation_hosts, so %s; its setup needs:\n",
		s.SignerName, s.Platform.Platform, what)
	for _, l := range missing {
		fprintf(out, "  %s\n", l)
	}
}
