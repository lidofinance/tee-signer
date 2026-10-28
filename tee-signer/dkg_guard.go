//go:build ((peer_azure || peer_aws || peer_gcp || peer_dev) && (debugimport || !peerselect)) || (peer_dev && !platform_dev) || peer_optee

// Build sets that must not compile. A build that hits one of these fails on
// the undefined name below, which says why:
//
//   - peer_* with debugimport: a debug build takes plaintext shares, so it
//     never makes keys (keep key generation in release builds only).
//   - peer_* without peerselect: attest/runnerclient would hold every
//     verifier. scripts/build-runner.sh adds peerselect with the peer tags.
//   - peer_dev without platform_dev: the dev verifier accepts unsigned
//     documents, so only a dev runner may have it.
//   - peer_optee: reserved for the boards' trusted app, not built yet.

package main

var _ = peer_tags_need_peerselect_release_build_and_peer_dev_only_with_platform_dev_peer_optee_is_reserved
