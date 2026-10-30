// Package nts is the Go wrapper of the signer's NTS time client (RFC
// 8915): the host operations of the C core in trusted-time/ntscore, and
// the client that trusted-time/clock.NTS drives.
//
// The core holds everything the time rests on: the records of NTS-KE, the
// keys and the cookies, the request with its random values, the check of
// every response, the measurement, the quorum, the drift and coarse checks
// and the time it serves. This package gives it what it asks for:
//
//   - hooks.go: random bytes (crypto/rand), the monotonic clock
//     (Monotonic, CLOCK_MONOTONIC_RAW), the TLS 1.3 session of NTS-KE over
//     crypto/tls (ALPN ntske/1, the operator's pinned roots, the
//     certificate dated by the core's time) with the keys from the
//     exporter, and the sockets: TCP for NTS-KE, UDP for NTP, both through
//     the platform's DialFunc.
//   - client.go: Client, the core with those operations.
//   - roots.go, roots/: the pinned roots per operator and the public
//     servers.
//   - selftest.go: the AES-SIV self-test of the runner's -nts-selftest.
//   - ntstest/: a loopback NTS-KE and NTP server for tests, with its own
//     AES-SIV.
//
// The wrapper is the network, nothing more: whatever it hands the core is
// something an attacker on the wire could hand it too. If the sockets lie,
// delay or drop, the client gets no time, never a wrong one. On the cloud
// runners the whole process is inside the TEE, so the random bytes, the
// clock and the TLS session are the TEE's as well; in an OP-TEE trusted
// application those three move inside and the sockets stay out.
//
// The package has code only in a build with the tag nts; the cloud runners
// carry it, the dev runners do not (scripts/common.sh, runner_tags).
package nts
