// Package nts is the signer's NTS time client over github.com/beevik/nts
// (NTS-KE, cookies, the AES-SIV extension fields) and github.com/beevik/ntp
// (the NTPv4 exchange). Go owns the sockets and the clock.
//
//   - ke.go: NTS-KE over crypto/tls (TLS 1.3, ALPN ntske/1), with a
//     caller-given clock for certificates and pinned roots.
//   - query.go: one NTP query over UDP, with T1 and T4 on Monotonic.
//   - sample.go: offset, delay and error bound of a response and the
//     RFC 5905 checks.
//   - quorum.go: the time from several servers, one of which may be wrong.
//   - roots.go, roots/: the pinned roots per operator and the public servers.
//   - ntstest/: a loopback NTS-KE and NTP server for tests, with its own
//     AES-SIV.
//
// trusted-time/clock.NTS builds the runner's clock on this package.
//
// The package has code only in a build with the tag nts; the cloud runners
// carry it, the dev runners do not (scripts/common.sh, runner_tags).
package nts
