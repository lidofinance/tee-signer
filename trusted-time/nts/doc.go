// Package nts is the signer's NTS time client (RFC 8915) on the standard
// library and github.com/beevik/ntp (the NTPv4 exchange). Go owns the
// sockets and the clock.
//
//   - siv.go: AES-SIV-CMAC-256 (RFC 5297) on crypto/aes, the one AEAD offered.
//   - ke.go: NTS-KE over crypto/tls (TLS 1.3, ALPN ntske/1), the records,
//     the keys from the exporter, with a caller-given clock for certificates
//     and pinned roots.
//   - query.go: one NTP query over UDP on the library's extension hook: the
//     Unique Identifier, cookie, placeholders and authenticator, with T1 and
//     T4 on Monotonic.
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
