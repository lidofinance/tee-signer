// Package nts is the signer's NTS time client (RFC 8915) on the Go standard
// library alone: the port of the Rust core that the runner linked before,
// with the sockets and the clock in Go.
//
//   - siv.go: AES-SIV-CMAC-256 (RFC 5297) on crypto/aes, the one AEAD offered.
//   - ke.go: NTS-KE over crypto/tls (TLS 1.3, ALPN ntske/1), the records,
//     the keys from the exporter, with a caller-given clock for certificates
//     and pinned roots.
//   - ntp.go: the NTP time formats with era-safe conversion (RFC 5905
//     section 6); the NTPv4 request with the Unique Identifier, cookie,
//     placeholders and authenticator, and the check of the response
//     (RFC 8915 section 5, RFC 7822). Untrusted bytes are read with length
//     checks only; a refused response leaves the request open for the
//     real one.
//   - query.go: one NTP query over UDP, T1 and T4 on Monotonic; answers
//     that fail the check are dropped until the real one comes or the
//     time runs out.
//   - sample.go: offset, delay and error bound of a response and the
//     RFC 5905 checks, in big.Int.
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
