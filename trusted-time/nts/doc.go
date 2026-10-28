// Package nts is the Go side of the Rust NTS library (nts/ in this repo): a
// static library with a C ABI, linked in through cgo, like the C signer core.
//
// Go owns the sockets and the clock; Rust owns the protocol bytes.
//
//   - nts.go: the cgo binding (NTS-KE records, associations with keys and
//     cookies in Rust memory, NTP requests and their check, the quorum).
//   - ke.go: NTS-KE over crypto/tls (TLS 1.3, ALPN ntske/1, the RFC 8915
//     section 5.1 exporter), with a caller-given clock for certificates.
//   - query.go: one NTP query over UDP.
//   - roots.go, roots/: the pinned roots per operator and the public servers.
//   - ntstest/: a loopback NTS-KE and NTP server for tests, with its own
//     AES-SIV.
//
// runner/clock.NTS builds the runner's clock on this package.
//
// The package has code only in a build with the tag nts. Without the tag it
// is empty, so no default build links Rust code or needs the library.
// scripts/build-nts.sh builds libsigner_nts.a into build/nts/<arch>/lib
// first, and scripts/build-runner-nts.sh builds the runners with the tag.
package nts
