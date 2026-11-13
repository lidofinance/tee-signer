//go:build nts

// Package ntscore is the NTS client core of trusted-time in C, and its cgo
// binding. The C (../c: nts_core.h and the .c files) holds everything
// the signer's time rests on: the NTS-KE records, the keys and cookies,
// the NTPv4 request and the check of the response, the measurement, the
// quorum, the drift and coarse checks, and the time served; it gets random
// bytes, the monotonic clock, the TLS session of NTS-KE and the sockets
// from host operations the binding routes to a HostOps. nts_core.h says
// which of those a trusted application must implement inside the TEE and
// which it may leave to the untrusted world.
//
// The binding has two faces. Core is the client: New with a Config and a
// HostOps, then Due, Poll, Combine, Bounded and Status, as
// trusted-time/clock.NTS drives it through trusted-time/nts; SetServers
// and SetPolicy change the server list, the protocol and the bounds of a
// running core, and are configuration: their caller must be the trusted
// side (a config update checked inside the TEE), never the network side.
// With ProtocolNTP the core asks with plain NTP, which nothing
// authenticates (nts_core.h says what is left of the promise then); a core
// built with NTS_NO_PLAIN_NTP refuses it (PlainSupported, the tag
// ntsnoplain). The rest
// (lowlevel.go) is the core's functions one by one, for the tests that
// check them one by one and for the AES-SIV self-test.
//
// The package has code only in a build with the tag nts, with cgo; the
// cloud runners carry it, the dev runners do not (scripts/common.sh,
// runner_tags). It links the archive make -C ../c builds (link.go): the
// C freestanding, every warning an error, with the stack protector, and
// its undefined symbols checked to be nothing but memcpy, memmove, memchr,
// memset and memcmp and the stack protector's two (make -C ../c check). go test needs that archive; scripts/build-core.sh
// (make core at the root) builds it for every architecture.
package ntscore
