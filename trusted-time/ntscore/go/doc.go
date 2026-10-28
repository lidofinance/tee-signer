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
// trusted-time/clock.NTS drives it through trusted-time/nts. The rest
// (lowlevel.go) is the core's functions one by one, for the tests that
// check them one by one and for the AES-SIV self-test.
//
// The package has code only in a build with the tag nts, with cgo; the
// cloud runners carry it, the dev runners do not (scripts/common.sh,
// runner_tags). It links the archive make -C ../c builds (link.go): the
// C freestanding, every warning an error, and its undefined symbols
// checked to be nothing but memcpy, memmove, memchr, memset and memcmp
// (make -C ../c check). go test needs that archive; scripts/build-core.sh
// (make core at the root) builds it for every architecture.
package ntscore
