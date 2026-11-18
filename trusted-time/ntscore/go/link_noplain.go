//go:build nts && ntsnoplain && !asan && !ntscov

package ntscore

// With the tag ntsnoplain the core is the archive make -C ../c noplain
// builds: compiled with NTS_NO_PLAIN_NTP, the build of a trusted
// application, which refuses plain NTP as a protocol (New and SetPolicy
// with ProtocolNTP give ErrBadConfig, PlainSupported is false). The tests
// run against it too: those of plain NTP as a protocol skip, and
// TestPlainRefusedByTheBuild checks the refusal.

/*
#cgo amd64 LDFLAGS: ${SRCDIR}/../c/build/x86_64/noplain/libnts_core.a
#cgo arm64 LDFLAGS: ${SRCDIR}/../c/build/aarch64/noplain/libnts_core.a
*/
import "C"
