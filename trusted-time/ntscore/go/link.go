//go:build nts && !asan && !ntscov

package ntscore

// The core is the archive ../c/Makefile builds: the freestanding build
// whose undefined symbols it checks, so a runner links the core the check
// saw. make -C ../c builds it for this machine; scripts/build-core.sh for
// every architecture of a release.

/*
#cgo amd64 LDFLAGS: ${SRCDIR}/../c/build/x86_64/libnts_core.a
#cgo arm64 LDFLAGS: ${SRCDIR}/../c/build/aarch64/libnts_core.a
*/
import "C"
