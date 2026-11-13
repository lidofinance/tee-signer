//go:build nts && asan

package ntscore

// Under go test -asan the core is the archive make -C ../c asan builds,
// with AddressSanitizer and UndefinedBehaviorSanitizer; the link adds
// UBSan's runtime, ASan's comes with -asan.

/*
#cgo amd64 LDFLAGS: ${SRCDIR}/../c/build/x86_64/asan/libnts_core.a -fsanitize=address,undefined
#cgo arm64 LDFLAGS: ${SRCDIR}/../c/build/aarch64/asan/libnts_core.a -fsanitize=address,undefined
*/
import "C"
