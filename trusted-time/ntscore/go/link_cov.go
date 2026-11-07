//go:build nts && ntscov

package ntscore

// With the tag ntscov the core is the archive make -C ../c cov builds,
// instrumented for gcov; make -C ../c cov-report prints the C coverage of
// the tests run since (COV=1 scripts/test-modules.sh trusted-time).

/*
#cgo amd64 LDFLAGS: ${SRCDIR}/../c/build/x86_64/cov/libnts_core.a -lgcov
#cgo arm64 LDFLAGS: ${SRCDIR}/../c/build/aarch64/cov/libnts_core.a -lgcov
*/
import "C"
