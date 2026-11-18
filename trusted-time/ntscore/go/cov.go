//go:build nts && ntscov

package ntscore

// With the tag ntscov the core is the archive make -C ../c cov builds,
// instrumented for gcov (link_cov.go). gcov writes its counts from an exit
// handler of the C runtime, which a Go program never runs (os.Exit is the
// exit_group system call), so the test binaries dump them themselves:
// GcovDump from a TestMain.

/*
void __gcov_dump(void);
*/
import "C"

// GcovDump writes the coverage counts of the C core gathered so far.
func GcovDump() { C.__gcov_dump() }
