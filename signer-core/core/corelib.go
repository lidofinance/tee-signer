//go:build !dvt

package core

// The default core, built by scripts/build-core.sh. A build with the tag
// dvt links libsigner_core_dvt.a instead (dvt.go).
//
// sc_core_dvt_marker: the DVT core defines it too (signer.c, SC_DVT), so a
// default build linked against a DVT core fails with a multiple definition
// (scripts/dvt-test.sh link). The default core does not define it.

/*
#cgo linux,amd64 LDFLAGS: -L${SRCDIR}/../../build/x86_64/lib -lsigner_core -lblst
#cgo linux,arm64 LDFLAGS: -L${SRCDIR}/../../build/aarch64/lib -lsigner_core -lblst
#cgo darwin,amd64 LDFLAGS: -L${SRCDIR}/../../build/x86_64/lib -lsigner_core -lblst
#cgo darwin,arm64 LDFLAGS: -L${SRCDIR}/../../build/aarch64/lib -lsigner_core -lblst
const char sc_core_dvt_marker[] = "default binding";
*/
import "C"
