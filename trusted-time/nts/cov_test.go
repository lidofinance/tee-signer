//go:build nts && ntscov

package nts

import (
	"os"
	"testing"

	ntscore "github.com/lidofinance/tee-signer/trusted-time/ntscore/go"
)

// The C core's coverage counts (make -C ../ntscore/c cov-report).
func TestMain(m *testing.M) {
	code := m.Run()
	ntscore.GcovDump()
	os.Exit(code)
}
