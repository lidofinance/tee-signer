//go:build nts && ntscov

package ntscore

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	code := m.Run()
	GcovDump()
	os.Exit(code)
}
