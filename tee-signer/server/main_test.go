package server

import (
	"testing"

	"github.com/lidofinance/tee-signer/devkit/leakcheck"
)

// Every goroutine the server started for a test ends after it: a
// connection handler, a probe after a panic, a timer.
func TestMain(m *testing.M) { leakcheck.Main(m, "github.com/lidofinance/tee-signer/tee-signer/server") }
