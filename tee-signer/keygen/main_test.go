package keygen

import (
	"testing"

	"github.com/lidofinance/tee-signer/devkit/leakcheck"
)

// Every goroutine a test started in key generation ends after it.
func TestMain(m *testing.M) { leakcheck.Main(m, "github.com/lidofinance/tee-signer/tee-signer/keygen") }
