package setupwire_test

import (
	"testing"

	"github.com/lidofinance/tee-signer/governance/setuptext"
	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// The human form refuses every setup the encoder refuses.
func TestFormatRefusesEverySetupRefusal(t *testing.T) {
	setupwire.FormatRefusals(t, func(s *setupwire.Setup) error {
		_, err := setuptext.FormatSetup(s)
		return err
	})
}
