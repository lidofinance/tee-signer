package handover

import (
	"testing"

	"github.com/lidofinance/tee-signer/governance/handoverorder"
)

// HANDOVER_ORDER has one number in both packages: governance/handoverorder
// holds the codec and cannot import this package (governance sits below
// tee-signer), so each keeps its own copy of the constant.
func TestTypeOrderMatchesHandoverOrder(t *testing.T) {
	if TypeOrder != handoverorder.TypeOrder {
		t.Fatalf("handover.TypeOrder is %#x, handoverorder.TypeOrder %#x; they must be one number", uint8(TypeOrder), uint8(handoverorder.TypeOrder))
	}
}
