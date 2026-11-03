package attls

import (
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol/buildchain"
)

// A mainnet build holds no name of the non-prod admin role, so the
// release gate (scripts/release-gate.sh) can forbid the string in its
// binaries.
func TestMainnetBuildHasNoRootDirectRoleName(t *testing.T) {
	got := RoleAdminRootDirect.String()
	if buildchain.AdminRootDirect {
		if got != "admin-root-direct" {
			t.Fatalf("non-prod build: role name %q, want admin-root-direct", got)
		}
		return
	}
	if got != "none" {
		t.Fatalf("mainnet build: role name %q, want none", got)
	}
}
