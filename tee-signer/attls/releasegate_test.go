package attls

import (
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol/buildflavor"
)

// A default build holds no name of the testnet-only admin role, so the
// release gate (scripts/release-gate.sh) can forbid the string in its
// binaries.
func TestDefaultBuildHasNoRootDirectRoleName(t *testing.T) {
	got := RoleAdminRootDirect.String()
	if buildflavor.AdminRootDirect {
		if got != "admin-root-direct" {
			t.Fatalf("testnet build: role name %q, want admin-root-direct", got)
		}
		return
	}
	if got != "none" {
		t.Fatalf("default build: role name %q, want none", got)
	}
}
