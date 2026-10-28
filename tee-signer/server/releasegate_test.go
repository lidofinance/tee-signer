package server

import (
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol/buildflavor"
	"github.com/lidofinance/tee-signer/tee-signer/attls"
)

// The role table of a default build has no row for the testnet-only admin
// role: nothing of it is reachable, even if RoleOf ever returned it.
func TestDefaultRoleTableHasNoRootDirectRow(t *testing.T) {
	_, ok := allows[attls.RoleAdminRootDirect]
	if ok != buildflavor.AdminRootDirect {
		t.Fatalf("flavour %s: row for %v present %v, want %v", buildflavor.Name, attls.RoleAdminRootDirect, ok, buildflavor.AdminRootDirect)
	}
}
