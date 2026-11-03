package server

import (
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol/buildchain"
	"github.com/lidofinance/tee-signer/tee-signer/attls"
)

// The role table of a mainnet build has no row for the non-prod admin
// role: nothing of it is reachable, even if RoleOf ever returned it.
func TestMainnetRoleTableHasNoRootDirectRow(t *testing.T) {
	_, ok := allows[attls.RoleAdminRootDirect]
	if ok != buildchain.AdminRootDirect {
		t.Fatalf("%s build: row for %v present %v, want %v", buildchain.Name, attls.RoleAdminRootDirect, ok, buildchain.AdminRootDirect)
	}
}
