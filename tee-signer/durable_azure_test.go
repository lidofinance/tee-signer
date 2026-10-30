//go:build platform_azure

package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/dev"
	"github.com/lidofinance/tee-signer/platform/filestore"
	"github.com/lidofinance/tee-signer/slashing-log"
	"github.com/lidofinance/tee-signer/slashing-log/wormfake"
)

// The state copy refuses an Azure container with version-level immutability
// on the setup path, as the mark log's lock check does: the restore reads
// current blob versions only, so an admin could hide the newest commits.
func TestDurableCopyRefusesVersionLevelImmutability(t *testing.T) {
	srv := wormfake.New(wormfake.Azure, "state")
	defer srv.Close()
	tok := func(s string) func(context.Context) (string, time.Time, error) {
		return func(context.Context) (string, time.Time, error) { return s, time.Now().Add(time.Hour), nil }
	}
	spec := "azblob:account=acct,container=state,endpoint=" + srv.URL + ",subscription=sub-1,resource_group=rg-1,arm_endpoint=" + srv.URL
	open := func(check bool) error {
		t.Helper()
		local, err := filestore.New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		p := &platform.Platform{Name: "azure", Store: local, Keys: dev.NewDevKeys("image-1"), HTTPClient: srv.Client(),
			StorageToken: tok("mi-token"), ManagementToken: tok("arm-token")}
		d, err := newDurableCopy(spec, "signer-1", true, quietLog)
		if err != nil {
			t.Fatal(err)
		}
		d.setupHash, d.checkVersions = [32]byte{1}, check
		_, err = d.open(context.Background(), p)
		return err
	}
	if err := open(true); err != nil {
		t.Fatalf("container-level lock: %v", err)
	}
	for _, l := range []wormfake.Lock{
		{Compliance: true, Days: 30, VersionLevel: true},
		{Compliance: true, Days: 30, Migrating: true},
	} {
		srv.SetLock(l)
		before := len(srv.Names())
		err := open(true)
		if !errors.Is(err, markstore.ErrNoLock) || !strings.Contains(err.Error(), "version-level") {
			t.Errorf("%+v: %v, want a version-level refusal", l, err)
		}
		if len(srv.Names()) != before {
			t.Errorf("%+v: wrote to the store before the refusal", l)
		}
	}
	// The flag path has no lock check for the mark log either.
	if err := open(false); err != nil {
		t.Fatalf("flag path: %v", err)
	}
}
