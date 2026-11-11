//go:build platform_gcp

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/dev"
	"github.com/lidofinance/tee-signer/platform/filestore"
	"github.com/lidofinance/tee-signer/platform/setup"
	"github.com/lidofinance/tee-signer/slashing-log/wormfake"
	"github.com/lidofinance/tee-signer/trusted-time/clock"
)

// rv-nsd.2: on the start path the mark log and the state copy refuse a
// bucket outside the setup's project_number, before they write to it.
func TestStartRefusesBucketOfAnotherProject(t *testing.T) {
	st, err := setup.Load(sampleSetup(t, "gcp"), "gcp")
	if err != nil {
		t.Fatal(err)
	}
	want := st.Wire.Platform.SealingKeyRelease.ProjectNumber
	if want == 0 {
		t.Fatal("the gcp sample setup has no project_number")
	}
	tok := func(context.Context) (string, time.Time, error) {
		return "federated-token", time.Now().Add(time.Hour), nil
	}
	plat := func(t *testing.T, srv *wormfake.Server) *platform.Platform {
		local, err := filestore.New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		return &platform.Platform{Name: "gcp", Store: local, Sealer: dev.NewDevSealer(), Clock: clock.System{},
			Keys: dev.NewDevKeys("image-1"), HTTPClient: srv.Client(), StorageToken: tok}
	}
	for _, project := range []string{"", "999"} {
		srv := wormfake.New(wormfake.GCS, "marks")
		srv.ProjectNumber = project
		srv.SetLock(wormfake.Lock{Compliance: true, Days: int(st.Wire.SlashingLogMinLockDays) + 1})
		spec := "gcs:bucket=marks,endpoint=" + srv.URL
		_, err := setupMarkLog(context.Background(), plat(t, srv), nil, "gcp", spec, "signer-3", true, st, quietLog)
		if err == nil || !strings.Contains(err.Error(), "project") {
			t.Errorf("mark log in project %q: %v, want a project refusal", project, err)
		}
		d, err := newDurableCopy(spec, "signer-3", true, quietLog)
		if err != nil {
			t.Fatal(err)
		}
		d.setupHash, d.projectNumber = st.SHA256, want
		if _, err := d.open(context.Background(), plat(t, srv)); err == nil || !strings.Contains(err.Error(), "project") {
			t.Errorf("state copy in project %q: %v, want a project refusal", project, err)
		}
		if n := len(srv.Names()); n != 0 {
			t.Errorf("project %q: %d objects written before the refusal", project, n)
		}
		srv.Close()
	}
}
