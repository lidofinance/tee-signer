package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/slashing-log"
)

// projectLog is a file log that reports a GCP project, as gcslog.Log does.
type projectLog struct {
	*markstore.FileLog
	number uint64
	err    error
}

func (p projectLog) ProjectNumber(context.Context) (uint64, error) { return p.number, p.err }

// The mark log and the state copy must be in the setup's project_number
// (rv-d3u.6). No project_number: no check.
func TestCheckStoreProject(t *testing.T) {
	fl, err := markstore.NewFileLog(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, c := range []struct {
		name string
		l    markstore.Log
		want uint64
		err  string
	}{
		{"no project_number", fl, 0, ""},
		{"no project_number, any bucket", projectLog{fl, 7, nil}, 0, ""},
		{"same project", projectLog{fl, 123456789, nil}, 123456789, ""},
		{"another project", projectLog{fl, 7, nil}, 123456789, "the bucket is in GCP project 7, the setup's project_number is 123456789"},
		{"metadata read fails", projectLog{fl, 0, errors.New("403 Forbidden")}, 123456789, "project check: 403 Forbidden"},
		{"store without a project", fl, 123456789, "cannot report its project"},
	} {
		err := checkStoreProject(ctx, c.l, c.want, "mark log")
		switch {
		case c.err == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
			t.Errorf("%s: %v, want an error with %q", c.name, err, c.err)
		}
	}
}
