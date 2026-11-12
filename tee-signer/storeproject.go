package main

import (
	"context"
	"fmt"
	"time"

	"github.com/lidofinance/tee-signer/slashing-log"
)

// projectNumberer is a store that reports the number of the Google Cloud
// project that holds it (gcslog.Log).
type projectNumberer interface {
	ProjectNumber(ctx context.Context) (uint64, error)
}

// checkStoreProject refuses a store outside the setup's GCP project:
// sealing_key_release.project_number (rv-d3u.6). A setup that named a
// bucket of another project would put the mark log or the state copy
// where that project's owner can delete them. want 0 (no project_number,
// or not GCP): no check. A store that cannot report its project is
// refused when want is set. what names the store in the error.
func checkStoreProject(ctx context.Context, l markstore.Log, want uint64, what string) error {
	if want == 0 {
		return nil
	}
	p, ok := l.(projectNumberer)
	if !ok {
		return fmt.Errorf("%s %s: the setup names GCP project %d, and this store cannot report its project", what, l, want)
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	got, err := p.ProjectNumber(ctx)
	if err != nil {
		return fmt.Errorf("%s %s: project check: %w", what, l, err)
	}
	if got != want {
		return fmt.Errorf("%s %s: the bucket is in GCP project %d, the setup's project_number is %d", what, l, got, want)
	}
	return nil
}
