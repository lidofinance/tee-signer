package markstore

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Lock is a store's retention lock, as the store reports it to the runner.
type Lock struct {
	Kind string // what was read: "s3 object lock", "gcs retention policy", "azure immutability policy"
	Mode string // as the store names it: S3 COMPLIANCE or GOVERNANCE, GCS and Azure locked or unlocked
	// Compliance: nobody can delete or overwrite a locked object before its
	// retention ends, and nobody can shorten the retention (S3 compliance
	// mode, a locked GCS retention policy, a locked Azure policy).
	Compliance bool
	Retention  time.Duration // how long each object stays locked
}

// Locker is a Log that reports its lock. Each store client reads it over
// the runner's own TLS, with the runner's own credentials.
type Locker interface {
	Lock(ctx context.Context) (Lock, error)
}

// ErrNoLock: the store has no lock that keeps the log safe.
var ErrNoLock = errors.New("markstore: the mark store is not locked")

// CheckLock is the lock self-check at every start (setup-phase.md,
// section 5): the store must be locked in compliance mode, with a retention
// of at least minDays (slashing_log_min_lock_days). Any error stops the start: an
// unlocked store lets its admin delete the newest records and roll the mark
// and the config state back.
func CheckLock(ctx context.Context, l Log, minDays uint32) error {
	lk, ok := l.(Locker)
	if !ok {
		return fmt.Errorf("%w: %s cannot report a lock", ErrNoLock, l)
	}
	got, err := lk.Lock(ctx)
	if err != nil {
		return fmt.Errorf("mark store %s: lock check: %w", l, err)
	}
	want := time.Duration(minDays) * 24 * time.Hour
	switch {
	case !got.Compliance:
		return fmt.Errorf("%w: %s: %s in mode %q, want compliance (locked)", ErrNoLock, l, got.Kind, got.Mode)
	case got.Retention < want:
		return fmt.Errorf("%w: %s: %s keeps objects %v, the setup's slashing_log_min_lock_days needs at least %v",
			ErrNoLock, l, got.Kind, got.Retention, want)
	}
	return nil
}

// Lock of a file log: none. The host owns the directory; the dev platform
// runs without the check.
func (f *FileLog) Lock(context.Context) (Lock, error) {
	return Lock{Kind: "file log", Mode: "none"}, nil
}
