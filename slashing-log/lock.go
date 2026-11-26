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
	// retention ends, and nobody can shorten that object's retention (S3
	// compliance mode, a locked GCS retention policy, a locked Azure
	// policy). On S3 this is the bucket default for new objects, which the
	// admin can still lower or remove later; the S3 client therefore sets
	// each object's own retention (Env.RetainDays). GCS and Azure lock the
	// policy itself.
	Compliance bool
	Retention  time.Duration // how long each object stays locked
}

// Locker is a Log that reports its lock. Each store client reads it over
// the runner's own TLS, with the runner's own credentials.
type Locker interface {
	Lock(ctx context.Context) (Lock, error)
}

// VersionChecker is a Log whose store can keep overwritten objects as
// previous versions that List and Get do not read (Azure version-level
// immutability). CheckVersions fails, with ErrNoLock, when it does.
type VersionChecker interface {
	CheckVersions(ctx context.Context) error
}

// CheckVersions runs l's CheckVersions, if l has one. The state copy runs
// it at every start: in such a store an admin could hide the newest
// commits, and the restore would take an older one.
func CheckVersions(ctx context.Context, l Log) error {
	vc, ok := l.(VersionChecker)
	if !ok {
		return nil
	}
	if err := vc.CheckVersions(ctx); err != nil {
		return fmt.Errorf("store %s: version check: %w", l, err)
	}
	return nil
}

// ErrNoLock: the store has no lock that keeps the log safe.
var ErrNoLock = errors.New("markstore: the mark store is not locked")

// CheckLock is the lock self-check at every start: the store must be locked in compliance mode, with a retention
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

// ObjectLock is the retention of one stored object (one version of a
// name), as the store reports it.
type ObjectLock struct {
	Kind string // what was read: "s3 object retention", "gcs retention policy", "azure immutability policy"
	Mode string // as the store names it: S3 COMPLIANCE or GOVERNANCE, GCS and Azure locked or unlocked; "none"
	// Compliance: nobody can delete the object, or shorten its retention,
	// before RetainUntil (S3 compliance mode, a locked GCS or Azure policy).
	Compliance  bool
	RetainUntil time.Time
}

// ObjectLocker is a Log that reports the retention of one object. A writer
// skips a record name taken by an object that is not a record only if
// this says the object stays as long as a record would (CheckKept).
type ObjectLocker interface {
	ObjectLock(ctx context.Context, e Entry) (ObjectLock, error)
}

// ErrNameTaken: the next name is taken by an object that is not a record
// (or not a commit), and the writer may not skip it: the mark log skips
// only an object the store shows to stay at least as long as a record
// written now (CheckKept), the state copy never skips. The writer neither
// skips the name nor writes there. It does not latch: a later write tries
// the same name again.
var ErrNameTaken = errors.New("markstore: the next name holds an object that is not a record or commit, and the writer may not skip it")

// lockMargin is how much shorter than a record's retention the retention
// of an object under a skipped name may be. S3 dates a record's retention
// from a clock it holds to within 15 minutes of its own; GCS and Azure
// count from the object's creation. The write age check (staleLocked)
// takes the same 15 minutes off a record's retention.
const lockMargin = 15 * time.Minute

// CheckKept is the rule for skipping a name taken by objects that are not
// records: every object under it (es, all versions) must be locked in
// compliance mode until at least now + keep - lockMargin, where keep is the
// retention a record written now gets. Then no object there can go before
// a record there could. An object that could go sooner (no retention, S3
// governance mode, a shorter date, an unlocked policy) could be deleted
// once one writer has skipped it, and another writer would then write
// there, beside the first. Any doubt is an error wrapping ErrNameTaken: no
// entries, keep 0 (the retention is not known), a store that cannot
// report an object's lock, or a read that fails.
//
// Another writer that comes to the name later either skips it too, when
// the object's date also covers its own now + keep - lockMargin, and the
// two then meet at the next name; or it gets ErrNameTaken and stops. What
// keeps a stopped writer from writing the name once the object is gone is
// the write age latch (MarkLog.staleLocked): it writes nothing more than
// keep/2 after its last record, and the object stays at least
// keep - lockMargin after the skip, which came after that record. The
// rule is safe only together with that latch; a log without it (no setup,
// the first record of a log, the state copy) must never skip.
//
// The rule dates the lock by the caller's trusted clock and assumes that
// clock does not lag real time; the claim refuses a clock that lags the
// newest record by more than lockMargin (ErrClockBehind).
func CheckKept(ctx context.Context, l Log, es []Entry, now time.Time, keep time.Duration) error {
	if len(es) == 0 {
		return fmt.Errorf("%w: the name lists no object", ErrNameTaken)
	}
	if keep <= 0 {
		return fmt.Errorf("%w: the retention of a record is not known", ErrNameTaken)
	}
	ol, ok := l.(ObjectLocker)
	if !ok {
		return fmt.Errorf("%w: %s cannot report an object's lock", ErrNameTaken, l)
	}
	need := now.Add(keep - lockMargin)
	for _, e := range es {
		lk, err := ol.ObjectLock(ctx, e)
		switch {
		case err != nil:
			return fmt.Errorf("%w: %s (%s): lock read: %v", ErrNameTaken, e.Name, e.Ref, err)
		case !lk.Compliance:
			return fmt.Errorf("%w: %s (%s): %s in mode %q, not compliance", ErrNameTaken, e.Name, e.Ref, lk.Kind, lk.Mode)
		case lk.RetainUntil.Before(need):
			return fmt.Errorf("%w: %s (%s): locked until %s, a record written now is kept until at least %s",
				ErrNameTaken, e.Name, e.Ref, lk.RetainUntil.UTC().Format(time.RFC3339), need.UTC().Format(time.RFC3339))
		}
	}
	return nil
}
