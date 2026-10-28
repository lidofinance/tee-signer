package markstore

// Names of this package's locks for the lock order check
// (runner/lockorder, -tags lockcheck).

type markLogMuName struct{}

func (markLogMuName) LockName() string { return "markstore.MarkLog.mu" }
