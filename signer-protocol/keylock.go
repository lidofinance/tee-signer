package backend

import "fmt"

// KeyLock says whether the rule of the key that releases a runner's
// sealing key can still change (the Azure release policy, the AWS key
// policy). The runner reads the rule inside the TEE at start
// (key_release_hash) and decides the lock from the same answer. HEALTH
// carries it; the setup state of IDENTITY and ATTEST does not, because its
// layout is the circuits' statement.
type KeyLock uint8

const (
	// KeyLockUnread: the runner did not read its key rule (no read grant,
	// a failed read, or a platform that reads none).
	KeyLockUnread KeyLock = iota
	// KeyLockLocked: nobody can change the rule any more.
	KeyLockLocked
	// KeyLockNotLocked: someone can still change the rule.
	KeyLockNotLocked
	// KeyLockNone: the platform has no lock to check (GCP, dev).
	KeyLockNone
)

var keyLockNames = [...]string{"unread", "locked", "not_locked", "none"}

func (l KeyLock) String() string {
	if int(l) < len(keyLockNames) {
		return keyLockNames[l]
	}
	return fmt.Sprintf("key_lock(%d)", uint8(l))
}

// ParseKeyLock reads String's form.
func ParseKeyLock(s string) (KeyLock, error) {
	for i, n := range keyLockNames {
		if n == s {
			return KeyLock(i), nil
		}
	}
	return 0, fmt.Errorf("key lock %q: want unread, locked, not_locked or none", s)
}
