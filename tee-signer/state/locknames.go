package state

// Names of this package's locks for the lock order check
// (devkit/lockorder, -tags lockcheck).

type hooksMuName struct{}

func (hooksMuName) LockName() string { return "state.Hooks.mu" }
