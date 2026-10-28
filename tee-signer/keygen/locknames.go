package keygen

// Names of this package's locks for the lock order check
// (runner/lockorder, -tags lockcheck).

type ordersMuName struct{}

func (ordersMuName) LockName() string { return "keygen.Orders.mu" }

type managerMuName struct{}

func (managerMuName) LockName() string { return "keygen.Manager.mu" }
