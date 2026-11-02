package server

// Names of this package's locks for the lock order check
// (devkit/lockorder, -tags lockcheck).

type updatesWriteMuName struct{}

func (updatesWriteMuName) LockName() string { return "server.Updates.writeMu" }

type updatesMuName struct{}

func (updatesMuName) LockName() string { return "server.Updates.mu" }
