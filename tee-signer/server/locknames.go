package server

// Names of this package's locks for the lock order check
// (runner/lockorder, -tags lockcheck).

type sharesMuName struct{}

func (sharesMuName) LockName() string { return "server.Server.sharesMu" }

type updatesWriteMuName struct{}

func (updatesWriteMuName) LockName() string { return "server.Updates.writeMu" }

type updatesMuName struct{}

func (updatesMuName) LockName() string { return "server.Updates.mu" }

type updatesSrcMuName struct{}

func (updatesSrcMuName) LockName() string { return "server.Updates.srcMu" }

type exitsMuName struct{}

func (exitsMuName) LockName() string { return "server.exitState.mu" }

type importSlotMuName struct{}

func (importSlotMuName) LockName() string { return "server.importer.slotMu" }

type importMuName struct{}

func (importMuName) LockName() string { return "server.importer.mu" }

type sourceMuName struct{}

func (sourceMuName) LockName() string { return "server.sourceHandover.mu" }
