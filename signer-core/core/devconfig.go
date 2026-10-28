package core

import (
	"crypto/sha256"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// DevConfig is a made-up test chain: arbitrary fork versions, a genesis
// validators root of sha256("tee-signer dev chain"), one fork at
// epoch 10, exit allowlist {7}. Tests and the dev runner use it.
func DevConfig(genesisTime, secondsPerSlot, slotsPerEpoch uint64) Config {
	var fee backend.Address
	for i := range fee {
		fee[i] = 0x11
	}
	return Config{
		GenesisValidatorsRoot:        sha256.Sum256([]byte("tee-signer dev chain")),
		GenesisForkVersion:           backend.Version{0x00, 0x00, 0x00, 0x01},
		Forks:                        []Fork{{Epoch: 10, Version: backend.Version{0x01, 0x00, 0x00, 0x01}}},
		VoluntaryExitForkVersion:     backend.Version{0x03, 0x00, 0x00, 0x01},
		GenesisTime:                  genesisTime,
		SecondsPerSlot:               secondsPerSlot,
		SlotsPerEpoch:                slotsPerEpoch,
		MaxEpochsAhead:               1,
		ExitAllowlist:                []uint64{7},
		FeeRecipients:                []backend.Address{fee},
		GasLimitMin:                  30_000_000,
		GasLimitMax:                  60_000_000,
		RegistrationMaxFutureSeconds: 3600,
		CommitAhead:                  CommitAhead{BlockSlots: 32, SourceEpochs: 1, TargetEpochs: 1},
	}
}
