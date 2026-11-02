package verify

import (
	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient/internal/optset"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
)

func init() {
	verifierFactories[VerifierDev] = func(*Attestation, *optset.Options) (VerifyFunc, error) {
		return remote.DevVerifier, nil
	}
}
