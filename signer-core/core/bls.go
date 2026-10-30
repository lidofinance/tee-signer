package core

/*
#include <stdint.h>
#include <stddef.h>
#include "signer_core.h"

*/
import "C"

import (
	"fmt"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// Verify checks a BLS signature with blst (sc_bls_verify, Ethereum POP
// ciphersuite) over a 32-byte signing root.
func Verify(pubkey backend.Pubkey, signingRoot backend.Root, sig backend.Signature) bool {
	return C.sc_bls_verify(u8(pubkey[:]), u8(signingRoot[:]), 32, u8(sig[:])) == C.SC_OK
}

// PubkeyOf returns the public key of a secret scalar (big endian).
func PubkeyOf(secret [32]byte) (backend.Pubkey, error) {
	var pk backend.Pubkey
	if rc := C.sc_bls_pubkey(u8(secret[:]), u8(pk[:])); rc != C.SC_OK {
		return pk, fmt.Errorf("core: %v", backend.Status(rc))
	}
	return pk, nil
}
